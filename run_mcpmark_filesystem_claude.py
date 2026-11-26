#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MCPMark Filesystem (standard suite) + Claude Code + HTTP-visible MCP + PCAP runner.

Design goal:
    Keep MCPMark's official Filesystem MCP server version, which is stdio-only,
    but expose it to Claude Code through a local Streamable HTTP bridge so that
    Claude <-> MCP traffic remains observable in packet captures.

Topology during the measured task:
    Claude Code
        |
        | Streamable HTTP (127.0.0.1:3000/mcp)
        v
    supergateway
        |
        | stdio
        v
    @modelcontextprotocol/server-filesystem@2025.12.18
        |
        | local filesystem I/O (not network traffic)
        v
    task-specific MCPMark backup directory

Important:
    MCPMark state setup and verification are intentionally OUTSIDE the PCAP window.
    Only Claude Code task execution is captured.

Run from the MCPMark repository root:

    chmod +x run_mcpmark_filesystem_claude.py

Smoke test:
    sudo -v
    ./run_mcpmark_filesystem_claude.py --limit 1 --sudo-dumpcap

All standard tasks:
    ./run_mcpmark_filesystem_claude.py --sudo-dumpcap

Prerequisites:
    - claude, npx, dumpcap are in PATH
    - MCPMark Python dependencies are installed
    - Claude Code's LLM endpoint is already configured
    - .mcp_env is optional; FILESYSTEM_TEST_ROOT is honored when present

Per-task files (same as run_mcpmark_notion_claude.py):
    raw_traffic.pcapng
    claude_timeline.jsonl
    claude_output.json
    task_prompt.txt
    result.json

Timeline timestamps are UTC observations of Claude CLI events; use PCAP for
wire-level LLM request and MCP dispatch times. Capture, stderr, and verification
logs are not retained as separate task files.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import uuid
import tempfile
import selectors
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.mcp_services.filesystem.filesystem_task_manager import FilesystemTaskManager
from src.mcp_services.filesystem.filesystem_state_manager import FilesystemStateManager


# ============================================================================
# Experiment configuration
# ============================================================================

MCP_HOST = "127.0.0.1"
MCP_PORT = 3000
MCP_URL = f"http://{MCP_HOST}:{MCP_PORT}/mcp"

FILESYSTEM_MCP_PACKAGE = "@modelcontextprotocol/server-filesystem@2025.12.18"
SUPERGATEWAY_PACKAGE = "supergateway@4.0.0"

TASK_SUITE = "standard"
EXPECTED_TASK_COUNT = 30

CLAUDE_MAX_TURNS = 50
CLAUDE_TIMEOUT_S = 3600

RESULTS_ROOT_NAME = "results_claude_mcpmark_filesystem"


# ============================================================================
# Generic helpers
# ============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(s: str) -> str:
    return (
        s.replace("/", "__")
        .replace("\\", "__")
        .replace(" ", "_")
        .replace(":", "-")
    )


def need_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required command not found in PATH: {name}")


def tcp_port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port(
    host: str,
    port: int,
    proc: subprocess.Popen,
    timeout_s: float = 60.0,
) -> None:
    deadline = time.time() + timeout_s

    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"Filesystem MCP HTTP bridge exited early with code {proc.returncode}"
            )

        if tcp_port_open(host, port):
            # Give the child stdio MCP server a brief moment to finish startup.
            time.sleep(1.0)
            return

        time.sleep(0.2)

    raise RuntimeError(f"Timed out waiting for {host}:{port}")


def stop_process(
    proc: subprocess.Popen | None,
    sig=signal.SIGTERM,
    timeout_s: float = 10.0,
) -> None:
    if proc is None or proc.poll() is not None:
        return

    try:
        os.killpg(proc.pid, sig)
        proc.wait(timeout=timeout_s)

    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=3)

    except ProcessLookupError:
        pass


def write_json(path: Path, obj) -> None:
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


# ============================================================================
# PCAP
# ============================================================================

def start_capture(pcap_path: Path, use_sudo: bool) -> subprocess.Popen:
    """Capture packets without creating capture.log."""
    base = ["dumpcap", "-q", "-i", "any", "-w", str(pcap_path)]
    cmd = (["sudo", "-n"] + base) if use_sudo else base
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(0.5)
    if proc.poll() is not None:
        raise RuntimeError(f"dumpcap exited early (code {proc.returncode})")
    return proc


def stop_capture(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            stop_process(proc, signal.SIGTERM, 5)


# ============================================================================
# Filesystem MCP server + HTTP bridge
# ============================================================================

def start_filesystem_mcp_bridge(
    test_directory: Path,
    task_dir: Path,
) -> tuple[subprocess.Popen, object]:
    if tcp_port_open(MCP_HOST, MCP_PORT):
        raise RuntimeError(
            f"{MCP_HOST}:{MCP_PORT} is already in use. "
            "Stop the existing MCP server before starting this task."
        )

    # Keep root artifact names identical to the reference Notion runner.
    log_path = task_dir.parent / "notion_mcp_server.log"
    log_handle = log_path.open("ab")

    env = os.environ.copy()

    child_cmd = [
        "npx",
        "-y",
        FILESYSTEM_MCP_PACKAGE,
        str(test_directory),
    ]
    stdio_cmd = " ".join(shlex.quote(part) for part in child_cmd)

    cmd = [
        "npx",
        "-y",
        SUPERGATEWAY_PACKAGE,
        "--stdio",
        stdio_cmd,
        "--outputTransport",
        "streamableHttp",
        "--stateful",
        "--sessionTimeout",
        "3600000",
        "--streamableHttpPath",
        "/mcp",
        "--port",
        str(MCP_PORT),
        "--healthEndpoint",
        "/healthz",
        "--logLevel",
        "info",
    ]

    proc = subprocess.Popen(
        cmd,
        cwd=str(Path.cwd()),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    try:
        wait_port(MCP_HOST, MCP_PORT, proc)
    except Exception:
        stop_process(proc)
        log_handle.close()
        raise

    return proc, log_handle


def stop_filesystem_mcp_bridge(
    proc: subprocess.Popen | None,
    log_handle,
) -> None:
    if proc is not None:
        stop_process(proc, signal.SIGTERM, 10)

    if log_handle is not None:
        try:
            log_handle.close()
        except Exception:
            pass


def start_filesystem_mcp_bridge_with_retry(
    test_directory: Path,
    task_dir: Path,
):
    last_error = None

    for attempt in range(1, 4):
        try:
            return start_filesystem_mcp_bridge(test_directory, task_dir)
        except Exception as exc:
            last_error = exc
            print(
                f"[WARN] MCP bridge startup failed "
                f"(attempt {attempt}/3): {exc}"
            )

            subprocess.run(
                [
                    "bash",
                    "-c",
                    f"fuser -k {MCP_PORT}/tcp >/dev/null 2>&1 || true",
                ],
                check=False,
            )

            if attempt < 3:
                time.sleep(5)

    raise RuntimeError(
        f"Filesystem MCP bridge startup failed after retries: {last_error}"
    )


def make_claude_mcp_config(run_root: Path) -> Path:
    path = run_root / ".claude_mcp_config.json"

    config = {
        "mcpServers": {
            "filesystem-local": {
                "type": "http",
                "url": MCP_URL,
            }
        }
    }

    write_json(path, config)
    os.chmod(path, 0o600)
    return path


# ============================================================================
# Claude
# ============================================================================

def build_claude_prompt(
    task_manager: FilesystemTaskManager,
    task,
) -> str:
    prompt = task_manager.get_task_instruction(task)

    return (
        prompt
        + "\n\n"
        + "Use the filesystem-local MCP server for all filesystem operations. "
        + "Work only inside the filesystem root exposed by that MCP server. "
        + "Complete the task fully; do not ask the user questions."
    )


def timestamp_from_ns(epoch_ns: int) -> str:
    """Wall-clock UTC, compatible with absolute timestamps from PCAP."""
    return datetime.fromtimestamp(epoch_ns / 1_000_000_000, timezone.utc).isoformat(
        timespec="microseconds"
    )


class ClaudeTimelineRecorder:
    """Write just one JSONL timeline; no duplicate stream/history/tool files.

    event time: when this Python runner receives a complete Claude CLI JSONL
    record. These are *observations*, not exact wire-level send times.

    In particular, stream_event/message_start means MODEL RESPONSE START, not
    LLM REQUEST SENT. For actual LLM request start and MCP tool dispatch on
    the wire, use PCAP (LLM HTTP and the local /mcp Streamable HTTP endpoint).
    """

    def __init__(self, task_dir: Path, session_id: str):
        self.task_dir = task_dir
        self.session_id = session_id
        self.event_count = 0
        self.unparsed_lines = 0
        self.tool_calls: dict[str, dict] = {}
        self.final_result: dict | None = None
        self.model_response_count = 0
        self._started_messages: set[tuple[str, str]] = set()
        self._current_message: dict[str, str | None] = {}
        self._timeline = (task_dir / "claude_timeline.jsonl").open(
            "w", encoding="utf-8", buffering=1
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._timeline.close()

    def emit(self, event: str, epoch_ns: int | None = None, **details) -> None:
        if epoch_ns is None:
            epoch_ns = time.time_ns()
        row = {
            "timestamp_utc": timestamp_from_ns(epoch_ns),
            "unix_ns": epoch_ns,
            "event": event,
            "session_id": self.session_id,
            **details,
        }
        self._timeline.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    def _call(self, tool_use_id: str) -> dict:
        return self.tool_calls.setdefault(tool_use_id, {
            "name": None,
            "generated": False,
            "dispatched": False,
            "result_seen": False,
            "dispatch_ns": None,
        })

    def record_line(self, raw: bytes) -> None:
        """Timestamp and distill one Claude --output-format stream-json line."""
        if not raw.strip():
            return
        observed_ns = time.time_ns()
        try:
            outer = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self.unparsed_lines += 1
            return
        if not isinstance(outer, dict):
            return
        self.event_count += 1
        kind = outer.get("type")
        parent = str(outer.get("parent_tool_use_id") or "root")

        if kind == "stream_event":
            inner = outer.get("event") or {}
            if not isinstance(inner, dict):
                return
            event_kind = inner.get("type")

            if event_kind == "message_start":
                message = inner.get("message") or {}
                msg_id = message.get("id") if isinstance(message, dict) else None
                self._current_message[parent] = msg_id
                key = (parent, str(msg_id))
                if key not in self._started_messages:
                    self._started_messages.add(key)
                    self.model_response_count += 1
                    self.emit("llm_response_start", observed_ns,
                              message_id=msg_id,
                              parent_tool_use_id=outer.get("parent_tool_use_id"))

            elif event_kind == "message_stop":
                self.emit("llm_response_end", observed_ns,
                          message_id=self._current_message.get(parent),
                          parent_tool_use_id=outer.get("parent_tool_use_id"))
                self._current_message.pop(parent, None)

            elif event_kind == "content_block_start":
                block = inner.get("content_block") or {}
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    return
                call_id = block.get("id")
                if not call_id:
                    return
                call = self._call(str(call_id))
                call["name"] = block.get("name") or call["name"]
                if not call["generated"]:
                    call["generated"] = True
                    self.emit("tool_use_generated", observed_ns,
                              tool_use_id=str(call_id), tool_name=call["name"])
            return

        if kind == "assistant":
            message = outer.get("message") or {}
            if not isinstance(message, dict):
                return
            msg_id = message.get("id")
            key = (parent, str(msg_id))
            # Fallback for CLI versions that do not emit stream_event.
            if key not in self._started_messages:
                self._started_messages.add(key)
                self.model_response_count += 1
                self.emit("llm_response_observed", observed_ns,
                          message_id=msg_id, note="response already received; not request start")
            blocks = message.get("content") or []
            if not isinstance(blocks, list):
                return
            for block in blocks:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                call_id = block.get("id")
                if not call_id:
                    continue
                call = self._call(str(call_id))
                call["name"] = block.get("name") or call["name"]
                if not call["dispatched"]:
                    call["dispatched"] = True
                    call["dispatch_ns"] = observed_ns
                    # This is when the CLI reports the complete tool_use
                    # message; NOT verified MCP HTTP dispatch on the wire.
                    self.emit("tool_dispatch_observed", observed_ns,
                              tool_use_id=str(call_id), tool_name=call["name"])
            return

        if kind == "user":
            message = outer.get("message") or {}
            if not isinstance(message, dict):
                return
            blocks = message.get("content") or []
            if not isinstance(blocks, list):
                return
            for block in blocks:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                call_id = block.get("tool_use_id")
                if not call_id:
                    continue
                call = self._call(str(call_id))
                if call["result_seen"]:
                    continue
                call["result_seen"] = True
                elapsed = (observed_ns - call["dispatch_ns"]) / 1e9 if call["dispatch_ns"] else None
                self.emit("tool_result_observed", observed_ns,
                          tool_use_id=str(call_id), tool_name=call["name"],
                          is_error=bool(block.get("is_error", False)),
                          observed_elapsed_s=round(elapsed, 6) if elapsed is not None else None)
            return

        if kind == "result":
            self.final_result = outer

    def save_final_result(self, rc: int, timed_out: bool, stderr_excerpt: str) -> None:
        if self.final_result is not None:
            write_json(self.task_dir / "claude_output.json", self.final_result)
        else:
            write_json(self.task_dir / "claude_output.json", {
                "type": "result_unavailable",
                "session_id": self.session_id,
                "claude_exit_code": rc,
                "claude_timed_out": timed_out,
                "error": stderr_excerpt[-2000:] if rc != 0 else None,
            })


def run_claude(prompt: str, mcp_config: Path, task_dir: Path, on_process_exit=None):
    """Run Claude and save only condensed timestamped events and the final result.

    on_process_exit stops PCAP before file postprocessing.
    Returns: exit_code, timed_out, error, metadata
    """
    session_id = str(uuid.uuid4())
    env = os.environ.copy()

    # Do not expose MCPMark's host-side filesystem paths through environment
    # variables. Claude should use the MCP server as the measured tool path.
    for key in (
        "FILESYSTEM_TEST_ROOT",
        "FILESYSTEM_TEST_DIR",
        "TEST_ENVIRONMENT_URL",
    ):
        env.pop(key, None)

    cmd = [
        "claude",
        "-p",
        prompt,
        "--model",
        "gpt-6.1-sol",
        "--effort",
        "medium",
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-partial-messages",
        "--session-id",
        session_id,
        "--max-turns",
        str(CLAUDE_MAX_TURNS),
        "--no-session-persistence",
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
        "--allowedTools",
        "mcp__filesystem-local__*",
    ]

    rc = -1
    timed_out = False
    stderr_excerpt = ""
    process_started_at = None
    process_ended_at = None
    with ClaudeTimelineRecorder(task_dir, session_id) as trace:
        # TemporaryFile is unlinked on close; no claude_stderr.log is generated.
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as stderr_file:
            proc = subprocess.Popen(
                cmd,
                cwd=str(Path.cwd()),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                start_new_session=True,
                bufsize=0,
            )
            started_ns = time.time_ns()
            process_started_at = timestamp_from_ns(started_ns)
            trace.emit("claude_process_start", started_ns)
            assert proc.stdout is not None
            buf = bytearray()
            deadline = time.monotonic() + CLAUDE_TIMEOUT_S
            exit_seen_at = None
            drain_deadline = None
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                try:
                    while selector.get_map():
                        now = time.monotonic()
                        if not timed_out and now >= deadline and proc.poll() is None:
                            timed_out = True
                            stop_process(proc, signal.SIGTERM, 5)
                            drain_deadline = time.monotonic() + 3
                        if drain_deadline is not None and now >= drain_deadline:
                            break

                        ready = selector.select(timeout=0.2)
                        for key, _ in ready:
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            buf.extend(chunk)
                            while True:
                                pos = buf.find(b"\n")
                                if pos < 0:
                                    break
                                trace.record_line(bytes(buf[:pos]))
                                del buf[:pos + 1]

                        # A child can inherit stdout and keep it open after Claude
                        # exits; don't wait forever for that extra child.
                        if proc.poll() is not None:
                            if exit_seen_at is None:
                                exit_seen_at = time.monotonic()
                            elif time.monotonic() - exit_seen_at >= 3:
                                break
                except BaseException:
                    stop_process(proc, signal.SIGTERM, 5)
                    raise
                finally:
                    if buf.strip():
                        trace.record_line(bytes(buf))
                    proc.stdout.close()

            if proc.poll() is None:
                stop_process(proc, signal.SIGTERM, 5)
            rc = proc.wait()
            ended_ns = time.time_ns()
            process_ended_at = timestamp_from_ns(ended_ns)
            if timed_out:
                rc = 124
            trace.emit("claude_process_end", ended_ns, exit_code=rc,
                       timed_out=timed_out)
            # End the PCAP window immediately after the Claude process exits.
            # No expensive session export; stop PCAP before final result writing.
            if on_process_exit is not None:
                on_process_exit()
            stderr_file.seek(0)
            stderr_excerpt = stderr_file.read()[-2000:]

        # Only one timeline is retained; native/raw/duplicated logs are omitted.
        trace.save_final_result(rc, timed_out, stderr_excerpt)
        meta = {
            "claude_session_id": session_id,
            "claude_process_started_at_utc": process_started_at,
            "claude_process_ended_at_utc": process_ended_at,
            "claude_event_count": trace.event_count,
            "claude_model_response_count": trace.model_response_count,
            "claude_tool_call_count": sum(
                call["dispatched"] for call in trace.tool_calls.values()
            ),
            "claude_tool_result_count": sum(
                call["result_seen"] for call in trace.tool_calls.values()
            ),
            "claude_unparsed_stdout_lines": trace.unparsed_lines,
            "claude_timeline_path": str(task_dir / "claude_timeline.jsonl"),
        }

    if timed_out:
        error = f"Claude timed out after {CLAUDE_TIMEOUT_S}s"
    elif rc != 0:
        error = f"Claude CLI exited with code {rc}"
        if stderr_excerpt.strip():
            print(f"  [claude stderr excerpt] {stderr_excerpt[-500:].strip()}")
    else:
        error = None
    return rc, timed_out, error, meta


# ============================================================================
# Verification
# ============================================================================

def verify_task(
    task_manager: FilesystemTaskManager,
    task,
    task_dir: Path,
) -> dict:
    result = task_manager.run_verification(task)

    return {
        "returncode": result.returncode,
        "passed": result.returncode == 0,
    }


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--task",
        default=None,
        help=(
            'Optional task filter, e.g. '
            '"file_property/size_classification".'
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional task limit for smoke testing.",
    )
    parser.add_argument(
        "--resume-dir",
        default=None,
        help=(
            "Resume an existing experiment directory and skip tasks "
            "with result.json."
        ),
    )
    parser.add_argument(
        "--sudo-dumpcap",
        action="store_true",
        help=(
            "Run dumpcap as `sudo -n dumpcap`. "
            "Run `sudo -v` first."
        ),
    )

    args = parser.parse_args()

    repo_root = Path.cwd().resolve()

    if not (repo_root / "tasks" / "filesystem" / TASK_SUITE).exists():
        print("[ERROR] Run this script from the MCPMark repository root.")
        return 2

    env_path = repo_root / ".mcp_env"
    if env_path.exists():
        load_dotenv(env_path, override=False)

    for command in ("claude", "npx", "dumpcap"):
        need_command(command)

    if args.sudo_dumpcap:
        need_command("sudo")

    if args.resume_dir:
        run_root = Path(args.resume_dir).resolve()
        run_root.mkdir(parents=True, exist_ok=True)
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_root = repo_root / RESULTS_ROOT_NAME / stamp
        run_root.mkdir(parents=True, exist_ok=True)

    (run_root / "notion_mcp_server.log").write_bytes(b"")

    write_json(
        run_root / "experiment.json",
        {
            "created_at": now_iso(),
            "repo_root": str(repo_root),
            "task_suite": TASK_SUITE,
            "mcp_url": MCP_URL,
            "filesystem_mcp_package": FILESYSTEM_MCP_PACKAGE,
            "transport_bridge": SUPERGATEWAY_PACKAGE,
            "transport_bridge_mode": "stateful Streamable HTTP -> stdio",
            "filesystem_test_root": os.getenv("FILESYSTEM_TEST_ROOT"),
            "claude_model": "gpt-5.6-luna",
            "claude_effort": "medium",
            "claude_max_turns": CLAUDE_MAX_TURNS,
            "claude_timeout_s": CLAUDE_TIMEOUT_S,
            "claude_output_format": "stream-json",
            "claude_session_persistence": False,
            "claude_timeline_timestamp_source": "runner reads Claude stdout (UTC)",
            "claude_timing_notice": (
                "llm_response_start is not LLM HTTP request start; "
                "tool_dispatch_observed is not exact MCP HTTP send time; "
                "use PCAP for wire-level timestamps"
            ),
            "capture_boundary": (
                "after Filesystem state setup and MCP bridge startup; "
                "before verifier and cleanup"
            ),
        },
    )

    task_manager = FilesystemTaskManager(
        tasks_root=repo_root / "tasks",
        task_suite=TASK_SUITE,
    )

    all_tasks = task_manager.discover_all_tasks()

    if len(all_tasks) != EXPECTED_TASK_COUNT:
        print(
            f"[WARN] Expected {EXPECTED_TASK_COUNT} Filesystem standard tasks "
            f"for the current MCPMark main branch, but discovered "
            f"{len(all_tasks)} in this checkout."
        )

    if args.task:
        tasks = task_manager.filter_tasks(args.task)
        if not tasks:
            print(f"[ERROR] No task matched: {args.task}")
            return 2
    else:
        tasks = all_tasks

    if args.limit is not None:
        tasks = tasks[: args.limit]

    test_root_raw = os.getenv("FILESYSTEM_TEST_ROOT", "").strip()
    state_manager = FilesystemStateManager(
        test_root=Path(test_root_raw) if test_root_raw else None,
        cleanup_on_exit=True,
    )

    mcp_config = make_claude_mcp_config(run_root)
    summary_rows: list[dict] = []

    try:
        print(f"Experiment dir : {run_root}")
        print(f"Tasks          : {len(tasks)}")
        print(f"MCP endpoint   : {MCP_URL}")
        print(f"Filesystem MCP : {FILESYSTEM_MCP_PACKAGE}")
        print(f"Bridge         : {SUPERGATEWAY_PACKAGE}")
        print()

        for index, task in enumerate(tasks, 1):
            task_name = task.name
            task_dir = run_root / safe_name(task_name)
            task_dir.mkdir(parents=True, exist_ok=True)
            # Match the Notion runner's retained task artifacts on reruns.
            for unwanted in (
                "capture.log", "claude_stderr.log",
                "verify_stdout.log", "verify_stderr.log",
                "messages.json", "filesystem_mcp_bridge.log",
            ):
                (task_dir / unwanted).unlink(missing_ok=True)

            result_path = task_dir / "result.json"

            if args.resume_dir and result_path.exists():
                print(
                    f"[{index}/{len(tasks)}] "
                    f"SKIP completed: {task_name}"
                )
                try:
                    summary_rows.append(
                        json.loads(
                            result_path.read_text(
                                encoding="utf-8"
                            )
                        )
                    )
                except Exception:
                    pass
                continue

            print("=" * 72)
            print(f"[{index}/{len(tasks)}] {task_name}")
            print("=" * 72)

            capture_proc = None
            bridge_proc = None
            bridge_log_handle = None
            setup_ok = False

            task_result = {
                "task_name": task_name,
                "category_id": task.category_id,
                "task_id": task.task_id,
                "started_at": now_iso(),
                "setup_ok": False,
                "test_directory": None,
                "claude_exit_code": None,
                "claude_timed_out": False,
                "claude_session_id": None,
                "claude_event_count": 0,
                "claude_tool_call_count": 0,
                "verify_passed": False,
                "verify_returncode": None,
                "cleanup_ok": False,
                "error": None,
                "pcap": str(task_dir / "raw_traffic.pcapng"),
            }

            try:
                # ------------------------------------------------------------
                # OUTSIDE PCAP: create an isolated task-specific backup.
                # ------------------------------------------------------------
                print("  [setup] Creating isolated Filesystem task state...")
                setup_ok = bool(state_manager.set_up(task))
                task_result["setup_ok"] = setup_ok

                if not setup_ok:
                    raise RuntimeError(
                        "MCPMark FilesystemStateManager.set_up() failed"
                    )

                test_directory = Path(str(task.test_directory)).resolve()
                task_result["test_directory"] = str(test_directory)

                prompt = build_claude_prompt(
                    task_manager,
                    task,
                )
                (task_dir / "task_prompt.txt").write_text(
                    prompt,
                    encoding="utf-8",
                )

                # ------------------------------------------------------------
                # OUTSIDE PCAP: start stdio -> HTTP bridge.
                # ------------------------------------------------------------
                print(
                    "  [mcp] Starting Filesystem MCP "
                    "behind local Streamable HTTP bridge..."
                )
                bridge_proc, bridge_log_handle = (
                    start_filesystem_mcp_bridge_with_retry(
                        test_directory,
                        task_dir,
                    )
                )
                print("  [mcp] Bridge ready.")

                # ------------------------------------------------------------
                # MEASURED WINDOW.
                # ------------------------------------------------------------
                print("  [pcap] Starting dumpcap...")
                capture_proc = start_capture(
                    task_dir / "raw_traffic.pcapng",
                    use_sudo=args.sudo_dumpcap,
                )

                print("  [claude] Running task...")
                task_result["claude_started_at"] = now_iso()

                rc, timed_out, claude_error, claude_meta = run_claude(
                    prompt=prompt,
                    mcp_config=mcp_config,
                    task_dir=task_dir,
                    on_process_exit=lambda: stop_capture(capture_proc),
                )

                task_result["claude_ended_at"] = now_iso()
                task_result["claude_exit_code"] = rc
                task_result["claude_timed_out"] = timed_out
                task_result.update(claude_meta)
                task_result["claude_started_at"] = claude_meta["claude_process_started_at_utc"]
                task_result["claude_ended_at"] = claude_meta["claude_process_ended_at_utc"]

                if claude_error:
                    task_result["error"] = claude_error

                stop_capture(capture_proc)
                capture_proc = None

                # Bridge traffic should not leak into verifier/cleanup.
                stop_filesystem_mcp_bridge(
                    bridge_proc,
                    bridge_log_handle,
                )
                bridge_proc = None
                bridge_log_handle = None

                # ------------------------------------------------------------
                # OUTSIDE PCAP: original MCPMark verification.
                # ------------------------------------------------------------
                print("  [verify] Running original MCPMark verifier...")

                verify = verify_task(
                    task_manager,
                    task,
                    task_dir,
                )

                task_result["verify_passed"] = verify["passed"]
                task_result["verify_returncode"] = verify["returncode"]

                print(
                    f"  [verify] "
                    f"{'PASS' if verify['passed'] else 'FAIL'}"
                )

            except KeyboardInterrupt:
                raise

            except Exception as exc:
                task_result["error"] = str(exc)
                print(f"  [ERROR] {exc}")

            finally:
                if capture_proc is not None:
                    stop_capture(capture_proc)

                if bridge_proc is not None or bridge_log_handle is not None:
                    stop_filesystem_mcp_bridge(
                        bridge_proc,
                        bridge_log_handle,
                    )

                if setup_ok:
                    print(
                        "  [cleanup] Removing Filesystem task backup..."
                    )
                    try:
                        task_result["cleanup_ok"] = bool(
                            state_manager.clean_up(task)
                        )
                    except Exception as exc:
                        task_result["cleanup_ok"] = False

                        if task_result["error"]:
                            task_result["error"] += (
                                f"; cleanup: {exc}"
                            )
                        else:
                            task_result["error"] = (
                                f"cleanup: {exc}"
                            )

                task_result["ended_at"] = now_iso()

                write_json(
                    result_path,
                    task_result,
                )
                summary_rows.append(task_result)

                print(
                    "  [done] "
                    f"claude_rc={task_result['claude_exit_code']} "
                    f"verify="
                    f"{'PASS' if task_result['verify_passed'] else 'FAIL'}"
                )
                print()

    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user.")

    finally:
        try:
            mcp_config.unlink(missing_ok=True)
        except Exception:
            pass

    summary_csv = run_root / "summary.csv"

    fields = [
        "task_name",
        "category_id",
        "task_id",
        "setup_ok",
        "test_directory",
        "claude_exit_code",
        "claude_timed_out",
        "verify_passed",
        "verify_returncode",
        "cleanup_ok",
        "error",
        "pcap",
    ]

    with summary_csv.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    passed = sum(
        1
        for row in summary_rows
        if row.get("verify_passed")
    )
    total = len(summary_rows)

    print()
    print("=== Batch Summary ===")
    print(f"completed : {total}")
    print(f"verified  : {passed}/{total}")
    print(f"results   : {run_root}")
    print(f"summary   : {summary_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
