#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MCPMark Notion (28 tasks) + Claude Code + Streamable HTTP MCP + PCAP runner.

Run from the MCPMark repository root:

    chmod +x run_mcpmark_notion_claude.py
    ./run_mcpmark_notion_claude.py

Prerequisites:
  - .mcp_env is configured for MCPMark Notion
  - notion_state.json exists (created by notion_login_helper)
  - `claude`, `npx` (local mode), `dumpcap` are in PATH
  - Claude Code's LLM endpoint is already configured by you

Default behavior:
  1) Start ONE local Notion MCP server on 127.0.0.1:3000
     using EVAL_NOTION_API_KEY only. Use --mcp remote for the hosted server.
  2) Discover all 28 MCPMark Notion standard tasks.
  3) For each task:
       MCPMark set_up() -> duplicate clean Source template into Eval Hub
       start dumpcap
       run Claude Code with only notion-local MCP
       stop dumpcap
       run the original MCPMark verify.py
       clean_up() the duplicated Eval page
  4) Save one concise Claude event timeline per task, plus PCAP and run results.
     Timeline timestamps are UTC when the runner reads a CLI event.
     They are NOT guaranteed to equal wire-level HTTP request timestamps.

Per-task files:
  raw_traffic.pcapng     packet-level capture
  claude_timeline.jsonl  chronological Claude model/tool events (one record per event)
  claude_output.json     final Claude result / metadata
  task_prompt.txt        task prompt
  result.json            task status and MCPMark verifier pass/fail

The timeline includes model response start/end, tool-call generation,
observed tool dispatch and tool-result events. The actual outbound LLM HTTP
request start and MCP request-send timestamps must be recovered from PCAP;
Claude Code's stream-json output does not expose those wire times.

Not created: claude_history.jsonl, claude_session.jsonl,
             claude_stream.jsonl, claude_events.jsonl,
             claude_tool_calls.json, claude_tool_events.jsonl,
             capture.log, claude_stderr.log, verify_stdout.log,
             verify_stderr.log.

Source credentials are NEVER passed to Claude Code or to the Notion MCP server.
The integration API keys initialize/verify/clean up tasks; they do not authenticate
the hosted MCP. For --mcp remote, authorize the hosted server in Claude Code first.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import selectors
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.mcp_services.notion.notion_task_manager import NotionTaskManager
from src.mcp_services.notion.notion_state_manager import NotionStateManager


MCP_HOST = "127.0.0.1"
MCP_PORT = 3000
MCP_URL = f"http://{MCP_HOST}:{MCP_PORT}/mcp"
MCP_AUTH_TOKEN = "mcpmark-local-capture-2026"
# Official Notion-hosted Streamable HTTP MCP endpoint (requires OAuth).
REMOTE_MCP_URL = "https://mcp.notion.com/mcp"
NOTION_MCP_PACKAGE = "@notionhq/notion-mcp-server@1.9.1"

TASK_SUITE = "standard"
EXPECTED_TASK_COUNT = 28
CLAUDE_MAX_TURNS = 50
CLAUDE_TIMEOUT_S = 3600
RESULTS_ROOT_NAME = "results_claude_mcpmark_notion"


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


def stop_process(proc, sig=signal.SIGTERM, timeout_s=10.0):
    if proc is None or proc.poll() is not None:
        return

    try:
        # proc 是用 start_new_session=True 启动的，
        # 所以 proc.pid 同时也是新进程组的 PGID。
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


def write_json(path: Path, obj) -> None:
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def tcp_port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port(host: str, port: int, proc: subprocess.Popen, timeout_s: float = 45.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Notion MCP server exited early with code {proc.returncode}")
        if tcp_port_open(host, port):
            return
        time.sleep(0.2)
    raise RuntimeError(f"Timed out waiting for {host}:{port}")


def start_notion_mcp(eval_token: str, run_root: Path):
    if tcp_port_open(MCP_HOST, MCP_PORT):
        raise RuntimeError(
            f"{MCP_HOST}:{MCP_PORT} is already in use. "
            "Stop the existing MCP server before starting the batch."
        )

    log_handle = (run_root / "notion_mcp_server.log").open("wb")
    env = os.environ.copy()
    env.pop("SOURCE_NOTION_API_KEY", None)
    env["NOTION_TOKEN"] = eval_token
    env["AUTH_TOKEN"] = MCP_AUTH_TOKEN
    cmd = [
        "npx", "--prefer-offline", "-y", NOTION_MCP_PACKAGE,
        "--transport", "http", "--port", str(MCP_PORT),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=str(Path.cwd()),
        env=env,
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


def make_claude_mcp_config(run_root: Path, mcp_url: str = REMOTE_MCP_URL) -> Path:
    path = run_root / ".claude_mcp_config.json"
    config = {
        "mcpServers": {
            "notion-local": {
                "type": "http",
                "url": mcp_url,
            }
        }
    }
    if mcp_url == MCP_URL:
        config["mcpServers"]["notion-local"]["headers"] = {
            "Authorization": f"Bearer {MCP_AUTH_TOKEN}"
        }
    write_json(path, config)
    os.chmod(path, 0o600)
    return path


def build_claude_prompt(task_manager: NotionTaskManager, task) -> str:
    prompt = task_manager.get_task_instruction(task)
    return (
        prompt
        + "\n\n"
        + "Use the notion-local MCP server for all Notion access and edits. "
          "Work only on the evaluation copy that is available to that MCP server. "
          "Complete the task fully; do not ask the user questions."
    )


# ============================================================================
# Minimal event timeline for aligning Claude Code with packet capture
# ============================================================================

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
    for key in (
        "SOURCE_NOTION_API_KEY",
        "EVAL_NOTION_API_KEY",
        "SOURCE_PARENT_PAGE_TITLE",
        "EVAL_PARENT_PAGE_TITLE",
        "NOTION_TOKEN",
        "OPENAPI_MCP_HEADERS",
    ):
        env.pop(key, None)

    cmd = [
        "claude", "-p", prompt,
        "--model", "gpt-6.1-sol",
        "--effort", "medium",
        "--output-format", "stream-json",
        "--verbose",
        "--include-partial-messages",
        "--session-id", session_id,
        "--max-turns", str(CLAUDE_MAX_TURNS),
        "--no-session-persistence",  # output is only the task timeline
        "--strict-mcp-config",
        "--mcp-config", str(mcp_config),
        "--allowedTools", "mcp__notion-local__*",
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


def verify_task(task_manager: NotionTaskManager, task) -> dict:
    """Still run MCPMark verification; store only the status in result.json."""
    result = task_manager.run_verification(task)
    return {
        "returncode": result.returncode,
        "passed": result.returncode == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mcp",
        choices=("local", "remote", "mix"),
        default="remote",
        help="Use local, official hosted, or alternating local/remote Notion MCP servers. Default: remote.",
    )
    parser.add_argument(
        "--task",
        default=None,
        help='Optional single task filter, e.g. "online_resume/work_history_addition".',
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional limit for smoke testing. Default: run all 28.",
    )
    parser.add_argument(
        "--resume-dir",
        default=None,
        help="Resume an existing experiment directory and skip tasks with result.json.",
    )
    parser.add_argument(
        "--sudo-dumpcap",
        action="store_true",
        help="Run dumpcap as `sudo -n dumpcap`. Run `sudo -v` first.",
    )
    args = parser.parse_args()
    mcp_url = REMOTE_MCP_URL if args.mcp == "remote" else MCP_URL

    repo_root = Path.cwd().resolve()

    if not (repo_root / "tasks" / "notion" / TASK_SUITE).exists():
        print("[ERROR] Run this script from the MCPMark repository root.")
        return 2

    if not (repo_root / "notion_state.json").exists():
        print("[ERROR] notion_state.json not found. Run notion_login_helper first.")
        return 2

    env_path = repo_root / ".mcp_env"
    if not env_path.exists():
        print("[ERROR] .mcp_env not found.")
        return 2

    load_dotenv(env_path, override=False)

    source_token = os.getenv("SOURCE_NOTION_API_KEY", "").strip()
    eval_token = os.getenv("EVAL_NOTION_API_KEY", "").strip()
    source_title = os.getenv("SOURCE_PARENT_PAGE_TITLE", "MCPMark Source Hub").strip()
    eval_title = os.getenv("EVAL_PARENT_PAGE_TITLE", "MCPMark Eval Hub").strip()
    browser = os.getenv("PLAYWRIGHT_BROWSER", "chromium").strip()
    headless_raw = os.getenv("PLAYWRIGHT_HEADLESS", "True").strip().lower()
    headless = headless_raw in {"1", "true", "yes", "on"}

    if not source_token or not eval_token:
        print("[ERROR] SOURCE_NOTION_API_KEY / EVAL_NOTION_API_KEY missing from .mcp_env")
        return 2

    need_command("claude")
    if args.mcp in ("local", "mix"):
        need_command("npx")
    need_command("dumpcap")
    if args.sudo_dumpcap:
        need_command("sudo")

    if args.resume_dir:
        run_root = Path(args.resume_dir).resolve()
        run_root.mkdir(parents=True, exist_ok=True)
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_root = repo_root / RESULTS_ROOT_NAME / stamp
        run_root.mkdir(parents=True, exist_ok=True)

    if args.mcp == "mix":
        (run_root / "local").mkdir(parents=True, exist_ok=True)
        (run_root / "remote").mkdir(parents=True, exist_ok=True)

    write_json(
        run_root / "experiment.json",
        {
            "created_at": now_iso(),
            "repo_root": str(repo_root),
            "task_suite": TASK_SUITE,
            "mcp_url": {"local": MCP_URL, "remote": REMOTE_MCP_URL} if args.mcp == "mix" else mcp_url,
            "notion_mcp_package": (
                f"{NOTION_MCP_PACKAGE} / Notion hosted MCP" if args.mcp == "mix"
                else NOTION_MCP_PACKAGE if args.mcp == "local" else "Notion hosted MCP"
            ),
            "source_parent_page_title": source_title,
            "eval_parent_page_title": eval_title,
            "playwright_browser": browser,
            "playwright_headless": headless,
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
        },
    )

    task_manager = NotionTaskManager(
        tasks_root=repo_root / "tasks",
        task_suite=TASK_SUITE,
    )
    all_tasks = task_manager.discover_all_tasks()

    if len(all_tasks) != EXPECTED_TASK_COUNT:
        print(
            f"[WARN] Expected {EXPECTED_TASK_COUNT} Notion tasks, "
            f"but discovered {len(all_tasks)}."
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

    runs = ([(task, mode) for task in tasks for mode in ("local", "remote")]
            if args.mcp == "mix" else [(task, args.mcp) for task in tasks])

    state_manager = NotionStateManager(
        source_notion_key=source_token,
        eval_notion_key=eval_token,
        headless=headless,
        browser=browser,
        eval_parent_page_title=eval_title,
        source_parent_page_title=source_title,
    )

    mcp_proc = None
    mcp_log_handle = None
    mcp_config = make_claude_mcp_config(run_root, mcp_url)
    summary_rows = []

    try:
        print(f"Experiment dir : {run_root}")
        print(f"Tasks          : {len(tasks)}")
        print(f"MCP endpoint   : {MCP_URL} (local), {REMOTE_MCP_URL} (remote)"
              if args.mcp == "mix" else f"MCP endpoint   : {mcp_url}")
        print()

        if args.mcp in ("local", "mix"):
            print("[BOOT] Starting one persistent Notion MCP server...")
            mcp_proc, mcp_log_handle = start_notion_mcp(eval_token, run_root)
            print("[BOOT] MCP server ready.")
            print()

        for index, (task, run_mode) in enumerate(runs, 1):
            task_name = task.name
            task_dir = (run_root / run_mode / safe_name(task_name)
                        if args.mcp == "mix" else run_root / safe_name(task_name))
            task_dir.mkdir(parents=True, exist_ok=True)
            # Also eliminate stale logs if reusing an older result directory.
            for unwanted in (
                "capture.log", "claude_stderr.log",
                "verify_stdout.log", "verify_stderr.log",
            ):
                (task_dir / unwanted).unlink(missing_ok=True)
            result_path = task_dir / "result.json"

            if args.resume_dir and result_path.exists():
                print(f"[{index}/{len(runs)}] SKIP completed: {task_name}"
                      + (f" ({run_mode})" if args.mcp == "mix" else ""))
                try:
                    summary_rows.append(
                        json.loads(result_path.read_text(encoding="utf-8"))
                    )
                except Exception:
                    pass
                continue

            if args.mcp == "mix":
                mcp_config = make_claude_mcp_config(
                    run_root, MCP_URL if run_mode == "local" else REMOTE_MCP_URL
                )

            print("=" * 72)
            print(f"[{index}/{len(runs)}] {task_name}"
                  + (f" ({run_mode})" if args.mcp == "mix" else ""))
            print("=" * 72)

            capture_proc = None
            setup_ok = False
            task_result = {
                "task_name": task_name,
                "category_id": task.category_id,
                "task_id": task.task_id,
                "started_at": now_iso(),
                "setup_ok": False,
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
                print("  [setup] Creating clean Eval Hub state...")
                setup_ok = state_manager.set_up(task)
                task_result["setup_ok"] = setup_ok
                if not setup_ok:
                    raise RuntimeError("MCPMark NotionStateManager.set_up() failed")

                task_result["duplicated_initial_state_id"] = task.duplicated_initial_state_id
                task_result["duplicated_initial_state_url"] = task.duplicated_initial_state_url

                prompt = build_claude_prompt(task_manager, task)
                (task_dir / "task_prompt.txt").write_text(prompt, encoding="utf-8")

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

                print("  [verify] Running original MCPMark verifier...")
                verify = verify_task(task_manager, task)
                task_result["verify_passed"] = verify["passed"]
                task_result["verify_returncode"] = verify["returncode"]

                print(f"  [verify] {'PASS' if verify['passed'] else 'FAIL'}")

            except KeyboardInterrupt:
                raise
            except Exception as exc:
                task_result["error"] = str(exc)
                print(f"  [ERROR] {exc}")

            finally:
                if capture_proc is not None:
                    stop_capture(capture_proc)

                if setup_ok:
                    print("  [cleanup] Archiving Eval task state...")
                    try:
                        task_result["cleanup_ok"] = bool(state_manager.clean_up(task))
                    except Exception as exc:
                        task_result["cleanup_ok"] = False
                        if task_result["error"]:
                            task_result["error"] += f"; cleanup: {exc}"
                        else:
                            task_result["error"] = f"cleanup: {exc}"

                task_result["ended_at"] = now_iso()
                write_json(result_path, task_result)
                summary_rows.append(task_result)

                print(
                    "  [done] "
                    f"claude_rc={task_result['claude_exit_code']} "
                    f"verify={'PASS' if task_result['verify_passed'] else 'FAIL'}"
                )
                print()

    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user.")

    finally:
        if mcp_proc is not None:
            print("[SHUTDOWN] Stopping Notion MCP server...")
            stop_process(mcp_proc, signal.SIGTERM, 10)
        if mcp_log_handle is not None:
            mcp_log_handle.close()
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
        "claude_exit_code",
        "claude_timed_out",
        "verify_passed",
        "verify_returncode",
        "cleanup_ok",
        "error",
        "pcap",
    ]

    with summary_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in summary_rows:
            writer.writerow(row)

    passed = sum(1 for r in summary_rows if r.get("verify_passed"))
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
