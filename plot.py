#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Plot a Claude Code event timeline aligned with upstream/downstream PCAP traffic.

Input files (from run_mcpmark_notion_claude.py):
  <task_dir>/claude_timeline.jsonl
  <task_dir>/raw_traffic.pcapng

Example (run in WSL):
  sudo apt-get install -y tshark
  pip install numpy matplotlib
  python plot_agent_traffic_timeline.py \
      --task-dir /path/to/results_claude_mcpmark_notion/<run>/<task> \
      --llm-endpoint 192.168.3.125:8317 \
      --bin-ms 100

Output: <task_dir>/agent_traffic_timeline.png, unless --output specifies another path.

Scientific measurement notes:
  1. Claude timeline timestamps are when the *runner observed CLI events*.
     'llm_response_start' is not the time an LLM HTTP request was sent.
     'tool_dispatch_observed' is not an exact MCP HTTP request start.
  2. When plaintext HTTP is visible, tshark can still identify HTTP requests,
     but they are no longer plotted as separate markers. A decoded request
     may be on the packet completing header reassembly, not its first byte.
  3. Network throughput uses frame.len (captured bytes incl. headers and
     retransmissions), not TCP payload bytes. Loopback MCP bytes are not WAN.
     A capture on 'any' may include duplicates, depending on interfaces.
  4. Encrypted traffic is classified by supplied endpoint, TLS SNI, or captured
     DNS answers, not by decrypted HTTP content; shared IPs, encrypted DNS,
     missing ClientHello, or missing DNS may cause 'Other' classification.
  5. 'Upstream' means client -> service, NOT necessarily host egress on every
     interface. Direction is inferred using endpoints, SYN, HTTP, or ports;
     traffic with indeterminate direction is omitted and reported.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch, Rectangle
from matplotlib.lines import Line2D

CATEGORIES = ("LLM", "MCP-local", "Web/API", "Other")
COLORS = {
    "LLM": "#528DDB",         # response / gateway
    "MCP-local": "#E98F3D",   # local MCP only, not WAN
    "Web/API": "#1CA998",     # downstream third-party service
    "Other": "#9A9FA9",
}
# High-contrast colors are reused per LLM round (not assigned by tool type).
TOOL_MARKER_COLORS = ("#6E56CF", "#DB4D98", "#009B91", "#D97722", "#327BC4", "#6E9E3D", "#B05CC2")

# See --help for fields and their interpretation.
TSHARK_FIELDS = (
    "frame.time_epoch", "frame.len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.stream", "tcp.flags.syn", "tcp.flags.ack",
    "dns.flags.response", "dns.qry.name", "dns.a", "dns.aaaa",
    "tls.handshake.extensions_server_name", "http.request.method", "http.request.uri",
)


def split_one(value: str) -> str:
    """First field occurrence (tshark -E occurrence=f is set)."""
    return value.split(",", 1)[0].strip() if value else ""


def normalize_hostname(host: str) -> str:
    return host.strip().lower().rstrip(".")


def hostname_matches(host: str, patterns: list[str]) -> bool:
    host = normalize_hostname(host)
    return bool(host) and any(
        host == p or host.endswith("." + p)
        for p in patterns
    )


def parse_endpoint(value: str) -> tuple[str, int]:
    """Host:port, IP:port or [IPv6]:port. DNS host resolution not attempted."""
    value = value.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", value)
        if not match:
            raise argparse.ArgumentTypeError("IPv6 requires [address]:port")
        host, port = match.groups()
    else:
        try:
            host, port = value.rsplit(":", 1)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("Endpoint must be address:port") from exc
        if ":" in host:
            raise argparse.ArgumentTypeError("IPv6 requires [address]:port")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"Invalid endpoint: {value}")
    return host.strip().lower(), int(port)


def timestamp_seconds(row: dict) -> float:
    if row.get("unix_ns") is not None:
        return int(row["unix_ns"]) / 1e9
    if row.get("timestamp_utc"):
        value = str(row["timestamp_utc"])
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    raise ValueError(f"Event has no unix_ns/timestamp_utc: {row}")


def read_events(path: Path) -> tuple[list[dict], float, float]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing event file: {path}")
    events: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
                row["_ts"] = timestamp_seconds(row)
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"Malformed {path.name}:{lineno}: {exc}") from exc
            events.append(row)
    if not events:
        raise ValueError(f"No events in {path}")
    events.sort(key=lambda e: e["_ts"])
    starts = [e["_ts"] for e in events if e.get("event") == "claude_process_start"]
    ends = [e["_ts"] for e in events if e.get("event") == "claude_process_end"]
    t0 = min(starts) if starts else events[0]["_ts"]
    t1 = max(ends) if ends else events[-1]["_ts"]
    if t1 < t0:
        raise ValueError("End timestamp is before start timestamp")
    if t1 == t0:
        t1 += 0.1
    return events, t0, t1


@dataclass
class EventBars:
    llm_intervals: list[tuple[float, float]] = field(default_factory=list)
    llm_observed: list[float] = field(default_factory=list)
    tool_intervals: list[tuple[float, float, str, int, int]] = field(default_factory=list)
    tool_dispatches: list[tuple[float, str, int, int]] = field(default_factory=list)
    tool_generated: list[float] = field(default_factory=list)
    tool_results: list[tuple[float, int, int]] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)


def pair_events(events: list[dict], t0: float, t1: float) -> EventBars:
    """Keep overlapping tool calls / LLM messages independent."""
    bars = EventBars()
    llm_started: dict[tuple[str, str], float] = {}
    tool_started: dict[str, tuple[float, str, int, int]] = {}
    current_round = -1
    round_tool_counts: dict[int, int] = defaultdict(int)
    for e in events:
        kind = e.get("event")
        ts = float(e["_ts"])
        bars.counts[kind] += 1
        par = str(e.get("parent_tool_use_id") or "root")
        msg_id = str(e.get("message_id") or "")
        if kind == "llm_response_start":
            current_round += 1
            llm_started[(par, msg_id)] = ts
        elif kind == "llm_response_end":
            key = (par, msg_id)
            if key in llm_started:
                start = llm_started.pop(key)
                bars.llm_intervals.append((start - t0, max(0.0, ts - start)))
            else:
                bars.llm_observed.append(ts - t0)
        elif kind == "llm_response_observed":
            bars.llm_observed.append(ts - t0)
        elif kind == "tool_use_generated":
            bars.tool_generated.append(ts - t0)
        elif kind == "tool_dispatch_observed":
            tid = str(e.get("tool_use_id") or f"no-id-{ts}")
            name = str(e.get("tool_name") or "unknown")
            round_idx = max(current_round, 0)
            slot = round_tool_counts[round_idx]
            round_tool_counts[round_idx] += 1
            tool_started[tid] = (ts, name, round_idx, slot)
            bars.tool_dispatches.append((ts - t0, name, round_idx, slot))
        elif kind == "tool_result_observed":
            tid = str(e.get("tool_use_id") or "")
            if tid in tool_started:
                start, name, round_idx, slot = tool_started.pop(tid)
                bars.tool_results.append((ts - t0, round_idx, slot))
                bars.tool_intervals.append((start - t0, max(0.0, ts - start), name, round_idx, slot))
            else:
                bars.tool_results.append((ts - t0, -1, 0))
    # Unclosed LLM responses have unknown end; show only an instantaneous marker.
    bars.llm_observed.extend(ts - t0 for ts in llm_started.values())
    return bars


@dataclass
class Packet:
    ts: float
    length: int
    src: str
    dst: str
    sport: int
    dport: int
    stream: str
    syn: bool
    ack: bool
    dns_response: bool
    dns_name: str
    dns_addresses: tuple[str, ...]
    sni: str
    http_method: str
    http_uri: str


def parse_packet(row: list[str]) -> Packet | None:
    if len(row) < len(TSHARK_FIELDS):
        row += [""] * (len(TSHARK_FIELDS) - len(row))
    data = dict(zip(TSHARK_FIELDS, row))
    if not data["frame.time_epoch"]:
        return None
    src = split_one(data["ip.src"] or data["ipv6.src"])
    dst = split_one(data["ip.dst"] or data["ipv6.dst"])
    if not src or not dst:
        return None
    try:
        length = int(split_one(data["frame.len"]))
        port_src = split_one(data["tcp.srcport"] or data["udp.srcport"])
        port_dst = split_one(data["tcp.dstport"] or data["udp.dstport"])
        return Packet(
            ts=float(data["frame.time_epoch"]),
            length=length,
            src=src.lower(), dst=dst.lower(),
            sport=int(port_src) if port_src else 0,
            dport=int(port_dst) if port_dst else 0,
            stream=split_one(data["tcp.stream"]),
            syn=split_one(data["tcp.flags.syn"]) == "1",
            ack=split_one(data["tcp.flags.ack"]) == "1",
            dns_response=split_one(data["dns.flags.response"]) == "1",
            dns_name=normalize_hostname(split_one(data["dns.qry.name"])),
            dns_addresses=tuple(
                a.strip().lower()
                for field_name in ("dns.a", "dns.aaaa")
                for a in (data[field_name] or "").split(",")
                if a.strip()
            ),
            sni=normalize_hostname(split_one(data["tls.handshake.extensions_server_name"])),
            http_method=split_one(data["http.request.method"]).upper(),
            http_uri=split_one(data["http.request.uri"]),
        )
    except (ValueError, OverflowError):
        return None


def tshark_rows(pcap: Path, decode_ports: set[int], discovery_only: bool) -> Iterator[list[str]]:
    if shutil.which("tshark") is None:
        raise RuntimeError("tshark is required. In WSL: sudo apt install tshark")
    cmd = ["tshark", "-n", "-r", str(pcap)]
    for port in sorted(decode_ports):
        if port not in (80, 443):
            cmd += ["-d", f"tcp.port=={port},http"]
    if discovery_only:
        cmd += ["-Y", "(dns.flags.response == 1) || (tls.handshake.extensions_server_name) || (tcp.flags.syn == 1 && tcp.flags.ack == 0) || (http.request.method)"]
    else:
        cmd += ["-Y", "ip || ipv6"]
    cmd += ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n"]
    for name in TSHARK_FIELDS:
        cmd += ["-e", name]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            yield line.rstrip("\r\n").split("\t")
    finally:
        proc.stdout.close()
        stderr = proc.stderr.read() if proc.stderr else ""
        rc = proc.wait()
        if rc != 0:
            raise RuntimeError(
                f"tshark exited with code {rc}. Command: {' '.join(cmd)}\n"
                + stderr[-4000:]
            )


@dataclass
class Discovery:
    stream_sni: dict[str, str] = field(default_factory=dict)
    dns_by_ip: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    # tcp.stream -> ((client_ip, port), (server_ip, port))
    stream_direction: dict[str, tuple[tuple[str, int], tuple[str, int]]] = field(default_factory=dict)


def discover(pcap: Path, decode_ports: set[int]) -> Discovery:
    info = Discovery()
    for row in tshark_rows(pcap, decode_ports, discovery_only=True):
        p = parse_packet(row)
        if p is None:
            continue
        if p.dns_response and p.dns_name:
            for addr in p.dns_addresses:
                info.dns_by_ip[addr].add(p.dns_name)
        if p.stream and p.sni:
            info.stream_sni[p.stream] = p.sni
        if p.stream and p.syn and not p.ack:
            info.stream_direction.setdefault(
                p.stream, ((p.src, p.sport), (p.dst, p.dport))
            )
        if p.stream and p.http_method:
            info.stream_direction.setdefault(
                p.stream, ((p.src, p.sport), (p.dst, p.dport))
            )
    return info


@dataclass
class Options:
    llm_endpoints: set[tuple[str, int]]
    mcp_endpoints: set[tuple[str, int]]
    llm_domains: list[str]
    web_domains: list[str]
    web_ips: set[str]
    local_ips: set[str]
    auto_web_sni: bool
    agent_domains: list[str]


def end_is(p: Packet, ends: set[tuple[str, int]]) -> str | None:
    if (p.dst, p.dport) in ends:
        return "up"
    if (p.src, p.sport) in ends:
        return "down"
    return None


def known_server(p: Packet, disc: Discovery) -> tuple[str, int] | None:
    if p.stream and p.stream in disc.stream_direction:
        return disc.stream_direction[p.stream][1]
    return None


def classify(p: Packet, disc: Discovery, opts: Options) -> tuple[str, str | None, str]:
    """Returns (category, upstream/downstream/unknown, direction method)."""
    # Explicit endpoint labels always win over weak DNS guesses.
    direction = end_is(p, opts.llm_endpoints)
    if direction:
        return "LLM", direction, "explicit endpoint"
    direction = end_is(p, opts.mcp_endpoints)
    if direction:
        return "MCP-local", direction, "explicit endpoint"

    # TLS SNI is per TCP stream; DNS IP association is a weaker fallback.
    if p.stream and p.stream in disc.stream_sni:
        hosts = [disc.stream_sni[p.stream]]
    else:
        hosts = list(disc.dns_by_ip.get(p.src, set()) | disc.dns_by_ip.get(p.dst, set()))
    is_llm = any(hostname_matches(h, opts.llm_domains) for h in hosts)
    is_web = any(hostname_matches(h, opts.web_domains) for h in hosts)
    is_web = is_web or p.src in opts.web_ips or p.dst in opts.web_ips
    # Generic GAIA / MCPMark support: a third-party TLS hostname is not
    # automatically Other just because it was not api.notion.com.
    if opts.auto_web_sni and not is_llm and not is_web and p.stream in disc.stream_sni:
        is_web = any(h and not hostname_matches(h, opts.agent_domains) for h in hosts)
    category = "LLM" if is_llm else "Web/API" if is_web else "Other"

    # Per-stream known server inferred from first SYN or visible HTTP request.
    server = known_server(p, disc)
    if server:
        if (p.dst, p.dport) == server:
            return category, "up", "SYN/HTTP server"
        if (p.src, p.sport) == server:
            return category, "down", "SYN/HTTP server"

    if category in ("LLM", "Web/API"):
        # In a known remote service TCP flow, endpoint IP is its server.
        # Ambiguous if both IPs are known by captured DNS; don't guess.
        dst_known = (p.dst in opts.web_ips or any(hostname_matches(h, opts.llm_domains + opts.web_domains)
                                                 for h in disc.dns_by_ip.get(p.dst, set())))
        src_known = (p.src in opts.web_ips or any(hostname_matches(h, opts.llm_domains + opts.web_domains)
                                                 for h in disc.dns_by_ip.get(p.src, set())))
        if dst_known and not src_known:
            return category, "up", "DNS IP"
        if src_known and not dst_known:
            return category, "down", "DNS IP"

    # Explicit local-ip lists can resolve private gateway traffic and other flows.
    if p.src in opts.local_ips and p.dst not in opts.local_ips:
        return category, "up", "local IP"
    if p.dst in opts.local_ips and p.src not in opts.local_ips:
        return category, "down", "local IP"

    # Port heuristic is usable for many ordinary client/server flows; never
    # silently attribute packets to a service beyond the classification above.
    if p.sport != p.dport and p.sport and p.dport:
        if p.dport <= 1024 and p.sport > 1024:
            return category, "up", "well-known port"
        if p.sport <= 1024 and p.dport > 1024:
            return category, "down", "well-known port"
        if p.dport < 32768 <= p.sport:
            return category, "up", "port heuristic"
        if p.sport < 32768 <= p.dport:
            return category, "down", "port heuristic"
    return category, None, "unknown"


@dataclass
class Network:
    rates: dict[str, dict[str, np.ndarray]]
    http_llm: list[float]
    http_mcp: list[float]
    byte_totals: Counter
    counts: Counter
    guessed_direction_bytes: int
    missing_direction_bytes: int
    bins: int
    bin_seconds: float


def collect_network(pcap: Path, info: Discovery, opts: Options,
                    t0: float, t1: float, bin_seconds: float, decode_ports: set[int]) -> Network:
    bins = max(1, int(math.ceil((t1 - t0) / bin_seconds)))
    total_bytes: dict[str, dict[str, np.ndarray]] = {
        way: {cat: np.zeros(bins, dtype=np.float64) for cat in CATEGORIES}
        for way in ("up", "down")
    }
    http_llm: list[float] = []
    http_mcp: list[float] = []
    sums = Counter()
    counts = Counter()
    guessed = 0
    unknown = 0
    for fields in tshark_rows(pcap, decode_ports, discovery_only=False):
        p = parse_packet(fields)
        if p is None or not (t0 <= p.ts <= t1):
            continue
        idx = min(bins - 1, int((p.ts - t0) / bin_seconds))
        cat, way, method = classify(p, info, opts)
        counts[(cat, method)] += 1
        if p.http_method:
            if cat == "LLM" and way == "up":
                http_llm.append(p.ts - t0)
            if cat == "MCP-local" and way == "up":
                http_mcp.append(p.ts - t0)
        if way is None:
            unknown += p.length
            sums[(cat, "unknown")] += p.length
            continue
        if method in ("port heuristic", "well-known port", "DNS IP", "local IP"):
            guessed += p.length
        total_bytes[way][cat][idx] += p.length
        sums[(cat, way)] += p.length
    rates = {
        direction: {
            category: values / bin_seconds
            for category, values in by_cat.items()
        } for direction, by_cat in total_bytes.items()
    }
    return Network(rates, http_llm, http_mcp, sums, counts, guessed, unknown, bins, bin_seconds)


def draw_event_panel(ax_event, bars: EventBars, total_duration: float) -> None:
    """Compact, legible tool timeline: paired colored ticks, no duration bars.

    Each completed tool is a hairline with START/END ticks in the same color.
    Calls issued by one LLM response use neighboring mini-lanes; genuinely
    overlapping lifetimes receive a subtle group highlight and a label.
    """
    ax_event.set_title("1. Claude Code events (CLI observations)", loc="left", fontsize=12, pad=8)
    ax_event.set_ylim(1.04, 2.73)
    ax_event.set_yticks([1.49, 2.35], ["Tool execution", "LLM response"])
    ax_event.tick_params(axis="y", length=0, pad=12)
    ax_event.grid(axis="x", alpha=0.13)
    ax_event.set_axisbelow(True)

    # Color-preserving thin blue blocks for LLM response intervals.
    for start, duration in bars.llm_intervals:
        ax_event.broken_barh([(start, max(duration, total_duration * 0.00015))], (2.16, 0.39),
                             facecolors=COLORS["LLM"], edgecolors="none", alpha=0.88)
    if bars.llm_observed:
        ax_event.scatter(bars.llm_observed, [2.35] * len(bars.llm_observed), marker="|",
                         s=90, c=COLORS["LLM"], zorder=6)

    groups = defaultdict(list)
    for start, duration, name, round_idx, slot in bars.tool_intervals:
        groups[round_idx].append((start, start + duration, name, slot))

    # A small, fixed number of micro-lanes; figure height doesn't grow with tool count.
    max_per_round = max((len(calls) for calls in groups.values()), default=1)
    n_lanes = min(5, max(1, max_per_round))
    if n_lanes == 1:
        ys = (1.49,)
    else:
        ys = tuple(np.linspace(1.22, 1.76, n_lanes))

    for round_idx, calls in sorted(groups.items()):
        calls.sort(key=lambda x: x[0])
        # Compute actual maximum observed concurrent tool intervals.
        edges = sorted([(st, 1) for st, en, _, _ in calls] +
                       [(en, -1) for st, en, _, _ in calls],
                       key=lambda item: (item[0], item[1]))
        active = peak = 0
        for _, change in edges:
            active += change
            peak = max(peak, active)
        if peak >= 2:
            left = min(c[0] for c in calls)
            right = max(c[1] for c in calls)
            launch_spread_ms = (max(c[0] for c in calls) - left) * 1000
            # Group box is only a faint background, not an execution bar.
            shade = Rectangle((left - 0.65, 1.10), right - left + 1.30, 0.83,
                              facecolor="#EDF1FF", edgecolor="#D3DCF6",
                              linewidth=0.8, alpha=0.70, zorder=0)
            ax_event.add_patch(shade)
            descriptor = f"{peak} OVERLAPPING  |  {launch_spread_ms:.0f} ms dispatch span"
            ax_event.text((left + right) / 2, 2.025, descriptor,
                          ha="center", va="center", fontsize=8.6, fontweight="bold",
                          color="#3D4979", zorder=10,
                          bbox=dict(facecolor="white", edgecolor="#D5DFF5",
                                    boxstyle="round,pad=0.35", linewidth=0.8, alpha=0.97))

        for st, en, name, slot in calls:
            y = ys[slot % n_lanes]
            color = TOOL_MARKER_COLORS[slot % len(TOOL_MARKER_COLORS)]
            # Hairline ties each start/end pair visually without a filled bar.
            ax_event.plot([st, en], [y, y], color=color, lw=1.65,
                          alpha=0.70, solid_capstyle="round", zorder=4)
            ax_event.vlines(st, y - 0.100, y + 0.100, color=color,
                            lw=3.0, zorder=7, capstyle="round")
            ax_event.vlines(en, y - 0.085, y + 0.085, color=color,
                            lw=2.35, alpha=0.72, zorder=7, capstyle="round")
            if en - st >= 2.8 and slot < n_lanes:
                # Show the actual tool type, including duplicate WebSearch calls.
                shown_name = name.replace("WebSearch", "Search").replace("WebFetch", "Fetch")
                if len(shown_name) > 14:
                    shown_name = shown_name[:13] + "…"
                ax_event.text((st + en) / 2, y + 0.075, shown_name,
                              ha="center", va="bottom", color=color,
                              fontweight="semibold", fontsize=8.2, zorder=8,
                              bbox=dict(facecolor="white", edgecolor="none", alpha=0.83, pad=0.65))

    # Unclosed tool calls: only draw start ticks (do not invent end times).
    completed = {(r, slot) for r, calls in groups.items() for _, _, _, slot in calls}
    for st, name, round_idx, slot in bars.tool_dispatches:
        if (round_idx, slot) not in completed:
            color = TOOL_MARKER_COLORS[slot % len(TOOL_MARKER_COLORS)]
            y = ys[slot % n_lanes]
            ax_event.vlines(st, y - 0.100, y + 0.100, color=color,
                            lw=2.8, zorder=7)

def plot(events: list[dict], t0: float, t1: float, bars: EventBars,
         network: Network, output: Path, rate_scale: str, dpi: int, show_other: bool,
         x_start: float | None = None, x_end: float | None = None) -> None:
    total_duration = t1 - t0
    fig, (ax_event, ax_up, ax_down) = plt.subplots(
        3, 1, sharex=True, figsize=(17, 9.5),
        gridspec_kw={"height_ratios": [2.1, 2.4, 2.4], "hspace": 0.23},
    )
    fig.patch.set_facecolor("white")
    draw_event_panel(ax_event, bars, total_duration)

    # Each direction is a distinct data plane, with the same category colors.
    times = np.arange(network.bins + 1) * network.bin_seconds
    show_cats = [cat for cat in CATEGORIES if (show_other or cat != "Other")
                 and any(np.any(network.rates[way][cat] > 0) for way in ("up", "down"))]
    for ax, way, number, ylab in (
        (ax_up, "up", 2, "Upstream (captured B/s)"),
        (ax_down, "down", 3, "Downstream (captured B/s)"),
    ):
        stacked = [np.r_[network.rates[way][cat], network.rates[way][cat][-1]] for cat in show_cats]
        ax.stackplot(times, *stacked, step="post", colors=[COLORS[cat] for cat in show_cats], alpha=0.88)
        ax.set_ylabel("Upstream" if way == "up" else "Downstream", fontsize=10)
        ax.set_title(f"{number}. Network {'client -> service' if way == 'up' else 'service -> client'}",
                     loc="left", fontsize=12, pad=7)
        ax.grid(axis="both", alpha=0.15)
        ax.set_axisbelow(True)
        if rate_scale == "symlog":
            ax.set_yscale("symlog", linthresh=1024)
        if np.max(np.sum(stacked, axis=0)) == 0:
            ax.set_ylim(0, 1)
            ax.text(0.5, 0.50, "No classified packets in this direction",
                    transform=ax.transAxes, ha="center", va="center", color="gray")

    ax_event.axvline(0, color="black", lw=0.8, alpha=0.55)
    for ax in (ax_up, ax_down):
        ax.axvline(0, color="black", lw=0.8, alpha=0.35)
    ax_down.set_xlim(0 if x_start is None else x_start,
                     max(total_duration, network.bin_seconds) if x_end is None else x_end)
    ax_down.set_xlabel("Time since Claude process start (seconds)", fontsize=11)

    legend = [Line2D([0], [0], color=TOOL_MARKER_COLORS[0], lw=1.65,
                     marker="|", markersize=12, markeredgewidth=2.5,
                     label="Tool: paired start/end ticks")]
    if any(len([c for c in bars.tool_intervals if c[3] == r]) > 1
           for r in {c[3] for c in bars.tool_intervals}):
        legend.append(Patch(facecolor="#EDF1FF", edgecolor="#D3DCF6",
                            label="Overlapping tool group"))
    legend += [Patch(facecolor=COLORS[k], label="MCP" if k == "MCP-local" else k)
               for k in show_cats]
    fig.legend(handles=legend, ncol=3, loc="upper center", bbox_to_anchor=(0.53, 0.955),
               frameon=False, fontsize=9)
    fig.suptitle(f"Agent events and packet-level traffic | {total_duration:.1f} s | "
                 f"{network.bin_seconds * 1000:g} ms bins", fontsize=15, y=0.997)
    start_utc = datetime.fromtimestamp(t0, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
    caption = (f"t=0: {start_utc}; bytes=frame.len incl. headers/retransmissions; "
               "local MCP is separate from WAN. LLM response start != LLM request send. "
               "Tool start/end are CLI observation times.")
    caption += " Tool tick pairs share a color within each round; shaded groups denote overlapping CLI-observed lifetimes (not proof of simultaneous CPU work)."
    fig.text(0.07, 0.012, caption, fontsize=7.3, color="#555555")
    fig.subplots_adjust(top=0.855, bottom=0.095, left=0.12, right=0.98)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=dpi, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def save_binned_csv(path: Path, net: Network, t0: float) -> None:
    """Optional per-bin CSV, useful for Fano/CV/P95 etc. downstream analysis."""
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = [f"{way}_{cat.replace('/', '_').replace('-', '_').lower()}_Bps"
               for way in ("up", "down") for cat in CATEGORIES]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time_from_start_s", "window_start_epoch_s", *columns])
        for i in range(net.bins):
            w.writerow([round(i * net.bin_seconds, 6), f"{t0 + i * net.bin_seconds:.6f}",
                        *[round(float(net.rates[way][cat][i]), 3)
                          for way in ("up", "down") for cat in CATEGORIES]])


def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Align Claude event JSONL and PCAPNG on a common timeline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--task-dir", type=Path, required=True, help="Single task directory or a parent directory containing task subdirectories")
    p.add_argument("--output", type=Path, help="Destination PNG")
    p.add_argument("--bin-ms", type=float, default=1000, help="Network aggregation bin, milliseconds")
    p.add_argument("--llm-endpoint", action="append", type=parse_endpoint, default=[("192.168.3.125", 8317)],
                   metavar="HOST:PORT", help="LLM gateway IP:port; repeat for multiple gateways")
    p.add_argument("--mcp-endpoint", action="append", type=parse_endpoint, default=[],
                   metavar="HOST:PORT", help="Local MCP endpoint(s); default 127.0.0.1:3000")
    p.add_argument("--llm-domain", action="append", default=[], help="LLM service domain to classify via TLS SNI/captured DNS")
    p.add_argument("--web-domain", action="append", default=[], help="Explicit Web/API domains, e.g. repository.tudelft.nl, arxiv.org")
    p.add_argument("--auto-web-sni", action=argparse.BooleanOptionalAction, default=True,
                   help="Classify third-party HTTPS flows with visible SNI as Web/API (excluding agent control domains)")
    p.add_argument("--agent-domain", action="append", default=[],
                   help="Agent background/control domain to keep in Other (can repeat)")
    p.add_argument("--web-ip", action="append", default=[], help="Explicit Web/API service IP, when SNI/DNS is missing")
    p.add_argument("--local-ip", action="append", default=[], help="Local agent IPv4/IPv6 for fallback direction inference")
    p.add_argument("--decode-http-port", action="append", type=int, default=[],
                   help="Ask tshark to decode plaintext HTTP on an additional TCP port")
    p.add_argument("--rate-scale", choices=("linear", "symlog"), default="symlog",
                   help="Scale of network byte-rate axes; symlog increases visibility of small bursts")
    p.add_argument("--hide-other", action="store_true", help="Hide Other from chart (still included in summary)")
    p.add_argument("--export-csv", type=Path, help="Optional binned per-category upstream/downstream rate CSV")
    p.add_argument("--x-start", type=float, default=None, help="Optional zoom: earliest time from Claude process start (seconds)")
    p.add_argument("--x-end", type=float, default=None, help="Optional zoom: latest time from Claude process start (seconds)")
    p.add_argument("--dpi", type=int, default=160, help="PNG resolution")
    return p


def main(argv: list[str] | None = None, _batch_task_dir: Path | None = None) -> int:
    args = create_parser().parse_args(argv)
    task_dir = (args.task_dir if _batch_task_dir is None else _batch_task_dir).expanduser().resolve()
    if _batch_task_dir is None:
        task_dirs = sorted(
            path.parent for path in task_dir.rglob("claude_timeline.jsonl")
            if (path.parent / "raw_traffic.pcapng").is_file()
        )
        if len(task_dirs) > 1 or (task_dirs and task_dirs[0] != task_dir):
            if len(task_dirs) > 1 and (args.output or args.export_csv):
                raise ValueError("--output and --export-csv must be omitted in batch mode "
                                 "to avoid overwriting results from multiple tasks")
            failed = 0
            for index, subdir in enumerate(task_dirs, 1):
                print(f"[BATCH {index}/{len(task_dirs)}] {subdir}", flush=True)
                try:
                    main(argv, _batch_task_dir=subdir)
                except (OSError, RuntimeError, ValueError) as exc:
                    failed += 1
                    print(f"[ERROR] Task {subdir}: {exc}", file=sys.stderr)
            print(f"[BATCH DONE] {len(task_dirs) - failed}/{len(task_dirs)} plots generated")
            return 1 if failed else 0

    event_file = task_dir / "claude_timeline.jsonl"
    pcap = task_dir / "raw_traffic.pcapng"
    if not pcap.is_file():
        raise FileNotFoundError(f"Missing pcap: {pcap}")
    if args.bin_ms <= 0 or not math.isfinite(args.bin_ms):
        raise ValueError("--bin-ms must be positive and finite")
    if not 0 < args.dpi <= 1200:
        raise ValueError("--dpi must be between 1 and 1200")
    if args.x_start is not None and (not math.isfinite(args.x_start) or args.x_start < 0):
        raise ValueError("--x-start must be finite and nonnegative")
    if args.x_end is not None and (not math.isfinite(args.x_end) or args.x_end <= (args.x_start or 0)):
        raise ValueError("--x-end must exceed --x-start")

    events, t0, t1 = read_events(event_file)
    bars = pair_events(events, t0, t1)
    llm_endpoints = set(args.llm_endpoint)
    mcp_endpoints = set(args.mcp_endpoint or [("127.0.0.1", 3000)])
    opts = Options(
        llm_endpoints=llm_endpoints,
        mcp_endpoints=mcp_endpoints,
        llm_domains=[normalize_hostname(s) for s in args.llm_domain],
        web_domains=[normalize_hostname(s) for s in args.web_domain],
        web_ips={s.lower() for s in args.web_ip},
        local_ips={s.lower() for s in args.local_ip} | {"127.0.0.1", "::1"},
        auto_web_sni=args.auto_web_sni,
        agent_domains=[normalize_hostname(s) for s in (
            ["api.anthropic.com", "ab.chatgpt.com", "downloads.claude.ai"] + args.agent_domain
        )],
    )
    decode_ports = {port for _, port in (llm_endpoints | mcp_endpoints)} | set(args.decode_http_port)
    print(f"[1/3] Inspecting packet metadata: {pcap}", flush=True)
    info = discover(pcap, decode_ports)
    print(f"      {len(info.stream_sni)} TLS SNI streams, "
          f"{len(info.dns_by_ip)} resolved IPs, {len(info.stream_direction)} TCP initiators", flush=True)
    print("[2/3] Aligning packet bytes and HTTP requests to Claude events...", flush=True)
    network = collect_network(pcap, info, opts, t0, t1, args.bin_ms / 1000, decode_ports)
    output = (args.output.expanduser().resolve() if args.output else
              task_dir / "agent_traffic_timeline.png")
    print(f"[3/3] Drawing {output}", flush=True)
    plot(events, t0, t1, bars, network, output, args.rate_scale, args.dpi, not args.hide_other, args.x_start, args.x_end)
    if args.export_csv:
        save_binned_csv(args.export_csv.expanduser().resolve(), network, t0)
        print(f"      CSV: {args.export_csv}")

    print(f"      Claude duration: {t1-t0:.2f}s; LLM response intervals: {len(bars.llm_intervals)}; "
          f"tool calls: {len(bars.tool_dispatches)}")
    print(f"      HTTP requests observed in PCAP: LLM={len(network.http_llm)}, MCP={len(network.http_mcp)}")
    for cat in CATEGORIES:
        print(f"      {cat:9s}  up={network.byte_totals[cat,'up']/1024:.1f} KiB, "
              f"down={network.byte_totals[cat,'down']/1024:.1f} KiB")
    if not (network.byte_totals["LLM", "up"] + network.byte_totals["LLM", "down"]):
        print("[WARNING] No LLM packets classified. Pass --llm-endpoint HOST:PORT "
              "and/or --llm-domain NAME for your actual gateway.")
    if network.missing_direction_bytes:
        print(f"[WARNING] {network.missing_direction_bytes/1024:.1f} KiB "
              "omitted because upstream/downstream direction was undetermined; "
              "try --local-ip AGENT_IP.")
    if network.guessed_direction_bytes:
        print(f"[INFO] {network.guessed_direction_bytes/1024:.1f} KiB were direction-inferred "
              "without explicit service endpoint/SYN, using DNS, local IP, or port rules.")
    print(f"[DONE] {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
