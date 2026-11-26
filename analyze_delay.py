#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze latency of Claude Code + MCPMark task captures (local OR remote MCP).

Usage (exactly one positional argument):
    python3 analyze_delay.py /home/claude-MCP/mcpmark/results_claude_mcpmark_notion/notion-gpt6.1sol-m-r/local
    python3 analyze_delay.py /home/claude-MCP/mcpmark/results_claude_mcpmark_notion/notion-gpt6.1sol-m-r/remote

Input directory contains one subdirectory per task, with raw_traffic.pcapng,
claude_timeline.jsonl and optionally result.json. Output: <directory>/analyze_delay.csv
(one row per task, followed by one __TOTAL__ row; pooled percentiles).

Only Python 3.10+ standard library is required; tshark and packet decryption are
not required. Supported captures: pcap, pcapng, Ethernet, Linux cooked SLL/SLL2,
raw IP (IPv4 / IPv6, TCP; DNS over UDP for optional hostname identification).

MEASUREMENT DEFINITIONS -- IMPORTANT FOR COMPARATIVE RESEARCH:
  mcp_tool_rtt_ms:        tool_result_observed - tool_dispatch_observed in
                          Claude's timeline. Includes client/proxy/network,
                          remote MCP processing, and waiting. COMPARABLE across
                          local and remote, but NOT a pure network RTT.
  mcp_tool_queue_ms:      tool_dispatch_observed - tool_use_generated.
  mcp_tool_total_ms:      tool_result_observed - tool_use_generated.
  mcp_tcp_syn_rtt_ms:     packet SYN -> SYN/ACK on the real MCP connection.
                          Only NEW TCP connections; NOT a tool-call RTT.
  mcp_tls_hello_rtt_ms:   TLS ClientHello -> ServerHello on the external TCP
                          connection; NOT a tool-call RTT.
  mcp_http_first_byte_ms: local plaintext POST /mcp -> HTTP response HEADER.
                          Includes client upload/processing; not full SSE body
                          or full MCP tool completion. Blank for encrypted MCP.
  mcp_proxy_connect_ms:  HTTP CONNECT -> 200 on local proxy (e.g. :18081).
                          Loopback PROXY latency; NOT remote MCP network RTT.
  llm_*:                 auxiliary LLM gateway HTTP/SSE observations where
                          unencrypted HTTP/1.1 and SSE markers are visible.

Remote MCP is identified by TLS SNI or unambiguous captured DNS for an external
TCP flow to mcp.notion.com (and other configured hosts). CONNECT requests on
127.0.0.1:18081 are tracked SEPARATELY as proxy traffic to avoid mistaking local
proxy TCP RTT for remote-network TCP RTT. No hard-coded remote MCP IPs.

Percentiles use linear interpolation and are POOLED across samples for TOTAL,
not an average of task percentiles. Blank means unobservable / unavailable,
never a zero-latency measurement. Failures are included in the 'all' tool RTT
and separated in 'success' RTT; check sample counts before interpreting.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import ipaddress
import math
import re
import socket
import statistics
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator


# ---------------------------- Site configuration ---------------------------
# In sync with analyze_traffic.py provided with the experiments.
LLM_PROXIES = {("192.168.3.125", 8317), ("172.17.192.1", 8317)}
LOCAL_MCP_PORTS = {3000}
REMOTE_MCP_HOSTS = {"mcp.notion.com", "api.githubcopilot.com"}
# No hard-coded :18081 is needed; a CONNECT to a known MCP host is recognized.

# Packet fields, output and time computations are pure Python.
HTTP_REQ = re.compile(rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+([^\s]+)\s+HTTP/1\.[01]\r\n")
HTTP_RESP = re.compile(rb"^HTTP/1\.[01]\s+(\d{3})\b")
CONTENT_LENGTH = re.compile(rb"\r\nContent-Length:\s*(\d+)\s*\r\n", re.I)
HTTP_HOST = re.compile(rb"\r\nHost:\s*([^\r\n]+)", re.I)
TOOL_CALL = re.compile(rb'"method"\s*:\s*"tools/call"')
LLM_STOP = (b"event: message_stop", b"data: [DONE]")

STATS_NAMES = (
    "mcp_tool_rtt_ms", "mcp_tool_success_rtt_ms", "mcp_tool_queue_ms",
    "mcp_tool_total_ms", "mcp_tool_dispatch_iat_ms",
    "mcp_http_first_byte_ms", "mcp_http_tool_first_byte_ms",
    "mcp_tcp_syn_rtt_ms", "mcp_tls_hello_rtt_ms",
    "mcp_proxy_connect_ms", "mcp_proxy_tcp_syn_rtt_ms",
    "llm_http_first_byte_ms", "llm_http_after_upload_first_byte_ms",
    "llm_http_upload_ms", "llm_http_stream_ms", "llm_http_round_ms",
    "llm_tcp_syn_rtt_ms",
)
STAT_SUFFIXES = ("count", "mean", "p50", "p90", "p95", "p99", "max")


def ip_private(s: str) -> bool:
    try:
        return not ipaddress.ip_address(s).is_global
    except ValueError:
        return False


def hostname(s: str) -> str:
    s = (s or "").strip().lower().rstrip(".")
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    elif s.count(":") == 1 and s.rsplit(":", 1)[1].isdigit():
        s = s.rsplit(":", 1)[0]
    return s


def event_time(event: dict) -> float | None:
    try:
        if event.get("unix_ns") is not None:
            return int(event["unix_ns"]) / 1_000_000_000
        raw = str(event["timestamp_utc"])
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def duration_between(start: float | None, end: float | None) -> float | None:
    if start is None or end is None or end < start:
        return None
    return (end - start) * 1000


def percentile(sorted_values: list[float], q: float) -> float:
    k = (len(sorted_values) - 1) * q
    lo = int(math.floor(k))
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] * (1 - (k - lo)) + sorted_values[hi] * (k - lo)


@dataclass
class Measurements:
    samples: dict[str, list[float]] = field(
        default_factory=lambda: collections.defaultdict(list))
    counters: collections.Counter = field(default_factory=collections.Counter)
    capture_duration_s: float = 0.0
    claude_duration_s: float = 0.0
    mcp_tool_active_s: float = 0.0
    mcp_tool_sum_s: float = 0.0
    mcp_tool_peak_inflight: int = 0
    mcp_overlap_tool_count: int = 0

    def record(self, name: str, value: float | None) -> None:
        if value is not None and math.isfinite(value) and value >= 0:
            self.samples[name].append(value)

    def merge(self, other: "Measurements") -> None:
        for name, values in other.samples.items():
            self.samples[name].extend(values)
        self.counters.update(other.counters)
        self.capture_duration_s += other.capture_duration_s
        self.claude_duration_s += other.claude_duration_s
        self.mcp_tool_active_s += other.mcp_tool_active_s
        self.mcp_tool_sum_s += other.mcp_tool_sum_s
        self.mcp_tool_peak_inflight = max(self.mcp_tool_peak_inflight,
                                          other.mcp_tool_peak_inflight)
        self.mcp_overlap_tool_count += other.mcp_overlap_tool_count


# --------------------------- Agent timeline -------------------------------
def load_timeline(path: Path, m: Measurements) -> None:
    generated: dict[str, float] = {}
    dispatched: dict[str, float] = {}
    completed: set[str] = set()
    dispatch_ts: list[float] = []
    intervals: list[tuple[float, float]] = []
    for line_number, line in enumerate(path.open(encoding="utf-8-sig"), 1):
        if not line.strip():
            continue
        try:
            import json
            e = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{path.name}:{line_number}: invalid JSONL: {exc}") from exc
        t, kind, uid = event_time(e), e.get("event"), e.get("tool_use_id")
        if t is None:
            continue
        # Other Claude tools (Bash, Read, WebFetch, etc.) are NOT MCP calls.
        # Both local and hosted Notion tools in these experiments use mcp__.
        if kind in ("tool_use_generated", "tool_dispatch_observed",
                    "tool_result_observed") and not str(e.get("tool_name", "")).startswith("mcp__"):
            continue
        if kind == "tool_use_generated" and uid:
            generated.setdefault(str(uid), t)
        elif kind == "tool_dispatch_observed" and uid:
            dispatched.setdefault(str(uid), t)
            dispatch_ts.append(t)
        elif kind == "tool_result_observed" and uid:
            uid = str(uid)
            if uid in completed:
                continue
            completed.add(uid)
            m.counters["mcp_tool_result_count"] += 1
            if e.get("is_error") is True:
                m.counters["mcp_tool_error_count"] += 1
            start = dispatched.get(uid)
            if start is not None:
                elapsed = duration_between(start, t)
                m.record("mcp_tool_rtt_ms", elapsed)
                if not e.get("is_error"):
                    m.record("mcp_tool_success_rtt_ms", elapsed)
                if elapsed is not None:
                    intervals.append((start, t))
            if uid in generated:
                m.record("mcp_tool_total_ms", duration_between(generated[uid], t))
        elif kind == "llm_response_start":
            m.counters["llm_timeline_response_count"] += 1
    m.counters["mcp_tool_generated_count"] += len(generated)
    m.counters["mcp_tool_dispatch_count"] += len(dispatched)
    m.counters["mcp_tool_missing_dispatch_count"] += len(set(generated) - set(dispatched))
    m.counters["mcp_tool_missing_result_count"] += len(set(dispatched) - completed)
    for uid, t in dispatched.items():
        if uid in generated:
            m.record("mcp_tool_queue_ms", duration_between(generated[uid], t))
    for a, b in zip(sorted(dispatch_ts), sorted(dispatch_ts)[1:]):
        m.record("mcp_tool_dispatch_iat_ms", duration_between(a, b))
    if intervals:
        # Exact time-weighted concurrent calls within a task; no assumptions
        # about TCP connection reuse or the MCP server's internal scheduling.
        points = []
        for start, end in intervals:
            points.append((start, 1))
            points.append((end, -1))
        points.sort(key=lambda x: (x[0], x[1]))  # ends before starts on ties
        active = peak = 0
        union = last = 0.0
        first = True
        for t, delta in points:
            if not first and active > 0:
                union += max(0.0, t - last)
            active += delta
            peak = max(peak, active)
            last = t
            first = False
        m.mcp_tool_active_s += union
        m.mcp_tool_sum_s += sum(end - start for start, end in intervals)
        m.mcp_tool_peak_inflight = max(m.mcp_tool_peak_inflight, peak)
        ordered = sorted(intervals)
        overlapping: set[int] = set()
        # O(n^2) in the uncommon worst case; per task usually <=100 calls.
        for i, (start, end) in enumerate(ordered):
            for j in range(i + 1, len(ordered)):
                a, b = ordered[j]
                if a >= end:
                    break
                if min(end, b) > max(start, a):
                    overlapping.add(i)
                    overlapping.add(j)
        m.mcp_overlap_tool_count += len(overlapping)


def load_result(path: Path, m: Measurements) -> tuple[str, str]:
    import json
    if not path.is_file():
        return "", ""
    obj = json.loads(path.read_text(encoding="utf-8-sig"))
    passed = obj.get("verify_passed")
    if passed is True:
        m.counters["verify_passed_tasks"] += 1
    if passed is False:
        m.counters["verify_failed_tasks"] += 1
    start, end = obj.get("claude_started_at"), obj.get("claude_ended_at")
    try:
        if start and end:
            t0 = dt.datetime.fromisoformat(start.replace("Z", "+00:00")).timestamp()
            t1 = dt.datetime.fromisoformat(end.replace("Z", "+00:00")).timestamp()
            if t1 >= t0:
                m.claude_duration_s += t1 - t0
    except (TypeError, ValueError):
        pass
    return str(passed).lower() if passed is not None else "", str(obj.get("claude_tool_call_count", ""))


# ------------------------- PCAP / PCAPNG input -----------------------------
# Generator yields (timestamp_seconds, linktype, captured_frame_bytes,
# original_wire_frame_length). Each interface may use a different clock unit.
def blocks_options(blob: bytes, pos: int, stop: int, order: str):
    while pos + 4 <= stop:
        code, length = struct.unpack_from(order + "HH", blob, pos)
        pos += 4
        if code == 0:
            break
        if pos + length > stop:
            break
        yield code, blob[pos:pos + length]
        pos += (length + 3) & ~3


def iter_frames(path: Path) -> Iterator[tuple[float, int, bytes, int]]:
    with path.open("rb") as f:
        first = f.read(4)
        if first == b"\x0a\x0d\x0d\x0a":
            f.seek(0)
            endian = "<"
            interfaces: list[tuple[int, float, float]] = []
            while True:
                header = f.read(8)
                if not header:
                    return
                if len(header) != 8:
                    raise ValueError("truncated pcapng block header")
                if header[:4] == b"\x0a\x0d\x0d\x0a":
                    bom = f.read(4)
                    if bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"
                    elif bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                    else:
                        raise ValueError("bad pcapng section byte-order magic")
                    length = struct.unpack(endian + "I", header[4:8])[0]
                    if length < 28 or length > 100_000_000:
                        raise ValueError("invalid pcapng section length")
                    rest = bom + f.read(length - 12)
                    if len(rest) != length - 8:
                        raise ValueError("truncated pcapng section")
                    interfaces = []
                    continue
                blocktype, length = struct.unpack(endian + "II", header)
                if length < 12 or length > 100_000_000:
                    raise ValueError(f"invalid pcapng block length: {length}")
                rest = f.read(length - 8)
                if len(rest) != length - 8:
                    raise ValueError("truncated pcapng block")
                if struct.unpack_from(endian + "I", rest, len(rest) - 4)[0] != length:
                    raise ValueError("pcapng block end-length mismatch")
                body = rest[:-4]
                if blocktype == 1 and len(body) >= 8:
                    link_type = struct.unpack_from(endian + "H", body, 0)[0]
                    ts_unit = 1e-6
                    offset = 0.0
                    for code, value in blocks_options(body, 8, len(body), endian):
                        if code == 9 and value:
                            v = value[0]
                            ts_unit = (2.0 ** -(v & 0x7f)) if (v & 0x80) else (10.0 ** -v)
                        elif code == 14 and len(value) == 8:
                            offset = float(struct.unpack(endian + "q", value)[0])
                    interfaces.append((link_type, ts_unit, offset))
                elif blocktype == 6 and len(body) >= 20:
                    interface_id, upper, lower, cap_len, orig_len = struct.unpack_from(endian + "IIIII", body, 0)
                    if interface_id >= len(interfaces) or cap_len > len(body) - 20:
                        continue
                    link_type, unit, offset = interfaces[interface_id]
                    timestamp = ((upper << 32) | lower) * unit + offset
                    yield timestamp, link_type, body[20:20 + cap_len], orig_len
                # Simple packet blocks have no reliable timestamps: skip them.
            return
        f.seek(0)
        header = f.read(24)
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("not a supported .pcap or .pcapng")
        ns_resolution = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        if len(header) < 24:
            raise ValueError("truncated pcap header")
        link_type = struct.unpack_from(endian + "I", header, 20)[0] & 0xffff
        while True:
            h = f.read(16)
            if not h:
                break
            if len(h) != 16:
                raise ValueError("truncated pcap packet header")
            sec, frac, incl, orig = struct.unpack(endian + "IIII", h)
            if incl > 100_000_000:
                raise ValueError("implausible packet length")
            frame = f.read(incl)
            if len(frame) != incl:
                raise ValueError("truncated pcap frame")
            yield sec + frac / (1e9 if ns_resolution else 1e6), link_type, frame, orig


@dataclass
class TCPPacket:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    flags: int
    payload: bytes
    wire_len: int

    @property
    def sender(self) -> tuple[str, int]:
        return self.src, self.sport

    @property
    def recipient(self) -> tuple[str, int]:
        return self.dst, self.dport


def ip_transport(frame: bytes, link_type: int) -> tuple[int, bytes] | None:
    off = 0
    eth = 0
    if link_type == 1:  # Ethernet
        if len(frame) < 14:
            return None
        eth = struct.unpack_from("!H", frame, 12)[0]
        off = 14
        while eth in (0x8100, 0x88a8, 0x9100):
            if len(frame) < off + 4:
                return None
            eth = struct.unpack_from("!H", frame, off + 2)[0]
            off += 4
    elif link_type == 113:  # Linux cooked capture v1, used in example ZIPs
        if len(frame) < 16:
            return None
        eth = struct.unpack_from("!H", frame, 14)[0]
        off = 16
    elif link_type == 276:  # Linux cooked capture v2
        if len(frame) < 20:
            return None
        eth = struct.unpack_from("!H", frame, 0)[0]
        off = 20
    elif link_type == 101:  # raw IPv4 / IPv6
        if not frame:
            return None
        eth = 0x0800 if frame[0] >> 4 == 4 else 0x86dd if frame[0] >> 4 == 6 else 0
    elif link_type in (0, 108):  # loopback / NULL
        if len(frame) < 4:
            return None
        fam = int.from_bytes(frame[:4], "little" if link_type == 0 else "big")
        eth = 0x0800 if fam == socket.AF_INET else 0x86dd if fam in (socket.AF_INET6, 24, 28, 30) else 0
        off = 4
    else:
        return None
    if eth in (0x0800, 0x86dd):
        return eth, frame[off:]
    return None


def decode_transport(frame: bytes, link_type: int, ts: float, wire: int) -> tuple[str, object] | None:
    result = ip_transport(frame, link_type)
    if not result:
        return None
    eth, ipdata = result
    if eth == 0x0800:
        if len(ipdata) < 20 or ipdata[0] >> 4 != 4:
            return None
        ihl = (ipdata[0] & 15) * 4
        if ihl < 20 or len(ipdata) < ihl:
            return None
        # Skip non-first IPv4 fragments; no TCP header on those fragments.
        if struct.unpack_from("!H", ipdata, 6)[0] & 0x1fff:
            return None
        proto = ipdata[9]
        src, dst = socket.inet_ntop(socket.AF_INET, ipdata[12:16]), socket.inet_ntop(socket.AF_INET, ipdata[16:20])
        ipend = min(len(ipdata), struct.unpack_from("!H", ipdata, 2)[0])
        off = ihl
    else:
        if len(ipdata) < 40 or ipdata[0] >> 4 != 6:
            return None
        src, dst = socket.inet_ntop(socket.AF_INET6, ipdata[8:24]), socket.inet_ntop(socket.AF_INET6, ipdata[24:40])
        proto = ipdata[6]
        off = 40
        ipend = min(len(ipdata), 40 + struct.unpack_from("!H", ipdata, 4)[0])
        for _ in range(10):
            if proto in (0, 43, 60):
                if off + 2 > ipend:
                    return None
                next_proto, hdrlen = ipdata[off], (ipdata[off + 1] + 1) * 8
                proto, off = next_proto, off + hdrlen
            elif proto == 44:
                if off + 8 > ipend or (struct.unpack_from("!H", ipdata, off + 2)[0] & 0xfff8):
                    return None
                proto, off = ipdata[off], off + 8
            elif proto == 51:
                if off + 2 > ipend:
                    return None
                next_proto, hdrlen = ipdata[off], (ipdata[off + 1] + 2) * 4
                proto, off = next_proto, off + hdrlen
            else:
                break
    if proto == 6 and off + 20 <= ipend:
        sport, dport, seq = struct.unpack_from("!HHI", ipdata, off)
        header_length = ((ipdata[off + 12] >> 4) & 15) * 4
        if header_length < 20 or off + header_length > ipend:
            return None
        return "tcp", TCPPacket(ts, src, sport, dst, dport, seq, ipdata[off + 13],
                                ipdata[off + header_length:ipend], wire)
    if proto == 17 and off + 8 <= ipend:
        sport, dport, plen = struct.unpack_from("!HHH", ipdata, off)
        return "udp", (src, sport, dst, dport, ipdata[off + 8:min(ipend, off + plen)])
    return None


def dns_name(payload: bytes, pos: int) -> tuple[str, int]:
    labels = []
    origin_pos = None
    visited = set()
    for _ in range(40):
        if pos >= len(payload) or pos in visited:
            raise ValueError("bad DNS label")
        visited.add(pos)
        length = payload[pos]
        if length == 0:
            return hostname(".".join(labels)), (origin_pos if origin_pos is not None else pos + 1)
        if length & 0xc0 == 0xc0:
            if pos + 1 >= len(payload):
                raise ValueError("bad DNS pointer")
            nxt = ((length & 0x3f) << 8) | payload[pos + 1]
            if origin_pos is None:
                origin_pos = pos + 2
            pos = nxt
        elif length & 0xc0:
            raise ValueError("invalid DNS label")
        else:
            pos += 1
            if pos + length > len(payload):
                raise ValueError("truncated DNS label")
            labels.append(payload[pos:pos + length].decode("ascii", "replace"))
            pos += length
    raise ValueError("DNS pointers loop")


def parse_dns_answer(payload: bytes, dns: dict[str, set[str]]) -> None:
    if len(payload) < 12:
        return
    flags, qcount, acount = struct.unpack_from("!HHH", payload, 2)
    if not flags & 0x8000:
        return
    cursor = 12
    questions = []
    try:
        for _ in range(min(qcount, 50)):
            qname, cursor = dns_name(payload, cursor)
            if cursor + 4 > len(payload):
                return
            cursor += 4
            if qname:
                questions.append(qname)
        for _ in range(min(acount, 100)):
            owner, cursor = dns_name(payload, cursor)
            if cursor + 10 > len(payload):
                return
            typ, klass, ttl, rdlen = struct.unpack_from("!HHIH", payload, cursor)
            cursor += 10
            if cursor + rdlen > len(payload):
                return
            if typ in (1, 28) and klass == 1 and rdlen == (4 if typ == 1 else 16):
                address = socket.inet_ntop(socket.AF_INET if typ == 1 else socket.AF_INET6,
                                           payload[cursor:cursor + rdlen])
                dns[address].update(questions if questions else [owner])
            cursor += rdlen
    except (ValueError, OSError, struct.error):
        pass


def tls_sni(payload: bytes) -> str:
    # TLS record with ClientHello; partial record is fine if the SNI extension
    # is already present in the current TCP segment.
    if len(payload) < 45 or payload[0] != 22 or payload[1] != 3 or payload[5] != 1:
        return ""
    pos = 9 + 2 + 32  # TLS record header + handshake header + version + random
    try:
        sid_len = payload[pos]
        pos += 1 + sid_len
        suites = struct.unpack_from("!H", payload, pos)[0]
        pos += 2 + suites
        compression = payload[pos]
        pos += 1 + compression
        ext_len = struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        end = min(len(payload), pos + ext_len)
        while pos + 4 <= end:
            typ, elen = struct.unpack_from("!HH", payload, pos)
            pos += 4
            if typ == 0 and pos + elen <= len(payload):
                # Server Name extension: list length, entry type, name length
                npos = pos + 2
                if npos + 3 <= pos + elen and payload[npos] == 0:
                    n = struct.unpack_from("!H", payload, npos + 1)[0]
                    if npos + 3 + n <= pos + elen:
                        return hostname(payload[npos + 3:npos + 3 + n].decode("ascii", "replace"))
            pos += elen
    except (IndexError, struct.error):
        pass
    return ""


@dataclass
class Request:
    ts: float
    method: str
    uri: str
    upload_done: float | None = None
    remaining: int | None = None
    is_tool: bool = False


@dataclass
class Response:
    ts: float
    code: int


@dataclass
class Flow:
    endpoints: tuple[tuple[str, int], tuple[str, int]]
    client: tuple[str, int] | None = None
    host_sni: str = ""
    proxy_host: str = ""
    requests: list[Request] = field(default_factory=list)
    responses: list[Response] = field(default_factory=list)
    sse_stops: list[float] = field(default_factory=list)
    syn_start: float | None = None
    syn_rtt_ms: float | None = None
    tls_client_hello: float | None = None
    tls_hello_rtt_ms: float | None = None
    packets: int = 0
    bytes: int = 0
    last_server_payload: bytes = b""
    seen_payloads: set[tuple[tuple[str, int], int, int]] = field(default_factory=set)

    def add(self, p: TCPPacket) -> None:
        self.packets += 1
        self.bytes += p.wire_len
        if (p.flags & 0x02) and not (p.flags & 0x10):
            if self.syn_start is None:
                self.syn_start = p.ts
                self.client = p.sender
        if (p.flags & 0x02) and (p.flags & 0x10):
            if self.client is None:
                self.client = p.recipient
            if (p.recipient == self.client and self.syn_start is not None
                    and self.syn_rtt_ms is None):
                self.syn_rtt_ms = duration_between(self.syn_start, p.ts)
        if not p.payload:
            return
        fingerprint = (p.sender, p.seq, len(p.payload))
        if fingerprint in self.seen_payloads:
            return  # local 'any' captures and retransmissions: do not double events
        self.seen_payloads.add(fingerprint)
        match = HTTP_REQ.match(p.payload)
        response = HTTP_RESP.match(p.payload)
        if match:
            self.client = p.sender
            method = match.group(1).decode("ascii")
            uri = match.group(2).decode("ascii", "replace")
            req = Request(ts=p.ts, method=method, uri=uri, is_tool=bool(TOOL_CALL.search(p.payload)))
            if method == "CONNECT":
                self.proxy_host = hostname(uri)
            header_end = p.payload.find(b"\r\n\r\n")
            if header_end >= 0:
                ch = CONTENT_LENGTH.search(p.payload[:header_end + 4])
                expected = int(ch.group(1)) if ch else 0
                present = len(p.payload) - header_end - 4
                req.remaining = max(0, expected - present)
                if req.remaining == 0:
                    req.upload_done = p.ts
            self.requests.append(req)
        elif response:
            self.responses.append(Response(ts=p.ts, code=int(response.group(1))))
        elif self.requests and self.client == p.sender:
            req = self.requests[-1]
            if req.remaining is not None and req.remaining > 0:
                req.remaining = max(0, req.remaining - len(p.payload))
                if req.remaining == 0:
                    req.upload_done = p.ts
            if not req.is_tool and TOOL_CALL.search(p.payload[:512]):
                req.is_tool = True

        if p.payload[0:3] == b"\x16\x03\x01" or p.payload[0:3] == b"\x16\x03\x03":
            if len(p.payload) >= 6 and p.payload[5] == 1:
                self.client = p.sender
                if self.tls_client_hello is None:
                    self.tls_client_hello = p.ts
                name = tls_sni(p.payload)
                if name:
                    self.host_sni = name
            elif (len(p.payload) >= 6 and p.payload[5] == 2
                  and self.tls_client_hello is not None
                  and p.recipient == self.client and self.tls_hello_rtt_ms is None):
                self.tls_hello_rtt_ms = duration_between(self.tls_client_hello, p.ts)

        # TLS SNI fallback for fragmented record decoders: only configured
        # domains, only in packets that begin with TLS handshake, not arbitrary
        # HTTPS application ciphertext.
        if not self.host_sni and p.payload[:2] == b"\x16\x03":
            for domain in REMOTE_MCP_HOSTS:
                if domain.encode("ascii") in p.payload:
                    self.host_sni = domain

        # Observing SSE message_stop requires only the marker, not content.
        if self.client is not None and p.sender != self.client:
            combined = self.last_server_payload + p.payload
            if any(marker in combined for marker in LLM_STOP):
                self.sse_stops.append(p.ts)
            self.last_server_payload = combined[-36:]

    def host(self, dns: dict[str, set[str]]) -> str:
        if self.host_sni:
            return self.host_sni
        external_names = set()
        for address, _port in self.endpoints:
            if not ip_private(address):
                external_names.update(dns.get(address, set()))
        return next(iter(external_names)) if len(external_names) == 1 else ""


def flow_type(f: Flow, dns: dict[str, set[str]]) -> str:
    endpoints = set(f.endpoints)
    if LLM_PROXIES & endpoints:
        return "llm"
    # A CONNECT to mcp.notion.com:443 on 127.0.0.1 is NOT a WAN RTT.
    if f.proxy_host in REMOTE_MCP_HOSTS and all(ip_private(ip) for ip, _ in endpoints):
        return "mcp_proxy"
    if any(port in LOCAL_MCP_PORTS for _, port in endpoints) and all(
            ip_private(ip) for ip, _ in endpoints):
        return "mcp"
    if f.host(dns) in REMOTE_MCP_HOSTS:
        return "mcp"  # SNI or unambiguous DNS; real external path
    return "other"


def matched_http(f: Flow) -> Iterator[tuple[Request, Response, float | None]]:
    """HTTP/1.1 sequential request/response pairing; no encrypted HTTP2 guesses."""
    r = 0
    stops = sorted(f.sse_stops)
    for idx, request in enumerate(f.requests):
        while r < len(f.responses) and f.responses[r].ts < request.ts:
            r += 1
        if r >= len(f.responses):
            break
        response = f.responses[r]
        # A new request before this response means HTTP pipelining/ambiguous;
        # do not invent a request/response pair in that case.
        if idx + 1 < len(f.requests) and f.requests[idx + 1].ts < response.ts:
            continue
        r += 1
        cutoff = (f.requests[idx + 1].ts if idx + 1 < len(f.requests) else float("inf"))
        stop = next((t for t in stops if response.ts <= t < cutoff), None)
        yield request, response, stop


def inspect_capture(pcap: Path, m: Measurements) -> None:
    flows: dict[tuple[tuple[str, int], tuple[str, int]], Flow] = {}
    dns: dict[str, set[str]] = collections.defaultdict(set)
    first_ts = last_ts = None
    observed_frames = 0
    for ts, lt, frame, wire in iter_frames(pcap):
        if not math.isfinite(ts):
            continue
        observed_frames += 1
        first_ts = ts if first_ts is None else min(first_ts, ts)
        last_ts = ts if last_ts is None else max(last_ts, ts)
        packet = decode_transport(frame, lt, ts, wire)
        if packet is None:
            continue
        proto, obj = packet
        if proto == "udp":
            src, sport, dst, dport, payload = obj
            if sport == 53:
                parse_dns_answer(payload, dns)
        elif proto == "tcp":
            p: TCPPacket = obj
            endpoints = tuple(sorted((p.sender, p.recipient)))
            flow = flows.get(endpoints)
            if flow is None:
                flow = Flow(endpoints)
                flows[endpoints] = flow
            flow.add(p)
    m.counters["pcap_files"] += 1
    m.counters["captured_frames"] += observed_frames
    if first_ts is not None and last_ts is not None:
        m.capture_duration_s += max(0.0, last_ts - first_ts)
    for f in flows.values():
        kind = flow_type(f, dns)
        if kind == "other":
            continue
        m.counters[f"{kind}_tcp_flows"] += 1
        m.counters[f"{kind}_tcp_packets"] += f.packets
        m.counters[f"{kind}_tcp_bytes"] += f.bytes
        if f.syn_start is not None:
            m.counters[f"{kind}_tcp_syn_count"] += 1
        if kind == "mcp":
            m.record("mcp_tcp_syn_rtt_ms", f.syn_rtt_ms)
            m.record("mcp_tls_hello_rtt_ms", f.tls_hello_rtt_ms)
            if f.host_sni in REMOTE_MCP_HOSTS:
                m.counters["mcp_remote_sni_flows"] += 1
            elif f.host(dns) in REMOTE_MCP_HOSTS:
                m.counters["mcp_remote_dns_flows"] += 1
        elif kind == "mcp_proxy":
            m.record("mcp_proxy_tcp_syn_rtt_ms", f.syn_rtt_ms)
        elif kind == "llm":
            m.record("llm_tcp_syn_rtt_ms", f.syn_rtt_ms)

        for request, response, stop in matched_http(f):
            first_byte = duration_between(request.ts, response.ts)
            if kind == "mcp" and request.method == "POST" and request.uri.startswith("/mcp"):
                m.counters["mcp_http_post_count"] += 1
                if response.code >= 400:
                    m.counters["mcp_http_error_response_count"] += 1
                m.record("mcp_http_first_byte_ms", first_byte)
                if request.is_tool:
                    m.counters["mcp_http_identified_tool_call_count"] += 1
                    m.record("mcp_http_tool_first_byte_ms", first_byte)
            elif kind == "mcp_proxy" and request.method == "CONNECT":
                m.counters["mcp_proxy_connect_count"] += 1
                if response.code == 200:
                    m.record("mcp_proxy_connect_ms", first_byte)
            elif kind == "llm" and request.method == "POST":
                m.counters["llm_http_post_count"] += 1
                if response.code >= 400:
                    m.counters["llm_http_error_response_count"] += 1
                m.record("llm_http_first_byte_ms", first_byte)
                m.record("llm_http_upload_ms", duration_between(request.ts, request.upload_done))
                m.record("llm_http_after_upload_first_byte_ms",
                         duration_between(request.upload_done, response.ts))
                if stop is not None:
                    m.record("llm_http_stream_ms", duration_between(response.ts, stop))
                    m.record("llm_http_round_ms", duration_between(request.ts, stop))


# --------------------------- Directory + output ---------------------------
def list_pcaps(task_dir: Path) -> list[Path]:
    # Same rule as analyze_traffic.py: one directory = one task; do not recurse.
    files = sorted(p for p in task_dir.iterdir() if p.is_file() and
                   p.suffix.lower() in (".pcap", ".pcapng"))
    for name in ("raw_traffic.pcapng", "raw_traffic.pcap"):
        for f in files:
            if f.name.lower() == name:
                return [f]  # never count derived PCAPs twice
    return files


def row_dict(task: str, deployment: str, status: str, m: Measurements,
             verification: str = "", expected_tools: str = "",
             total_row: bool = False) -> dict:
    c = m.counters
    out = {
        "task": task,
        "deployment": deployment,
        "status": status,
        "verify_passed": "" if total_row else verification,
        "result_tool_calls": "" if total_row else expected_tools,
        "task_count": c["task_count"],
        "verify_passed_tasks": c["verify_passed_tasks"],
        "pcap_files": c["pcap_files"],
        "capture_duration_s": round(m.capture_duration_s, 3) if m.capture_duration_s else "",
        "claude_duration_s": round(m.claude_duration_s, 3) if m.claude_duration_s else "",
        "mcp_tool_generated_count": c["mcp_tool_generated_count"],
        "mcp_tool_dispatch_count": c["mcp_tool_dispatch_count"],
        "mcp_tool_result_count": c["mcp_tool_result_count"],
        "mcp_tool_error_count": c["mcp_tool_error_count"],
        "mcp_tool_missing_dispatch_count": c["mcp_tool_missing_dispatch_count"],
        "mcp_tool_missing_result_count": c["mcp_tool_missing_result_count"],
        "mcp_tool_active_s": round(m.mcp_tool_active_s, 3),
        "mcp_tool_sum_s": round(m.mcp_tool_sum_s, 3),
        "mcp_tool_peak_inflight": m.mcp_tool_peak_inflight,
        "mcp_tool_avg_inflight_while_active": (round(m.mcp_tool_sum_s / m.mcp_tool_active_s, 3)
                                                 if m.mcp_tool_active_s > 0 else ""),
        "mcp_overlapping_tool_fraction_pct": (round(100 * m.mcp_overlap_tool_count /
                                                     len(m.samples["mcp_tool_rtt_ms"]), 2)
                                               if m.samples["mcp_tool_rtt_ms"] else ""),
        "mcp_active_pct_of_claude_duration": (round(100 * m.mcp_tool_active_s / m.claude_duration_s, 2)
                                               if m.claude_duration_s else ""),
        "mcp_tcp_flows": c["mcp_tcp_flows"],
        "mcp_tcp_packets": c["mcp_tcp_packets"],
        "mcp_tcp_bytes": c["mcp_tcp_bytes"],
        "mcp_tcp_syn_count": c["mcp_tcp_syn_count"],
        "mcp_remote_sni_flows": c["mcp_remote_sni_flows"],
        "mcp_remote_dns_flows": c["mcp_remote_dns_flows"],
        "mcp_http_post_count": c["mcp_http_post_count"],
        "mcp_http_identified_tool_call_count": c["mcp_http_identified_tool_call_count"],
        "mcp_http_error_response_count": c["mcp_http_error_response_count"],
        "mcp_proxy_tcp_flows": c["mcp_proxy_tcp_flows"],
        "mcp_proxy_tcp_packets": c["mcp_proxy_tcp_packets"],
        "mcp_proxy_tcp_bytes": c["mcp_proxy_tcp_bytes"],
        "mcp_proxy_connect_count": c["mcp_proxy_connect_count"],
        "llm_tcp_flows": c["llm_tcp_flows"],
        "llm_timeline_response_count": c["llm_timeline_response_count"],
        "llm_http_post_count": c["llm_http_post_count"],
        "llm_http_error_response_count": c["llm_http_error_response_count"],
    }
    for metric in STATS_NAMES:
        values = sorted(m.samples[metric])
        out[metric + "_count"] = len(values)
        if not values:
            for suffix in STAT_SUFFIXES[1:]:
                out[metric + "_" + suffix] = ""
        else:
            out[metric + "_mean"] = round(statistics.fmean(values), 3)
            for suffix, q in (("p50", .50), ("p90", .90), ("p95", .95), ("p99", .99)):
                out[metric + "_" + suffix] = round(percentile(values, q), 3)
            out[metric + "_max"] = round(values[-1], 3)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Claude/MCP local or hosted timing; output one analyze_delay.csv")
    parser.add_argument("directory", type=Path, help="Directory with one subfolder per MCPMark task")
    args = parser.parse_args()
    top = args.directory.expanduser().resolve()
    if not top.is_dir():
        parser.error(f"Not a directory: {top}")
    tasks = sorted(p for p in top.iterdir() if p.is_dir())
    if not tasks:
        parser.error(f"No per-task subdirectories in: {top}")
    deployment = top.name.lower() if top.name.lower() in ("local", "remote") else "unspecified"
    rows: list[dict] = []
    total = Measurements()
    problem_tasks = 0
    for index, task_dir in enumerate(tasks, 1):
        print(f"[{index}/{len(tasks)}] {task_dir.name}", flush=True)
        m = Measurements()
        m.counters["task_count"] = 1
        status = []
        verified = tool_calls = ""
        result = task_dir / "result.json"
        try:
            verified, tool_calls = load_result(result, m)
        except Exception as exc:
            status.append("RESULT_ERROR")
            print(f"  [WARN] result.json: {exc}", file=sys.stderr)
        timeline = task_dir / "claude_timeline.jsonl"
        if timeline.is_file():
            try:
                load_timeline(timeline, m)
            except Exception as exc:
                status.append("TIMELINE_ERROR")
                print(f"  [WARN] claude_timeline.jsonl: {exc}", file=sys.stderr)
        else:
            status.append("NO_TIMELINE")
        pcaps = list_pcaps(task_dir)
        if pcaps:
            for pcap in pcaps:
                try:
                    # If malformed, keep valid timeline samples and report it.
                    partial = Measurements()
                    inspect_capture(pcap, partial)
                    m.merge(partial)
                except Exception as exc:
                    status.append("PCAP_ERROR")
                    print(f"  [WARN] {pcap.name}: {exc}", file=sys.stderr)
        else:
            status.append("NO_PCAP")
        if status:
            problem_tasks += 1
        total.merge(m)
        rows.append(row_dict(task_dir.name, deployment,
                             "OK" if not status else "+".join(sorted(set(status))),
                             m, verified, tool_calls))
    rows.append(row_dict("__TOTAL__", deployment, "OK" if not problem_tasks else "PARTIAL",
                         total, total_row=True))
    output = top / "analyze_delay.csv"
    with output.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    r = rows[-1]
    print(f"\nCSV saved: {output}")
    print(f"Tasks: {len(tasks)}, issues: {problem_tasks}, MCP tools with RTT: {r['mcp_tool_rtt_ms_count']}")
    print(f"MCP tool latency (logs): mean={r['mcp_tool_rtt_ms_mean']} ms, "
          f"p50={r['mcp_tool_rtt_ms_p50']} ms, p90={r['mcp_tool_rtt_ms_p90']} ms")
    print(f"MCP real TCP flows: {r['mcp_tcp_flows']}; "
          f"network SYN RTT samples: {r['mcp_tcp_syn_rtt_ms_count']}; "
          f"local proxy flows (separate): {r['mcp_proxy_tcp_flows']}")
    print("Note: log MCP tool RTT includes server work; TCP SYN RTT is transport-only, "
          "and HTTPS tool HTTP timing is not decryptable.")
    return 0 if problem_tasks == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
