#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCPMark / Claude Code: packet-capture traffic composition analysis.

Usage (the only argument is the top-level results directory)::

    python3 analyze_traffic.py /home/claude-MCP/mcpmark/results_claude_mcpmark_notion

Expected layout::

    results_claude_mcpmark_notion/
        task_A/raw_traffic.pcapng
        task_A/result.json                 # ignored; optional
        task_B/raw_traffic.pcapng
        ...

Exactly one output file is written:
    <input directory>/analyze_traffic.csv

Requirements: Python >= 3.10; `tshark` installed (sudo apt install tshark).
No third-party Python packages are required.

Category rules (the first applicable rule wins):
    LLM        exact endpoints 192.168.3.125:8317 or 172.17.192.1:8317, either direction
    MCP        local TCP/UDP connection on port 3000, or official remote MCP hostname
    WEB        known local web application port, or external web domain observed
               via TLS SNI / HTTP Host / HTTP2 authority / unambiguous captured DNS
    DB         local PostgreSQL connection on port 5432 (excluded from analysis)
    AUXILIARY  *.anthropic.com, *.claude.ai, *.claude.com, plus known auxiliary sites
    OTHER      other traffic, including unknown-origin encrypted external flows

Loopback filter: after preserving LLM, MCP and WEB flows, discard all
other 127.0.0.0/8 <-> 127.0.0.0/8 and ::1 <-> ::1 conversations; also
exclude same-IP local/private-host self-connections on unknown ports.
Local PostgreSQL DB flows on port 5432 are excluded from analysis.
Do NOT drop local MCP traffic merely because its endpoints are loopback.

IMPORTANT: these numbers are PCAP captured FRAME bytes (frame.len), not TCP
payload or unique application data. Packet re-transmissions / local-capture
duplicates, if present, count as observed bytes. Network-encrypted traffic
without an identifiable hostname is kept as OTHER, not silently labeled WEB.
Percentages use the retained (raw minus filtered local) captured bytes.

Adjust LOCAL_MCP_PORTS etc. below if YOUR deployment uses different ports.
"""

from __future__ import annotations

import argparse
import collections
import csv
import ipaddress
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ----------------------- Environment-specific configuration ------------------
LLM_PROXIES = {
    ("192.168.3.125", 8317),  # existing LLM gateway
    ("172.17.192.1", 8317),  # WSL LLM gateway
}
LOCAL_MCP_PORTS = {3000}
REMOTE_MCP_HOSTS = {
    "api.githubcopilot.com",  # GitHub official hosted MCP
    "mcp.notion.com",         # Notion official hosted MCP
}
LOCAL_WEB_PORTS = {7770, 7780, 9999}  # WebArena local application ports
LOCAL_DB_PORTS = {5432}               # PostgreSQL (excluded from analysis)

# These are auxiliary, even when they use HTTPS on port 443.
ANTHROPIC_SUFFIXES = ("anthropic.com", "claude.ai", "claude.com")
ADDITIONAL_AUXILIARY_SUFFIXES = (
    "registry.npmjs.org", "nodejs.org", "pypi.org", "pythonhosted.org",
    "mtalk.google.com", "android.clients.google.com", "a.nel.cloudflare.com",
)

CATEGORIES = ("llm", "mcp", "web", "auxiliary", "other")

CORE_FIELDS = (
    "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ipv6.src",
    "ipv6.dst", "tcp.stream", "tcp.srcport", "tcp.dstport",
    "udp.stream", "udp.srcport", "udp.dstport",
)
OPTIONAL_FIELDS = (
    "tls.handshake.extensions_server_name", "http.host",
    "http2.headers.authority", "dns.qry.name", "dns.a", "dns.aaaa",
)


def first_field(value: str) -> str:
    """Select the first value when tshark reports multiple protocol layers."""
    return (value or "").split(",", 1)[0].strip()


def norm_host(value: str) -> str:
    host = (value or "").strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    return host


def belongs_to(host: str, suffixes: tuple[str, ...]) -> bool:
    host = norm_host(host)
    return any(host == suffix or host.endswith("." + suffix)
               for suffix in suffixes)


def ip_obj(raw: str):
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def loopback_connection(endpoints: set[tuple[str, int]]) -> bool:
    ips = [ip_obj(ip) for ip, _ in endpoints]
    return bool(ips) and all(ip is not None and ip.is_loopback for ip in ips)


def local_self_connection(endpoints: set[tuple[str, int]]) -> bool:
    """Same non-public IP at both ends: also a local host-process connection."""
    ips = {ip for ip, _ in endpoints}
    if len(ips) != 1:
        return False
    address = ip_obj(next(iter(ips)))
    return address is not None and (address.is_private or address.is_loopback)


def port_in(endpoints: set[tuple[str, int]], ports: set[int]) -> bool:
    return any(port in ports for _, port in endpoints)


def has_proxy(endpoints: set[tuple[str, int]]) -> bool:
    return bool(LLM_PROXIES.intersection(endpoints))


def locally_addressed(endpoints: set[tuple[str, int]]) -> bool:
    """Conservatively require non-global addresses at both ends for local ports."""
    addresses = [ip_obj(ip) for ip, _ in endpoints]
    return bool(addresses) and all(a is not None and not a.is_global
                                   for a in addresses)


@dataclass
class Flow:
    key: str
    endpoints: set[tuple[str, int]] = field(default_factory=set)
    observed_hosts: collections.Counter = field(default_factory=collections.Counter)
    nbytes: int = 0
    npackets: int = 0

    def add(self, src: str, sport: int, dst: str, dport: int,
            length: int, hosts: list[str]) -> None:
        self.endpoints.add((src, sport))
        self.endpoints.add((dst, dport))
        self.nbytes += length
        self.npackets += 1
        for host in hosts:
            host = norm_host(host)
            if host:
                self.observed_hosts[host] += 1

    def hostname(self, dns_answers: dict[str, set[str]]) -> str:
        # Captured SNI and HTTP authority are stronger than inferred DNS names.
        if self.observed_hosts:
            return self.observed_hosts.most_common(1)[0][0]
        matches: set[str] = set()
        for remote_ip, _ in self.endpoints:
            ip = ip_obj(remote_ip)
            if ip is not None and ip.is_global:
                matches.update(dns_answers.get(remote_ip, set()))
        # Do not guess from shared CDN IP addresses resolving to several hosts.
        if len(matches) == 1:
            return next(iter(matches))
        return ""


def classify_flow(flow: Flow, dns_answers: dict[str, set[str]]) -> tuple[str, bool, str]:
    """Return (category, is_filtered, matched_subtype)."""
    ep = flow.endpoints
    # Classify fixed service endpoints BEFORE dropping loopback connections.
    if has_proxy(ep):
        return "llm", False, ""
    if locally_addressed(ep) and port_in(ep, LOCAL_MCP_PORTS):
        return "mcp", False, ""
    if locally_addressed(ep) and port_in(ep, LOCAL_WEB_PORTS):
        return "web", False, "local_web"
    if locally_addressed(ep) and port_in(ep, LOCAL_DB_PORTS):
        return "", True, "filtered_local"

    # Drop ONLY irrelevant local self/loopback communications, not the entire
    # RFC1918/private space: LAN tool traffic may still be meaningful.
    if loopback_connection(ep) or local_self_connection(ep):
        return "", True, "filtered_local"

    host = flow.hostname(dns_answers)
    if host in REMOTE_MCP_HOSTS:
        return "mcp", False, ""
    if host and belongs_to(host, ANTHROPIC_SUFFIXES):
        return "auxiliary", False, "anthropic"
    if host and belongs_to(host, ADDITIONAL_AUXILIARY_SUFFIXES):
        return "auxiliary", False, "additional_auxiliary"
    if host:
        return "web", False, "external_web"
    return "other", False, "unknown_host"


def capture_fields() -> list[str]:
    exe = shutil.which("tshark")
    if not exe:
        raise RuntimeError("Cannot find tshark. On Ubuntu/WSL: sudo apt install tshark")
    proc = subprocess.run([exe, "-G", "fields"], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError("tshark -G fields failed: " + proc.stderr[-500:])
    available = set()
    for line in proc.stdout.splitlines():
        if line.startswith("F\t"):
            parts = line.split("\t")
            if len(parts) > 2:
                available.add(parts[2])
    missing = set(CORE_FIELDS) - available
    if missing:
        raise RuntimeError("tshark lacks required fields: " + ", ".join(sorted(missing)))
    optional = [f for f in OPTIONAL_FIELDS if f in available]
    if len(optional) < len(OPTIONAL_FIELDS):
        print("[WARN] Unsupported optional fields: " + ", ".join(
            f for f in OPTIONAL_FIELDS if f not in available), file=sys.stderr)
    return list(CORE_FIELDS) + optional


def read_packets(pcap: Path, fields: list[str]) -> Iterator[dict[str, str]]:
    # Multi-occurrence DNS fields are aggregated using commas; src/dst use
    # first_field() to select the outer IP address when multiple layers exist.
    cmd = ["tshark", "-n", "-r", str(pcap), "-T", "fields", "-E", "header=n",
           "-E", "quote=n", "-E", "occurrence=a", "-E", "aggregator=,"]
    for name in fields:
        cmd.extend(("-e", name))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace", bufsize=1)
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            values = line.rstrip("\r\n").split("\t")
            if len(values) < len(fields):
                values.extend([""] * (len(fields) - len(values)))
            yield dict(zip(fields, values))
    finally:
        proc.stdout.close()
    assert proc.stderr is not None
    stderr = proc.stderr.read()
    returncode = proc.wait()
    if returncode:
        raise RuntimeError(f"tshark exited with {returncode}: {stderr[-500:]}")


def safe_int(text: str) -> int:
    try:
        return int(first_field(text))
    except (TypeError, ValueError):
        return 0


def safe_float(text: str) -> float | None:
    try:
        return float(first_field(text))
    except (TypeError, ValueError):
        return None


def flow_key(pkt: dict[str, str], src: str, sport: int,
             dst: str, dport: int) -> str:
    tcp_stream = first_field(pkt.get("tcp.stream", ""))
    udp_stream = first_field(pkt.get("udp.stream", ""))
    if tcp_stream:
        return "tcp:" + tcp_stream
    if udp_stream:
        return "udp:" + udp_stream
    # For non-TCP/UDP traffic, a best-effort directionless conversation key.
    proto = "tcp" if pkt.get("tcp.srcport") else (
        "udp" if pkt.get("udp.srcport") else "ip")
    pair = sorted(((src, sport), (dst, dport)))
    return f"{proto}:{pair[0]}:{pair[1]}"


def update_dns(pkt: dict[str, str], dns: dict[str, set[str]]) -> None:
    queries = [norm_host(q) for q in pkt.get("dns.qry.name", "").split(",")]
    queries = [q for q in queries if q]
    # DNS answers can be multiple A/AAAA records. Only unambiguous answers are
    # subsequently attributed to hosts; ambiguous shared CDN IPs stay OTHER.
    for name in ("dns.a", "dns.aaaa"):
        for result_ip in pkt.get(name, "").split(","):
            result_ip = result_ip.strip()
            if result_ip and ip_obj(result_ip) is not None:
                dns.setdefault(result_ip, set()).update(queries)


@dataclass
class CaptureStats:
    raw_bytes: int = 0
    raw_packets: int = 0
    filtered_bytes: int = 0
    filtered_packets: int = 0
    byte_counts: collections.Counter = field(default_factory=collections.Counter)
    packet_counts: collections.Counter = field(default_factory=collections.Counter)
    anthropic_bytes: int = 0
    local_web_bytes: int = 0
    unknown_host_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    pcap_files: int = 0

    def add_packet(self, nbytes: int, timestamp: float | None) -> None:
        self.raw_bytes += nbytes
        self.raw_packets += 1
        if timestamp is not None:
            self.first_ts = min(self.first_ts, timestamp) if self.first_ts is not None else timestamp
            self.last_ts = max(self.last_ts, timestamp) if self.last_ts is not None else timestamp

    def add_flow(self, category: str, filtered: bool, detail: str,
                 nbytes: int, npackets: int) -> None:
        if filtered:
            self.filtered_bytes += nbytes
            self.filtered_packets += npackets
            return
        self.byte_counts[category] += nbytes
        self.packet_counts[category] += npackets
        if detail == "anthropic":
            self.anthropic_bytes += nbytes
        if detail == "local_web":
            self.local_web_bytes += nbytes
        if detail == "unknown_host":
            self.unknown_host_bytes += nbytes

    def add(self, other: CaptureStats) -> None:
        self.raw_bytes += other.raw_bytes
        self.raw_packets += other.raw_packets
        self.filtered_bytes += other.filtered_bytes
        self.filtered_packets += other.filtered_packets
        self.byte_counts.update(other.byte_counts)
        self.packet_counts.update(other.packet_counts)
        self.anthropic_bytes += other.anthropic_bytes
        self.local_web_bytes += other.local_web_bytes
        self.unknown_host_bytes += other.unknown_host_bytes
        self.pcap_files += other.pcap_files
        if other.first_ts is not None:
            self.first_ts = min(self.first_ts, other.first_ts) if self.first_ts is not None else other.first_ts
        if other.last_ts is not None:
            self.last_ts = max(self.last_ts, other.last_ts) if self.last_ts is not None else other.last_ts

    @property
    def analyzed_bytes(self) -> int:
        return self.raw_bytes - self.filtered_bytes

    def validate(self) -> None:
        if sum(self.byte_counts.values()) != self.analyzed_bytes:
            raise RuntimeError("Internal error: category bytes do not equal retained bytes")
        if sum(self.packet_counts.values()) + self.filtered_packets != self.raw_packets:
            raise RuntimeError("Internal error: packet counts do not reconcile")


def inspect_capture(pcap: Path, fields: list[str]) -> CaptureStats:
    stats = CaptureStats(pcap_files=1)
    flows: dict[str, Flow] = {}
    dns: dict[str, set[str]] = {}
    # Non-IP packets are retained in OTHER (e.g., ARP), not silently lost.
    non_ip_bytes = 0
    non_ip_packets = 0
    for pkt in read_packets(pcap, fields):
        length = safe_int(pkt.get("frame.len", ""))
        if length < 0:
            continue
        stats.add_packet(length, safe_float(pkt.get("frame.time_epoch", "")))
        update_dns(pkt, dns)
        src = first_field(pkt.get("ip.src") or pkt.get("ipv6.src", ""))
        dst = first_field(pkt.get("ip.dst") or pkt.get("ipv6.dst", ""))
        if not src or not dst:
            non_ip_bytes += length
            non_ip_packets += 1
            continue
        sp = safe_int(pkt.get("tcp.srcport") or pkt.get("udp.srcport", ""))
        dp = safe_int(pkt.get("tcp.dstport") or pkt.get("udp.dstport", ""))
        key = flow_key(pkt, src, sp, dst, dp)
        if key not in flows:
            flows[key] = Flow(key=key)
        observed: list[str] = []
        for name in ("tls.handshake.extensions_server_name", "http.host",
                     "http2.headers.authority"):
            observed.extend(pkt.get(name, "").split(","))
        flows[key].add(src, sp, dst, dp, length, observed)

    for flow in flows.values():
        category, filtered, detail = classify_flow(flow, dns)
        stats.add_flow(category, filtered, detail, flow.nbytes, flow.npackets)
    stats.add_flow("other", False, "no_ip", non_ip_bytes, non_ip_packets)
    stats.validate()
    return stats


def list_pcaps(task_dir: Path) -> list[Path]:
    # Do NOT recurse: each second-level directory represents exactly one task.
    found = sorted(p for p in task_dir.iterdir()
                   if p.is_file() and p.suffix.lower() in (".pcap", ".pcapng"))
    # Prioritize the original capture; avoid double counting derived/subset
    # captures that happen to coexist in the same task directory.
    for canonical in ("raw_traffic.pcapng", "raw_traffic.pcap"):
        for path in found:
            if path.name.lower() == canonical:
                return [path]
    return found


def environment_name(top_directory: Path) -> str:
    name = top_directory.name.lower()
    for token, label in (("playwright_webarena", "playwright_webarena"),
                         ("webarena", "playwright_webarena"),
                         ("filesystem", "filesystem"),
                         ("postgres", "postgres"),
                         ("github", "github"),
                         ("notion", "notion"),
                         ("playwright", "playwright")):
        if token in name:
            return label
    return "unspecified"


def mib_decimal(nbytes: int) -> float:
    # 'MB' below means decimal megabytes, matching the slides' presentation.
    return round(nbytes / 1_000_000, 6)


def percent(numerator: int, denominator: int) -> float:
    return round(100 * numerator / denominator, 4) if denominator else 0.0


def summary_row(task: str, env: str, stats: CaptureStats, status: str,
                show_duration: bool = True) -> dict:
    stats.validate()
    analyzed = stats.analyzed_bytes
    result = {
        "task": task,
        "environment": env,
        "status": status,
        "pcap_files": stats.pcap_files,
        "capture_duration_s": (round(stats.last_ts - stats.first_ts, 3)
                               if show_duration and stats.first_ts is not None and stats.last_ts is not None else ""),
        "raw_bytes": stats.raw_bytes,
        "raw_MB": mib_decimal(stats.raw_bytes),
        "filtered_local_bytes": stats.filtered_bytes,
        "filtered_local_MB": mib_decimal(stats.filtered_bytes),
        "filtered_local_pct_of_raw": percent(stats.filtered_bytes, stats.raw_bytes),
        "analyzed_bytes": analyzed,
        "analyzed_MB": mib_decimal(analyzed),
    }
    for category in CATEGORIES:
        count = stats.byte_counts[category]
        result[f"{category}_bytes"] = count
        result[f"{category}_MB"] = mib_decimal(count)
        result[f"{category}_pct"] = percent(count, analyzed)
    result.update({
        "anthropic_auxiliary_MB": mib_decimal(stats.anthropic_bytes),
        "local_web_MB": mib_decimal(stats.local_web_bytes),
        "unknown_host_other_MB": mib_decimal(stats.unknown_host_bytes),
        "raw_packets": stats.raw_packets,
        "filtered_local_packets": stats.filtered_packets,
        "analyzed_packets": stats.raw_packets - stats.filtered_packets,
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze MCPMark PCAP traffic composition; write one analyze_traffic.csv")
    parser.add_argument("directory", type=Path, help="Top-level directory containing task subdirectories")
    args = parser.parse_args()
    top = args.directory.expanduser().resolve()
    if not top.is_dir():
        parser.error(f"Not a directory: {top}")
    task_dirs = sorted(p for p in top.iterdir() if p.is_dir())
    if not task_dirs:
        parser.error(f"No second-level task folders in: {top}")
    try:
        fields = capture_fields()
    except Exception as exc:
        parser.exit(1, f"ERROR: {exc}\n")

    env = environment_name(top)
    output = top / "analyze_traffic.csv"
    rows = []
    totals = CaptureStats()
    error_count = 0
    for index, task_dir in enumerate(task_dirs, start=1):
        print(f"[{index}/{len(task_dirs)}] {task_dir.name}", flush=True)
        pcaps = list_pcaps(task_dir)
        if not pcaps:
            error_count += 1
            rows.append(summary_row(task_dir.name, env, CaptureStats(), "NO_PCAP"))
            continue
        try:
            task_stats = CaptureStats()
            for pcap in pcaps:
                if len(pcaps) > 1:
                    print(f"  Capture: {pcap.name}", flush=True)
                task_stats.add(inspect_capture(pcap, fields))
            totals.add(task_stats)
            rows.append(summary_row(task_dir.name, env, task_stats, "OK"))
        except Exception as exc:
            error_count += 1
            print(f"  [ERROR] {exc}", file=sys.stderr)
            rows.append(summary_row(task_dir.name, env, CaptureStats(),
                                    "ERROR: " + str(exc)[:180]))

    rows.append(summary_row("__TOTAL__", env, totals, "OK" if not error_count else "PARTIAL",
                            show_duration=False))
    with output.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nCSV saved: {output}")
    print(f"Tasks OK: {len(task_dirs) - error_count}/{len(task_dirs)}")
    print(f"Raw: {mib_decimal(totals.raw_bytes):.3f} MB; "
          f"excluded local: {mib_decimal(totals.filtered_bytes):.3f} MB; "
          f"analyzed: {mib_decimal(totals.analyzed_bytes):.3f} MB")
    for category in CATEGORIES:
        n = totals.byte_counts[category]
        print(f"  {category.upper():10s} {mib_decimal(n):10.3f} MB   "
              f"{percent(n, totals.analyzed_bytes):6.2f}%")
    return 1 if error_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
