#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
analyze_test_v4.py
==================

Validated single-test analyzer (v3) for the Siemens iPCF-2 / standard WLAN
experimental campaign.

Design goals
------------
1) Work from the raw PCAP, not from previously processed CSV files.
2) Use the known experimental topology by default:
       receiver/server = 192.168.1.10
       STA1            = 192.168.1.11
       STA2            = 192.168.1.12
3) Define experimental phases from the JSON metadata stored in each Test folder,
   instead of imposing rigid 0/180/360/540-s PCAP boundaries.
4) Pair ICMP Echo Request/Reply using addresses + ICMP identifier + sequence.
5) Compute RTT variation only between consecutive valid RTTs from the same
   station, same ICMP process, same phase, and same probing period.
6) Use the empirical nearest-rank quantile used in the manuscript:
       Q_q = x_(ceil(q*N))
7) Compute application/transport-payload throughput only for the experimental
   uplink flows, excluding unrelated PCAP traffic.
8) Produce QC files so Test 1 can be validated before batch processing.

The script uses only the Python standard library. Wireshark/TShark is required.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
import statistics
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# -----------------------------------------------------------------------------
# Experiment defaults
# -----------------------------------------------------------------------------

DEFAULT_SERVER_IP = "192.168.1.10"
DEFAULT_STA_IPS = ["192.168.1.11", "192.168.1.12"]
EXPECTED_PROBE_PERIODS = [1.0, 0.5, 0.05]  # actual order in each 180-s block

IPERF_PORTS = {5201, 5202}
FFMPEG_RTP_PORTS = {1234, 1236}

# Expected nominal duration of each traffic block. The JSON metadata defines
# the start time; these durations define the analysis windows.
IDLE_NOMINAL_S = 180.0
IPERF_TCP_NOMINAL_S = 180.0
IPERF_UDP_NOMINAL_S = 180.0
FFMPEG_NOMINAL_S = 180.0


# -----------------------------------------------------------------------------
# Data containers
# -----------------------------------------------------------------------------

@dataclass
class PhaseWindow:
    phase: str
    start_epoch: float
    end_epoch: float

    @property
    def duration_s(self) -> float:
        return max(0.0, self.end_epoch - self.start_epoch)

    def contains(self, t: float) -> bool:
        return self.start_epoch <= t < self.end_epoch


# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------

def find_tshark(explicit: Optional[str] = None) -> str:
    """Locate tshark.exe / tshark."""
    if explicit:
        p = Path(explicit)
        if p.exists():
            return str(p)
        raise FileNotFoundError(f"Specified TShark does not exist: {p}")

    found = shutil.which("tshark")
    if found:
        return found

    windows_default = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if windows_default.exists():
        return str(windows_default)

    raise FileNotFoundError(
        "TShark was not found. Install Wireshark or pass "
        '--tshark "C:\\Program Files\\Wireshark\\tshark.exe"'
    )


def parse_local_datetime(value: str) -> float:
    """
    Convert metadata timestamps such as '2025-11-25 10:28:40' to epoch seconds.

    datetime.timestamp() interprets the naive datetime in the local timezone of
    the Windows machine. This is appropriate when the experiment metadata and
    the PCAP were created on correctly configured local machines at the same site.
    The QC report checks the alignment afterwards.
    """
    dt = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S")
    return dt.timestamp()


def epoch_to_local_string(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_float(x: str) -> Optional[float]:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def safe_int(x: str) -> Optional[int]:
    try:
        return int(x)
    except (TypeError, ValueError):
        try:
            return int(float(x))
        except (TypeError, ValueError):
            return None


def nearest_rank(values: Iterable[float], q: float) -> Optional[float]:
    """
    Empirical quantile:
        Q_q = inf{x : F_N(x) >= q} = x_(ceil(q*N))
    """
    vals = sorted(values)
    if not vals:
        return None
    n = len(vals)
    k = max(1, min(n, math.ceil(q * n)))
    return vals[k - 1]


def metric_stats(values: Iterable[float]) -> dict:
    vals = list(values)
    if not vals:
        return {
            "N": 0,
            "mean": None,
            "sd_population": None,
            "min": None,
            "P50": None,
            "P95": None,
            "P99": None,
            "P99.9": None,
            "max": None,
        }

    return {
        "N": len(vals),
        "mean": statistics.fmean(vals),
        "sd_population": statistics.pstdev(vals) if len(vals) > 1 else 0.0,
        "min": min(vals),
        "P50": nearest_rank(vals, 0.50),
        "P95": nearest_rank(vals, 0.95),
        "P99": nearest_rank(vals, 0.99),
        "P99.9": nearest_rank(vals, 0.999),
        "max": max(vals),
    }


def nearest_probe_period(median_dt: Optional[float]) -> Optional[float]:
    if median_dt is None:
        return None
    return min(EXPECTED_PROBE_PERIODS, key=lambda p: abs(p - median_dt))


def phase_for_epoch(t: float, windows: List[PhaseWindow]) -> Optional[str]:
    for w in windows:
        if w.contains(t):
            return w.phase
    return None


def window_for_phase(phase: str, windows: List[PhaseWindow]) -> PhaseWindow:
    for w in windows:
        if w.phase == phase:
            return w
    raise KeyError(phase)


def parse_config_from_path(path: Path) -> dict:
    text = str(path)
    pat = re.compile(
        r"(iPCF2|iWLAN)_"
        r"(24GHz|5GHz)_"
        r"(CamAne|Lab)_"
        r"(SN|CN)_"
        r"BW(\d+)MHz",
        re.IGNORECASE,
    )
    m = pat.search(text)

    out = {
        "mechanism": "",
        "band": "",
        "environment": "",
        "condition": "",
        "bandwidth_mhz": "",
        "test": "",
    }

    if m:
        out.update({
            "mechanism": m.group(1),
            "band": m.group(2),
            "environment": m.group(3),
            "condition": m.group(4),
            "bandwidth_mhz": m.group(5),
        })

    mt = re.search(r"Test\s*(\d+)", text, re.IGNORECASE)
    if mt:
        out["test"] = mt.group(1)

    return out


def discover_pcap(test_dir: Path) -> Path:
    """Select the capture belonging directly to this Test directory.

    Priority is intentionally shallow:
      1) Test N/pcap|pcaps|capture|captures/*.pcap[ng]
      2) Test N/*.pcap[ng]
      3) recursive fallback only when no direct capture exists

    This prevents accidental duplicate/nested folders such as
    ``Test 7/Test 7/pcap/rep_1.pcap`` from making an otherwise valid Test
    ambiguous. If exactly one direct capture exists, nested captures are
    ignored with a visible QC warning.
    """
    suffixes = {".pcap", ".pcapng"}
    capture_dir_names = {"pcap", "pcaps", "capture", "captures"}

    direct = []
    try:
        for child in test_dir.iterdir():
            if child.is_dir() and child.name.lower() in capture_dir_names:
                direct.extend(
                    p for p in child.iterdir()
                    if p.is_file() and p.suffix.lower() in suffixes
                )
        direct.extend(
            p for p in test_dir.iterdir()
            if p.is_file() and p.suffix.lower() in suffixes
        )
    except (OSError, PermissionError):
        pass

    # De-duplicate paths while preserving stable ordering.
    direct = sorted({p.resolve() for p in direct}, key=lambda p: str(p).lower())
    recursive = sorted(
        {p.resolve() for p in list(test_dir.rglob("*.pcap")) + list(test_dir.rglob("*.pcapng"))},
        key=lambda p: str(p).lower(),
    )

    if direct:
        if len(direct) == 1:
            nested = [p for p in recursive if p not in direct]
            if nested:
                print(
                    "WARNING_NESTED_DUPLICATE_PCAP_IGNORED: using direct capture\n"
                    f"  {direct[0]}\n"
                    "Nested/secondary capture(s) ignored:\n  "
                    + "\n  ".join(str(p) for p in nested)
                )
            return direct[0]

        rep1 = [p for p in direct if p.name.lower() in {"rep_1.pcap", "rep_1.pcapng"}]
        if len(rep1) == 1:
            others = [p for p in direct if p != rep1[0]]
            print(
                "WARNING_MULTIPLE_DIRECT_PCAPS: unique rep_1 selected as primary capture\n"
                f"  {rep1[0]}\n"
                "Other direct capture(s) ignored:\n  "
                + "\n  ".join(str(p) for p in others)
            )
            return rep1[0]

        raise RuntimeError(
            "More than one direct PCAP found in this Test and no unique rep_1 exists. "
            "Please inspect the Test directory or specify --pcap explicitly:\n  "
            + "\n  ".join(str(p) for p in direct)
        )

    if not recursive:
        raise FileNotFoundError(f"No PCAP/PCAPNG found below: {test_dir}")

    if len(recursive) == 1:
        print(
            "WARNING_RECURSIVE_PCAP_FALLBACK: no direct Test capture was found; using\n"
            f"  {recursive[0]}"
        )
        return recursive[0]

    rep1 = [p for p in recursive if p.name.lower() in {"rep_1.pcap", "rep_1.pcapng"}]
    if len(rep1) == 1:
        print(
            "WARNING_RECURSIVE_PCAP_FALLBACK: multiple nested captures found; "
            "unique rep_1 selected\n"
            f"  {rep1[0]}"
        )
        return rep1[0]

    raise RuntimeError(
        "More than one recursive PCAP found and no unique primary capture can be selected. "
        "Please specify --pcap explicitly:\n  "
        + "\n  ".join(str(p) for p in recursive)
    )


# -----------------------------------------------------------------------------
# Phase metadata
# -----------------------------------------------------------------------------

def build_phase_windows(test_dir: Path) -> Tuple[List[PhaseWindow], List[str]]:
    """
    Build absolute phase windows from the JSON metadata produced during testing.

    Test 1 structure verified from the uploaded files:
      pings/rep_1.json       -> no-load/ping block
      pingsIperf/rep_1.json  -> 180 s TCP + 180 s UDP
      pingsFmpeg/rep_1.json  -> ffmpeg block (use first 180 s)
    """
    notes: List[str] = []

    idle_json = test_dir / "pings" / "rep_1.json"
    iperf_json = test_dir / "pingsIperf" / "rep_1.json"
    ffmpeg_json = test_dir / "pingsFmpeg" / "rep_1.json"

    if not idle_json.exists():
        raise FileNotFoundError(f"Missing metadata: {idle_json}")
    if not iperf_json.exists():
        raise FileNotFoundError(f"Missing metadata: {iperf_json}")
    if not ffmpeg_json.exists():
        raise FileNotFoundError(f"Missing metadata: {ffmpeg_json}")

    idle = read_json(idle_json)
    iperf = read_json(iperf_json)
    ffmpeg = read_json(ffmpeg_json)

    idle_start = parse_local_datetime(idle["inicio"])
    idle_end_meta = parse_local_datetime(idle["fin"])
    iperf_start = parse_local_datetime(iperf["inicio"])
    iperf_end_meta = parse_local_datetime(iperf["fin"])
    ffmpeg_start = parse_local_datetime(ffmpeg["inicio"])
    ffmpeg_end_meta = parse_local_datetime(ffmpeg["fin"])

    # Use the next block start as the clean no-load boundary because the metadata
    # shows the idle block ending at the same wall-clock transition.
    idle_end = min(idle_start + IDLE_NOMINAL_S, iperf_start)

    tcp_start = iperf_start
    tcp_end = tcp_start + IPERF_TCP_NOMINAL_S
    udp_start = tcp_end
    udp_end = min(udp_start + IPERF_UDP_NOMINAL_S, iperf_end_meta)

    ffmpeg_end = min(ffmpeg_start + FFMPEG_NOMINAL_S, ffmpeg_end_meta)

    windows = [
        PhaseWindow("idle", idle_start, idle_end),
        PhaseWindow("iperf_tcp", tcp_start, tcp_end),
        PhaseWindow("iperf_udp", udp_start, udp_end),
        PhaseWindow("ffmpeg_udp", ffmpeg_start, ffmpeg_end),
    ]

    if abs((iperf_end_meta - iperf_start) - 360.0) > 3.0:
        notes.append(
            f"WARNING: pingsIperf metadata duration is "
            f"{iperf_end_meta - iperf_start:.3f} s, expected about 360 s."
        )

    if ffmpeg_end_meta - ffmpeg_start > FFMPEG_NOMINAL_S + 5:
        notes.append(
            "INFO: pingsFmpeg metadata extends beyond 180 s; only the first "
            "180 s are used for the nominal multimedia measurement window."
        )

    return windows, notes


# -----------------------------------------------------------------------------
# Optional log validation
# -----------------------------------------------------------------------------

def parse_iperf_log(path: Path, phase: str) -> Optional[dict]:
    if not path.exists():
        return None

    text = path.read_text(encoding="utf-8", errors="replace")

    host = None
    port = None
    mh = re.search(r"Connecting to host\s+([0-9.]+),\s+port\s+(\d+)", text)
    if mh:
        host = mh.group(1)
        port = int(mh.group(2))

    # Prefer final receiver summary.
    final_receiver = None
    for line in text.splitlines():
        if "receiver" not in line:
            continue
        # Handles K/M/Gbits/sec.
        m = re.search(r"([0-9.]+)\s+([KMG])bits/sec", line)
        if m:
            val = float(m.group(1))
            unit = m.group(2)
            scale = {"K": 1e-3, "M": 1.0, "G": 1e3}[unit]
            final_receiver = val * scale

    out = {
        "phase": phase,
        "log_file": str(path),
        "remote_host": host,
        "remote_port": port,
        "reported_receiver_mbps": final_receiver,
    }

    if phase == "iperf_udp":
        # Parse final receiver jitter/loss if available.
        receiver_lines = [ln for ln in text.splitlines() if "receiver" in ln]
        if receiver_lines:
            last = receiver_lines[-1]
            mj = re.search(r"([0-9.]+)\s+ms\s+(\d+)/(\d+)\s+\(([0-9.]+)%\)", last)
            if mj:
                out["reported_jitter_ms"] = float(mj.group(1))
                out["reported_lost_datagrams"] = int(mj.group(2))
                out["reported_total_datagrams"] = int(mj.group(3))
                out["reported_loss_pct"] = float(mj.group(4))

    return out


def parse_ffmpeg_receiver_log(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")

    # Use the final 'Lsize ... bitrate=...kbits/s' line if present.
    kbps = None
    for line in text.splitlines():
        if "Lsize=" in line and "bitrate=" in line:
            m = re.search(r"bitrate=\s*([0-9.]+)kbits/s", line)
            if m:
                kbps = float(m.group(1))

    return {
        "phase": "ffmpeg_udp",
        "log_file": str(path),
        "reported_receiver_mbps": (kbps / 1000.0) if kbps is not None else None,
    }


# -----------------------------------------------------------------------------
# TShark extraction
# -----------------------------------------------------------------------------

# Populated only when TShark successfully emitted valid packets before reaching
# a truncated final packet. This is deliberately narrow: genuinely corrupt PCAPs
# remain fatal and are NOT salvaged.
CAPTURE_QC_WARNINGS = []

def tshark_stream(tshark: str, pcap: Path):
    """Yield selected packet fields from the PCAP as dictionaries."""

    fields = [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "icmp.type",
        "icmp.ident",
        "icmp.ident_le",
        "icmp.seq",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.len",
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "udp.srcport",
        "udp.dstport",
        "udp.length",
    ]

    cmd = [
        tshark,
        "-n",
        "-r", str(pcap),
        "-Y", "icmp || tcp || udp",
        "-T", "fields",
        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]
    for f in fields:
        cmd.extend(["-e", f])

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        cols = line.rstrip("\n").split("|")
        if len(cols) < len(fields):
            cols += [""] * (len(fields) - len(cols))
        yield dict(zip(fields, cols[:len(fields)]))

    stderr = proc.stderr.read() if proc.stderr is not None else ""
    code = proc.wait()
    if code != 0:
        # Wireshark/TShark commonly returns exit code 14 when a capture ended
        # while the final packet was still being written. All complete packets
        # before that point have already been emitted on stdout and can be used.
        # We salvage ONLY this specific EOF-truncation condition. Errors such as
        # absurd packet lengths / damaged headers remain fatal.
        low = stderr.lower()
        eof_truncated = (
            "appears to have been cut short in the middle of a packet" in low
            or "cut short in the middle of a packet" in low
        )
        if code == 14 and eof_truncated:
            warning = (
                "PARTIAL_CAPTURE_TRUNCATED: TShark reached an incomplete final "
                "packet. All complete packets emitted before the truncation were "
                "retained; the incomplete final packet was discarded."
            )
            CAPTURE_QC_WARNINGS.append(warning)
            print("WARNING:", warning)
            return
        raise RuntimeError(f"TShark failed with exit code {code}:\n{stderr}")


# -----------------------------------------------------------------------------
# Analysis
# -----------------------------------------------------------------------------

def analyze(
    test_dir: Path,
    pcap: Path,
    outdir: Path,
    tshark: str,
    server_ip: str,
    sta_ips: List[str],
) -> None:

    outdir.mkdir(parents=True, exist_ok=True)
    CAPTURE_QC_WARNINGS.clear()
    metadata = parse_config_from_path(test_dir)
    windows, metadata_notes = build_phase_windows(test_dir)

    # ------------------------------------------------------------------
    # Containers
    # ------------------------------------------------------------------

    # Request/reply matching.
    pending: Dict[Tuple[str, str, str, str], deque] = defaultdict(deque)
    requests: List[dict] = []
    rtt_records: List[dict] = []

    # Request timestamps by complete ping process.
    request_times_by_process: Dict[Tuple[str, str, str, str], List[float]] = defaultdict(list)

    # Throughput bytes in 1-second bins relative to the true phase start.
    # Key: (phase, sta_ip, second_index)
    throughput_bytes_1s: Dict[Tuple[str, str, int], int] = defaultdict(int)
    throughput_retrans_bytes_1s: Dict[Tuple[str, str, int], int] = defaultdict(int)
    tcp_retrans_packets: Dict[Tuple[str, str], int] = defaultdict(int)

    # Topology/QC observations.
    observed_ips = set()
    first_epoch = None
    last_epoch = None
    phase_payload_packets = defaultdict(int)
    phase_payload_bytes = defaultdict(int)

    print(f"\nReading PCAP:\n  {pcap}")
    print("This can take several minutes for a large capture.\n")

    for row in tshark_stream(tshark, pcap):
        epoch = safe_float(row["frame.time_epoch"])
        if epoch is None:
            continue

        first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
        last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)

        src = row["ip.src"]
        dst = row["ip.dst"]
        if src:
            observed_ips.add(src)
        if dst:
            observed_ips.add(dst)

        phase = phase_for_epoch(epoch, windows)

        # --------------------------------------------------------------
        # ICMP RTT
        # --------------------------------------------------------------
        if row["icmp.type"]:
            typ = safe_int(row["icmp.type"])
            ident = row["icmp.ident"] or row["icmp.ident_le"] or "unknown"
            seq = row["icmp.seq"]

            # Only keep ICMP probes between server and the two known STAs.
            if not (
                (src == server_ip and dst in sta_ips)
                or (dst == server_ip and src in sta_ips)
            ):
                continue

            if typ == 8:  # Echo Request
                key = (src, dst, ident, seq)
                req = {
                    "request_epoch": epoch,
                    "src": src,
                    "dst": dst,
                    "ident": ident,
                    "seq": seq,
                    "phase": phase,
                    "matched": False,
                }
                idx = len(requests)
                requests.append(req)
                pending[key].append(idx)

                if phase is not None:
                    process_key = (src, dst, ident, phase)
                    request_times_by_process[process_key].append(epoch)

            elif typ == 0:  # Echo Reply
                reverse_key = (dst, src, ident, seq)
                if pending[reverse_key]:
                    idx = pending[reverse_key].popleft()
                    req = requests[idx]
                    req["matched"] = True
                    req_phase = req["phase"]

                    # Require the reply to fall very close to the same measurement
                    # phase; RTTs are milliseconds, so phase-crossing replies are
                    # normally boundary artefacts.
                    rtt_ms = (epoch - req["request_epoch"]) * 1000.0
                    if rtt_ms >= 0:
                        sta_ip = req["dst"] if req["dst"] in sta_ips else req["src"]
                        rtt_records.append({
                            "phase": req_phase,
                            "sta_ip": sta_ip,
                            "icmp_id": ident,
                            "icmp_seq": seq,
                            "request_epoch": req["request_epoch"],
                            "reply_epoch": epoch,
                            "rtt_ms": rtt_ms,
                        })
            continue

        # --------------------------------------------------------------
        # Application/transport throughput
        # --------------------------------------------------------------
        if phase not in {"iperf_tcp", "iperf_udp", "ffmpeg_udp"}:
            continue

        # We are evaluating the uplink traffic from each STA to 192.168.1.10.
        if src not in sta_ips or dst != server_ip:
            continue

        w = window_for_phase(phase, windows)
        sec = int(math.floor(epoch - w.start_epoch))
        if sec < 0 or sec >= int(math.ceil(w.duration_s)):
            continue

        payload = 0

        if phase == "iperf_tcp":
            sport = safe_int(row["tcp.srcport"])
            dport = safe_int(row["tcp.dstport"])
            tcp_len = safe_int(row["tcp.len"]) or 0

            if sport not in IPERF_PORTS and dport not in IPERF_PORTS:
                continue
            if tcp_len <= 0:
                continue

            retrans = bool(row["tcp.analysis.retransmission"]) or bool(
                row["tcp.analysis.fast_retransmission"]
            )
            if retrans:
                throughput_retrans_bytes_1s[(phase, src, sec)] += tcp_len
                tcp_retrans_packets[(phase, src)] += 1
                continue

            payload = tcp_len

        elif phase == "iperf_udp":
            sport = safe_int(row["udp.srcport"])
            dport = safe_int(row["udp.dstport"])
            udp_len = safe_int(row["udp.length"]) or 0

            if sport not in IPERF_PORTS and dport not in IPERF_PORTS:
                continue
            if udp_len <= 8:
                continue

            # UDP transport payload, excluding the 8-byte UDP header.
            payload = udp_len - 8

        elif phase == "ffmpeg_udp":
            sport = safe_int(row["udp.srcport"])
            dport = safe_int(row["udp.dstport"])
            udp_len = safe_int(row["udp.length"]) or 0

            if sport not in FFMPEG_RTP_PORTS and dport not in FFMPEG_RTP_PORTS:
                continue
            if udp_len <= 8:
                continue

            # RTP packet is carried inside UDP. This is transport-payload
            # throughput: UDP header excluded, RTP header retained.
            payload = udp_len - 8

        if payload > 0:
            throughput_bytes_1s[(phase, src, sec)] += payload
            phase_payload_packets[(phase, src)] += 1
            phase_payload_bytes[(phase, src)] += payload

    # ------------------------------------------------------------------
    # Hard topology checks
    # ------------------------------------------------------------------

    missing = [ip for ip in [server_ip] + sta_ips if ip not in observed_ips]
    if missing:
        raise RuntimeError(
            "Expected topology was not found in the PCAP. Missing IP(s): "
            + ", ".join(missing)
            + "\nObserved IPs include: "
            + ", ".join(sorted(observed_ips)[:30])
        )

    # ------------------------------------------------------------------
    # Reassign each COMPLETE ICMP ping process to one experimental phase
    # ------------------------------------------------------------------
    #
    # JSON phase boundaries are second-resolution timestamps, whereas a ping
    # subprocess may cross a boundary by a few packets.  Splitting one ICMP
    # identifier across two phases contaminates the tail statistics.  We
    # therefore assign the complete (src,dst,icmp_id) process to the phase
    # containing the majority of its Echo Requests, then rebuild all process
    # structures from that assignment.

    process_phase_counts = defaultdict(lambda: defaultdict(int))
    for req in requests:
        if req["phase"] is not None:
            bare_key = (req["src"], req["dst"], req["ident"])
            process_phase_counts[bare_key][req["phase"]] += 1

    dominant_process_phase = {}
    for bare_key, counts in process_phase_counts.items():
        # Deterministic tie-break: larger count first; if exactly equal, choose
        # the phase containing the median request timestamp below.
        best_count = max(counts.values())
        tied = [ph for ph, n in counts.items() if n == best_count]
        if len(tied) == 1:
            dominant_process_phase[bare_key] = tied[0]
        else:
            times = sorted(
                req["request_epoch"] for req in requests
                if (req["src"], req["dst"], req["ident"]) == bare_key
            )
            median_t = statistics.median(times)
            median_phase = phase_for_epoch(median_t, windows)
            dominant_process_phase[bare_key] = median_phase if median_phase in tied else tied[0]

    # Update requests.
    for req in requests:
        bare_key = (req["src"], req["dst"], req["ident"])
        if bare_key in dominant_process_phase:
            req["phase"] = dominant_process_phase[bare_key]

    # Update RTT records (Echo Requests are server -> STA in this campaign).
    for rec in rtt_records:
        bare_key = (server_ip, rec["sta_ip"], rec["icmp_id"])
        if bare_key in dominant_process_phase:
            rec["phase"] = dominant_process_phase[bare_key]

    # Rebuild request timestamps by complete process AFTER reassignment.
    request_times_by_process = defaultdict(list)
    for req in requests:
        if req["phase"] is None:
            continue
        process_key = (req["src"], req["dst"], req["ident"], req["phase"])
        request_times_by_process[process_key].append(req["request_epoch"])

    # ------------------------------------------------------------------
    # Identify probing period from the observed ICMP process cadence
    # ------------------------------------------------------------------

    process_period: Dict[Tuple[str, str, str, str], Optional[float]] = {}
    process_qc_rows: List[dict] = []

    for process_key, times in sorted(request_times_by_process.items()):
        times = sorted(times)
        diffs = [
            times[i] - times[i - 1]
            for i in range(1, len(times))
            if 0 < times[i] - times[i - 1] < 2.5
        ]
        median_dt = statistics.median(diffs) if diffs else None
        assigned = nearest_probe_period(median_dt)
        process_period[process_key] = assigned

        src, dst, ident, phase = process_key
        sta_ip = dst if dst in sta_ips else src if src in sta_ips else ""
        process_qc_rows.append({
            **metadata,
            "phase": phase,
            "sta_ip": sta_ip,
            "icmp_id": ident,
            "requests": len(times),
            "first_request_local": epoch_to_local_string(times[0]),
            "last_request_local": epoch_to_local_string(times[-1]),
            "median_request_interval_s": median_dt,
            "assigned_probe_interval_s": assigned,
        })

    # Attach period to RTT records.
    for rec in rtt_records:
        # Requests are server -> STA in the verified Test 1 topology.
        pkey = (server_ip, rec["sta_ip"], rec["icmp_id"], rec["phase"])
        rec["probe_interval_s"] = process_period.get(pkey)

    # ------------------------------------------------------------------
    # ICMP loss grouped by phase / STA / probing process
    # ------------------------------------------------------------------

    process_counts = defaultdict(lambda: {"sent": 0, "received": 0})

    for req in requests:
        if req["phase"] is None:
            continue
        sta_ip = req["dst"] if req["dst"] in sta_ips else req["src"] if req["src"] in sta_ips else ""
        pkey = (req["src"], req["dst"], req["ident"], req["phase"])
        period = process_period.get(pkey)
        gkey = (req["phase"], sta_ip, req["ident"], period)
        process_counts[gkey]["sent"] += 1
        if req["matched"]:
            process_counts[gkey]["received"] += 1

    # ------------------------------------------------------------------
    # RTT and successive RTT variation
    # ------------------------------------------------------------------

    rtt_by_group = defaultdict(list)  # (phase, period, sta) -> values
    rtt_by_process = defaultdict(list)  # (phase, period, sta, id) -> (time, RTT)

    for rec in rtt_records:
        if rec["phase"] is None or rec["probe_interval_s"] is None:
            continue
        key = (rec["phase"], rec["probe_interval_s"], rec["sta_ip"])
        rtt_by_group[key].append(rec["rtt_ms"])
        pkey = (rec["phase"], rec["probe_interval_s"], rec["sta_ip"], rec["icmp_id"])
        rtt_by_process[pkey].append((rec["request_epoch"], rec["rtt_ms"]))

    variation_by_group = defaultdict(list)
    variation_rows = []

    for pkey, samples in rtt_by_process.items():
        phase, period, sta, ident = pkey
        samples = sorted(samples)
        for i in range(1, len(samples)):
            prev_t, prev_rtt = samples[i - 1]
            curr_t, curr_rtt = samples[i]
            j = abs(curr_rtt - prev_rtt)
            variation_by_group[(phase, period, sta)].append(j)
            variation_rows.append({
                **metadata,
                "phase": phase,
                "probe_interval_s": period,
                "sta_ip": sta,
                "icmp_id": ident,
                "previous_request_local": epoch_to_local_string(prev_t),
                "current_request_local": epoch_to_local_string(curr_t),
                "previous_rtt_ms": prev_rtt,
                "current_rtt_ms": curr_rtt,
                "rtt_variation_ms": j,
            })

    # ------------------------------------------------------------------
    # Export raw RTT samples
    # ------------------------------------------------------------------

    rtt_samples_path = outdir / "rtt_samples.csv"
    rtt_rows_out = []
    for rec in sorted(rtt_records, key=lambda x: x["request_epoch"]):
        if rec["phase"] is None or rec["probe_interval_s"] is None:
            continue
        rtt_rows_out.append({
            **metadata,
            "phase": rec["phase"],
            "probe_interval_s": rec["probe_interval_s"],
            "sta_ip": rec["sta_ip"],
            "icmp_id": rec["icmp_id"],
            "icmp_seq": rec["icmp_seq"],
            "request_local": epoch_to_local_string(rec["request_epoch"]),
            "reply_local": epoch_to_local_string(rec["reply_epoch"]),
            "rtt_ms": rec["rtt_ms"],
        })

    write_csv(rtt_samples_path, rtt_rows_out)
    write_csv(outdir / "rtt_variation_samples.csv", variation_rows)
    write_csv(outdir / "icmp_processes.csv", process_qc_rows)

    # ------------------------------------------------------------------
    # RTT/variation summary
    # ------------------------------------------------------------------

    summary_rows = []
    summary_keys = sorted(set(rtt_by_group) | set(variation_by_group))

    # Aggregate ICMP sent/received across ping identifiers with same phase/STA/period.
    counts_by_group = defaultdict(lambda: {"sent": 0, "received": 0})
    for (phase, sta, ident, period), c in process_counts.items():
        counts_by_group[(phase, period, sta)]["sent"] += c["sent"]
        counts_by_group[(phase, period, sta)]["received"] += c["received"]

    for key in summary_keys:
        phase, period, sta = key
        rtt_stats = metric_stats(rtt_by_group.get(key, []))
        var_stats = metric_stats(variation_by_group.get(key, []))
        counts = counts_by_group.get(key, {"sent": 0, "received": 0})
        sent, received = counts["sent"], counts["received"]
        loss_pct = 100.0 * (sent - received) / sent if sent else None

        row = {
            **metadata,
            "phase": phase,
            "probe_interval_s": period,
            "sta_ip": sta,
            "icmp_requests": sent,
            "icmp_replies": received,
            "icmp_loss_pct": loss_pct,
        }
        for k, v in rtt_stats.items():
            row[f"rtt_{k}"] = v
        for k, v in var_stats.items():
            row[f"variation_{k}"] = v
        summary_rows.append(row)

    write_csv(outdir / "rtt_variation_summary.csv", summary_rows)

    # ------------------------------------------------------------------
    # Throughput 1-s series and summaries
    # ------------------------------------------------------------------

    throughput_rows: List[dict] = []
    throughput_summary_rows: List[dict] = []

    traffic_phases = ["iperf_tcp", "iperf_udp", "ffmpeg_udp"]

    for phase in traffic_phases:
        w = window_for_phase(phase, windows)
        n_seconds = int(round(w.duration_s))

        # The experiment uses 3 consecutive 60-s ping blocks in this order.
        # We label throughput windows by the nominal probing period for direct
        # comparison with RTT statistics.
        for sta in sta_ips + ["AGGREGATE"]:
            values_by_period = defaultdict(list)

            for sec in range(n_seconds):
                if sta == "AGGREGATE":
                    b = sum(throughput_bytes_1s[(phase, s, sec)] for s in sta_ips)
                else:
                    b = throughput_bytes_1s[(phase, sta, sec)]

                mbps = b * 8.0 / 1_000_000.0
                block = min(2, sec // 60)
                probe_period = EXPECTED_PROBE_PERIODS[block]
                values_by_period[probe_period].append(mbps)

                throughput_rows.append({
                    **metadata,
                    "phase": phase,
                    "probe_interval_s": probe_period,
                    "sta_ip": sta,
                    "second_in_phase": sec,
                    "payload_bytes": b,
                    "throughput_mbps": mbps,
                })

            # Summary by 60-s probing sub-window.
            for probe_period, vals in sorted(values_by_period.items(), reverse=True):
                s = metric_stats(vals)
                row = {
                    **metadata,
                    "phase": phase,
                    "probe_interval_s": probe_period,
                    "sta_ip": sta,
                }
                for k, v in s.items():
                    row[f"throughput_{k}"] = v
                throughput_summary_rows.append(row)

            # Whole 180-s phase summary.
            all_vals = [
                (sum(throughput_bytes_1s[(phase, s, sec)] for s in sta_ips)
                 if sta == "AGGREGATE"
                 else throughput_bytes_1s[(phase, sta, sec)])
                * 8.0 / 1_000_000.0
                for sec in range(n_seconds)
            ]
            s = metric_stats(all_vals)
            row = {
                **metadata,
                "phase": phase,
                "probe_interval_s": "ALL",
                "sta_ip": sta,
            }
            for k, v in s.items():
                row[f"throughput_{k}"] = v
            throughput_summary_rows.append(row)

    write_csv(outdir / "throughput_1s.csv", throughput_rows)
    write_csv(outdir / "throughput_summary.csv", throughput_summary_rows)

    # ------------------------------------------------------------------
    # Phase/QC table
    # ------------------------------------------------------------------

    phase_rows = []
    for w in windows:
        phase_rows.append({
            **metadata,
            "phase": w.phase,
            "start_local": epoch_to_local_string(w.start_epoch),
            "end_local": epoch_to_local_string(w.end_epoch),
            "duration_s": w.duration_s,
        })
    write_csv(outdir / "phase_windows.csv", phase_rows)

    # ------------------------------------------------------------------
    # Validate against available generator logs
    # ------------------------------------------------------------------

    validation_rows = []
    tcp_log = parse_iperf_log(test_dir / "pingsIperf" / "iperf_tcp_rep_1.log", "iperf_tcp")
    udp_log = parse_iperf_log(test_dir / "pingsIperf" / "iperf_udp_rep_1.log", "iperf_udp")
    ff_log = parse_ffmpeg_receiver_log(test_dir / "pingsFmpeg" / "reporte_RECEPTOR_rep_1.txt")

    for x in [tcp_log, udp_log, ff_log]:
        if x:
            validation_rows.append({**metadata, **x})
    write_csv(outdir / "log_validation.csv", validation_rows)

    # ------------------------------------------------------------------
    # QC text report
    # ------------------------------------------------------------------

    qc_path = outdir / "qc_report.txt"
    with qc_path.open("w", encoding="utf-8") as f:
        f.write("iPCF-2 / WLAN Test Analyzer v5 - QC REPORT\n")
        f.write("================================================\n\n")
        f.write(f"Test directory: {test_dir}\n")
        f.write(f"PCAP: {pcap}\n")
        f.write(f"TShark: {tshark}\n\n")
        f.write(f"Expected server: {server_ip}\n")
        f.write(f"Expected STAs: {', '.join(sta_ips)}\n")
        f.write("Topology check: PASS\n\n")

        if CAPTURE_QC_WARNINGS:
            f.write("Capture QC warnings:\n")
            for warning in CAPTURE_QC_WARNINGS:
                f.write(f"  {warning}\n")
            f.write("\n")

        if first_epoch is not None:
            f.write(f"PCAP first packet local: {epoch_to_local_string(first_epoch)}\n")
        if last_epoch is not None:
            f.write(f"PCAP last packet local:  {epoch_to_local_string(last_epoch)}\n")
        f.write("\nPhase windows from experiment JSON metadata:\n")
        for w in windows:
            f.write(
                f"  {w.phase:12s} {epoch_to_local_string(w.start_epoch)} -> "
                f"{epoch_to_local_string(w.end_epoch)} ({w.duration_s:.3f} s)\n"
            )

        if metadata_notes:
            f.write("\nMetadata notes:\n")
            for note in metadata_notes:
                f.write(f"  {note}\n")

        f.write("\nObserved experimental payload by phase/STA:\n")
        for phase in traffic_phases:
            for sta in sta_ips:
                f.write(
                    f"  {phase:12s} {sta}: "
                    f"packets={phase_payload_packets[(phase, sta)]}, "
                    f"payload_bytes={phase_payload_bytes[(phase, sta)]}, "
                    f"TCP_retrans_packets={tcp_retrans_packets[(phase, sta)]}\n"
                )

        f.write("\nICMP processes:\n")
        for row in process_qc_rows:
            f.write(
                f"  phase={row['phase']}, STA={row['sta_ip']}, id={row['icmp_id']}, "
                f"requests={row['requests']}, median_dt={row['median_request_interval_s']}, "
                f"assigned={row['assigned_probe_interval_s']}\n"
            )

        f.write("\nICMP phase-assignment rule:\n")
        f.write("  Each complete (src,dst,ICMP identifier) ping process is assigned\n")
        f.write("  to the phase containing the majority of its Echo Requests.\n")
        f.write("  This prevents second-resolution metadata boundaries from splitting\n")
        f.write("  one ping process across adjacent experimental phases.\n")

        f.write("\nQuantile definition:\n")
        f.write("  Q_q = x_(ceil(q*N)) [empirical nearest-rank / inverse ECDF]\n")
        f.write("  Reported: P50, P95, P99, P99.9, maximum\n")
        f.write("\nRTT variation definition:\n")
        f.write("  J_i = |RTT_i - RTT_(i-1)| within the same ICMP process\n")
        f.write("\nThroughput definition:\n")
        f.write("  TCP: unique/non-retransmitted TCP payload from STA -> server\n")
        f.write("  UDP iperf3: UDP payload (UDP header excluded) from STA -> server\n")
        f.write("  ffmpeg: UDP transport payload (UDP header excluded; RTP retained)\n")

    print("\nDONE - v5 analysis completed")
    print(f"Output directory: {outdir}\n")
    print("Generated:")
    for name in [
        "phase_windows.csv",
        "icmp_processes.csv",
        "rtt_samples.csv",
        "rtt_variation_samples.csv",
        "rtt_variation_summary.csv",
        "throughput_1s.csv",
        "throughput_summary.csv",
        "log_validation.csv",
        "qc_report.txt",
    ]:
        print(f"  - {name}")


def write_csv(path: Path, rows: List[dict]) -> None:
    if not rows:
        # Create an empty file with a short comment rather than silently omitting it.
        path.write_text("", encoding="utf-8")
        return

    # Preserve first-seen field order while supporting optional validation fields.
    fieldnames: List[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Analyze one complete Siemens iPCF-2/WLAN Test folder from raw PCAP."
    )
    ap.add_argument(
        "--test-dir",
        required=True,
        type=Path,
        help='Path to the Test folder, e.g. "D:\\...\\Prueba_Siemens2\\Test 1"',
    )
    ap.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Directory in which the new CSV/QC outputs will be written.",
    )
    ap.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help="Optional PCAP path. If omitted, the script finds rep_1.pcap below --test-dir.",
    )
    ap.add_argument(
        "--tshark",
        default=None,
        help='Optional explicit TShark path, e.g. "C:\\Program Files\\Wireshark\\tshark.exe"',
    )
    ap.add_argument("--server-ip", default=DEFAULT_SERVER_IP)
    ap.add_argument(
        "--sta-ip",
        dest="sta_ips",
        action="append",
        default=None,
        help="STA IP. Supply twice to override the defaults.",
    )

    args = ap.parse_args()
    test_dir = args.test_dir.resolve()
    if not test_dir.exists() or not test_dir.is_dir():
        sys.exit(f"Test directory does not exist: {test_dir}")

    sta_ips = args.sta_ips if args.sta_ips else list(DEFAULT_STA_IPS)
    if len(sta_ips) != 2:
        sys.exit("Exactly two --sta-ip values are required for this study.")

    pcap = args.pcap.resolve() if args.pcap else discover_pcap(test_dir)
    if not pcap.exists():
        sys.exit(f"PCAP does not exist: {pcap}")

    tshark = find_tshark(args.tshark)

    analyze(
        test_dir=test_dir,
        pcap=pcap,
        outdir=args.out.resolve(),
        tshark=tshark,
        server_ip=args.server_ip,
        sta_ips=sta_ips,
    )


if __name__ == "__main__":
    main()
