#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
analyze_folder_batch_v4.py
=======================

Batch wrapper for the validated single-test analyzer `analyze_test_v4.py`.

Purpose
-------
Process every `Test N` directory inside one Siemens experiment folder, e.g.:

    D:\iPCF2_5GHz_CamAne_SN_BW20MHz\Prueba_Siemens2

The script:
1. Finds Test 1, Test 2, ... automatically.
2. Calls the validated v4 raw-PCAP analyzer on each Test.
3. Extracts test-level traffic-rate metadata from the original generator logs.
4. Creates one output directory per Test.
5. Concatenates the per-test summaries into MASTER CSV files.
6. Writes a batch QC/index file and continues past failed tests instead of
   discarding already completed work.

Important
---------
`analyze_test_v4.py` must be in the SAME directory as this script (or otherwise
importable through PYTHONPATH).

The reference test load is NOT inferred from achieved TCP throughput.  UDP is
explicitly rate-controlled in the experiment, so its final sender rate is used
as the primary per-STA reference/offered load.  The ffmpeg SDP target rate is
used as an independent consistency check when available.  TCP sender/receiver
rates are retained separately as achieved transport throughput, allowing the
analysis to expose TCP saturation instead of misclassifying it as a load error.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import sys
import traceback
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# The validated raw-PCAP engine.
try:
    import analyze_test_v4 as engine
except ImportError as exc:
    raise SystemExit(
        "Could not import analyze_test_v4.py. Put analyze_test_v4.py in the "
        "same folder as analyze_folder_batch.py and try again."
    ) from exc


# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------

def test_number(path: Path) -> int:
    m = re.fullmatch(r"Test\s*(\d+)", path.name, flags=re.IGNORECASE)
    return int(m.group(1)) if m else 10**9


def _has_raw_pcap(test_dir: Path) -> bool:
    try:
        for child in test_dir.iterdir():
            if child.is_dir() and child.name.lower() in {"pcap", "pcaps", "capture", "captures"}:
                try:
                    if any(f.is_file() and f.suffix.lower() in {".pcap", ".pcapng"} for f in child.iterdir()):
                        return True
                except (OSError, PermissionError):
                    pass
        return any(f.is_file() and f.suffix.lower() in {".pcap", ".pcapng"} for f in test_dir.iterdir())
    except (OSError, PermissionError):
        return False


def discover_test_dirs(root: Path) -> List[Path]:
    tests = []
    for p in root.iterdir():
        if not p.is_dir():
            continue
        m = re.fullmatch(r"Test\s*(\d+)", p.name, flags=re.IGNORECASE)
        if not m:
            continue
        # Test 0 is auxiliary/warm-up in some trees; publication load levels start at Test 1.
        if int(m.group(1)) < 1:
            continue
        if not _has_raw_pcap(p):
            print(f"SKIP {p.name}: no raw PCAP/PCAPNG found")
            continue
        tests.append(p)
    return sorted(tests, key=test_number)


def convert_rate_to_mbps(value: float, unit: str) -> float:
    scales = {
        "bits/sec": 1e-6,
        "Kbits/sec": 1e-3,
        "Mbits/sec": 1.0,
        "Gbits/sec": 1e3,
    }
    return value * scales[unit]


def parse_final_iperf_summary(path: Path) -> Dict[str, Optional[float]]:
    """
    Parse final iperf3 sender/receiver summary rates.

    Returns Mbps values from lines like:
      0.00-180.01 sec ... 5.00 Mbits/sec ... sender
      0.00-180.00 sec ... 5.00 Mbits/sec ... receiver

    For UDP, also extracts receiver jitter/loss when available.
    """
    result: Dict[str, Optional[float]] = {
        "sender_mbps": None,
        "receiver_mbps": None,
        "receiver_jitter_ms": None,
        "receiver_loss_pct": None,
    }

    if not path.exists():
        return result

    text = path.read_text(encoding="utf-8", errors="replace")

    rate_pat = re.compile(
        r"([0-9]+(?:\.[0-9]+)?)\s+"
        r"(bits/sec|Kbits/sec|Mbits/sec|Gbits/sec)"
    )

    for line in text.splitlines():
        role = None
        if re.search(r"\bsender\s*$", line):
            role = "sender"
        elif re.search(r"\breceiver\s*$", line):
            role = "receiver"
        else:
            continue

        matches = list(rate_pat.finditer(line))
        if not matches:
            continue

        # The final bitrate token is the throughput summary bitrate.
        m = matches[-1]
        mbps = convert_rate_to_mbps(float(m.group(1)), m.group(2))
        result[f"{role}_mbps"] = mbps

        if role == "receiver":
            mj = re.search(r"([0-9]+(?:\.[0-9]+)?)\s+ms", line)
            if mj:
                result["receiver_jitter_ms"] = float(mj.group(1))

            ml = re.search(
                r"(\d+)\s*/\s*(\d+)\s*\(([0-9]+(?:\.[0-9]+)?)%\)",
                line,
            )
            if ml:
                result["receiver_loss_pct"] = float(ml.group(3))

    return result


def parse_ffmpeg_target_mbps(test_dir: Path) -> Optional[float]:
    """
    Read the advertised RTP/SDP bandwidth from the original sender report.

    Example:
        b=AS:5000

    SDP AS bandwidth is reported in kbit/s here, so 5000 -> 5.0 Mbps.
    This is retained as target/application metadata, not as measured goodput.
    """
    candidates = list((test_dir / "pingsFmpeg").glob("reporte_EMISOR_rep_*.txt"))
    if not candidates:
        return None

    for path in sorted(candidates):
        text = path.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"(?m)^b=AS:(\d+(?:\.\d+)?)\s*$", text)
        if m:
            return float(m.group(1)) / 1000.0

    return None


def build_test_load_metadata(test_dir: Path, tolerance_pct: float) -> dict:
    """
    Resolve the test-level reference/offered load without using TCP achieved
    throughput as the load definition.

    Experimental interpretation
    ---------------------------
    * UDP iperf3 is explicitly rate-controlled. Its final sender rate is used
      as the primary reference/offered load per STA.
    * ffmpeg's SDP ``b=AS`` value is an application target and is used only as
      an independent consistency check against the UDP reference load.
    * TCP sender/receiver summary rates are ACHIEVED throughput. They are never
      required to equal the reference load because TCP may saturate or respond
      to congestion control at high load.

    This distinction is essential for Tests in which the nominal/reference load
    continues increasing but TCP throughput plateaus.
    """
    tcp_path = test_dir / "pingsIperf" / "iperf_tcp_rep_1.log"
    udp_path = test_dir / "pingsIperf" / "iperf_udp_rep_1.log"

    tcp = parse_final_iperf_summary(tcp_path)
    udp = parse_final_iperf_summary(udp_path)
    ffmpeg_target = parse_ffmpeg_target_mbps(test_dir)

    tcp_sender = tcp["sender_mbps"]
    tcp_receiver = tcp["receiver_mbps"]
    udp_sender = udp["sender_mbps"]
    udp_receiver = udp["receiver_mbps"]

    reference = None
    load_status = "UNRESOLVED"
    load_note = ""
    udp_ffmpeg_diff_pct = None

    if udp_sender is not None:
        # Primary definition: UDP sender rate is the controlled offered load.
        reference = udp_sender

        if ffmpeg_target is not None:
            denom = max(abs(udp_sender), abs(ffmpeg_target), 1e-12)
            udp_ffmpeg_diff_pct = 100.0 * abs(udp_sender - ffmpeg_target) / denom

            if udp_ffmpeg_diff_pct <= tolerance_pct:
                load_status = "OK_UDP_FFMPEG_MATCH"
                load_note = (
                    f"Reference load taken from rate-controlled UDP sender summary "
                    f"({udp_sender:.6g} Mbps/STA). ffmpeg target={ffmpeg_target:.6g} "
                    f"Mbps/STA; difference={udp_ffmpeg_diff_pct:.3f}% <= tolerance "
                    f"{tolerance_pct:.3f}%. TCP is retained as achieved throughput "
                    f"and is not required to match the reference load."
                )
            else:
                load_status = "UDP_FFMPEG_TARGET_MISMATCH"
                load_note = (
                    f"Reference load retained from rate-controlled UDP sender summary "
                    f"({udp_sender:.6g} Mbps/STA), but ffmpeg target={ffmpeg_target:.6g} "
                    f"Mbps/STA differs by {udp_ffmpeg_diff_pct:.3f}% > tolerance "
                    f"{tolerance_pct:.3f}%. Inspect this Test before pooling ffmpeg "
                    f"with the common test-load axis."
                )
        else:
            load_status = "OK_FROM_UDP_SENDER"
            load_note = (
                f"Reference load taken from rate-controlled UDP sender summary "
                f"({udp_sender:.6g} Mbps/STA). No ffmpeg target was available for "
                f"cross-checking."
            )

    elif ffmpeg_target is not None:
        # Fallback only when UDP metadata is unavailable.
        reference = ffmpeg_target
        load_status = "FALLBACK_FROM_FFMPEG_TARGET"
        load_note = (
            "UDP sender summary was unavailable. Reference load was taken from "
            f"ffmpeg SDP target ({ffmpeg_target:.6g} Mbps/STA). This Test should "
            "be inspected before final publication."
        )
    elif tcp_sender is not None:
        # Do NOT promote TCP achieved throughput to offered/reference load.
        load_status = "TCP_ONLY_REFERENCE_UNRESOLVED"
        load_note = (
            f"Only TCP achieved sender throughput ({tcp_sender:.6g} Mbps) was "
            "available. It is not used as offered/reference load because TCP "
            "throughput is congestion-controlled."
        )
    else:
        load_note = "No usable UDP sender or ffmpeg target metadata found."

    # Diagnostics: how much TCP achieved rate falls below/above the reference.
    tcp_sender_vs_reference_pct = None
    tcp_receiver_vs_reference_pct = None
    if reference is not None and reference > 0:
        if tcp_sender is not None:
            tcp_sender_vs_reference_pct = 100.0 * tcp_sender / reference
        if tcp_receiver is not None:
            tcp_receiver_vs_reference_pct = 100.0 * tcp_receiver / reference

    return {
        # Reference/offered load used on the common Test load axis.
        "reference_load_per_sta_mbps": reference,
        "reference_load_aggregate_mbps": (2.0 * reference) if reference is not None else None,
        "reference_load_source": (
            "iperf3_udp_sender" if udp_sender is not None
            else "ffmpeg_sdp_target" if ffmpeg_target is not None
            else None
        ),
        "load_resolution_status": load_status,
        "load_resolution_note": load_note,
        "udp_ffmpeg_difference_pct": udp_ffmpeg_diff_pct,

        # TCP: achieved transport throughput, not offered-load definition.
        "tcp_achieved_sender_mbps": tcp_sender,
        "tcp_achieved_receiver_mbps": tcp_receiver,
        "tcp_sender_as_pct_of_reference": tcp_sender_vs_reference_pct,
        "tcp_receiver_as_pct_of_reference": tcp_receiver_vs_reference_pct,

        # UDP: controlled offered rate plus achieved receiver rate/loss.
        "udp_offered_sender_mbps": udp_sender,
        "udp_achieved_receiver_mbps": udp_receiver,
        "udp_reported_jitter_ms": udp["receiver_jitter_ms"],
        "udp_reported_loss_pct": udp["receiver_loss_pct"],

        # ffmpeg target metadata.
        "ffmpeg_target_rate_mbps": ffmpeg_target,

        # Backward-compatible aliases for previously generated MASTER files.
        # They now mean the reference/offered Test load, NOT TCP achieved rate.
        "nominal_test_load_per_sta_mbps": reference,
        "nominal_test_load_aggregate_mbps": (2.0 * reference) if reference is not None else None,

        # Legacy raw names retained so existing analysis notebooks do not break.
        "tcp_sender_rate_mbps": tcp_sender,
        "tcp_receiver_rate_mbps": tcp_receiver,
        "udp_sender_rate_mbps": udp_sender,
        "udp_receiver_rate_mbps": udp_receiver,
    }


def read_csv(path: Path) -> List[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fields: List[str] = []
    seen = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fields.append(key)

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def augment_rows(rows: List[dict], load_meta: dict, test_dir: Path) -> List[dict]:
    out = []
    for row in rows:
        merged = dict(row)
        # Put traceability fields at the end so original v3 columns remain intact.
        merged.update(load_meta)
        merged["source_test_dir"] = str(test_dir)
        out.append(merged)
    return out


def phase_load_for_row(row: dict, load_meta: dict) -> Optional[float]:
    """
    Return the phase-specific rate descriptor per STA.

    IMPORTANT: this is not the same concept for all phases:
      * TCP  -> achieved sender throughput (congestion-controlled)
      * UDP  -> controlled offered sender rate
      * ffmpeg -> configured SDP target rate

    The common experimental x-axis is always stored separately in
    ``reference_load_per_sta_mbps``.
    """
    phase = row.get("phase", "")
    if phase == "iperf_tcp":
        return load_meta.get("tcp_achieved_sender_mbps")
    if phase == "iperf_udp":
        return load_meta.get("udp_offered_sender_mbps")
    if phase == "ffmpeg_udp":
        return load_meta.get("ffmpeg_target_rate_mbps")
    return None


def phase_rate_role(row: dict) -> Optional[str]:
    phase = row.get("phase", "")
    if phase == "iperf_tcp":
        return "achieved_tcp_sender_throughput"
    if phase == "iperf_udp":
        return "controlled_udp_offered_rate"
    if phase == "ffmpeg_udp":
        return "ffmpeg_sdp_target_rate"
    return None


def add_phase_specific_rate(rows: List[dict], load_meta: dict) -> None:
    for row in rows:
        rate = phase_load_for_row(row, load_meta)
        row["phase_rate_per_sta_mbps"] = rate
        row["phase_rate_aggregate_mbps"] = 2.0 * rate if rate is not None else None
        row["phase_rate_role"] = phase_rate_role(row)
        # Keep old column names as aliases for compatibility.
        row["phase_reference_rate_per_sta_mbps"] = rate
        row["phase_reference_rate_aggregate_mbps"] = (
            2.0 * rate if rate is not None else None
        )


# -----------------------------------------------------------------------------
# Batch processing
# -----------------------------------------------------------------------------

def process_one_test(
    test_dir: Path,
    out_dir: Path,
    tshark: str,
    server_ip: str,
    sta_ips: List[str],
    tolerance_pct: float,
    reuse_existing: bool = False,
) -> Tuple[dict, Dict[str, List[dict]]] :

    n = test_number(test_dir)
    test_out = out_dir / f"Test_{n:02d}"
    test_out.mkdir(parents=True, exist_ok=True)

    load_meta = build_test_load_metadata(test_dir, tolerance_pct)
    pcap = engine.discover_pcap(test_dir)

    required_existing = [
        test_out / "rtt_variation_summary.csv",
        test_out / "throughput_summary.csv",
        test_out / "log_validation.csv",
        test_out / "phase_windows.csv",
        test_out / "icmp_processes.csv",
    ]

    if reuse_existing and all(p.exists() for p in required_existing):
        print(f"REUSE {test_dir.name}: existing validated v3/v4 outputs found; PCAP not re-read.")
    else:
        engine.analyze(
            test_dir=test_dir,
            pcap=pcap,
            outdir=test_out,
            tshark=tshark,
            server_ip=server_ip,
            sta_ips=sta_ips,
        )

    # Load the compact outputs needed for paper-level master tables.
    rtt = read_csv(test_out / "rtt_variation_summary.csv")
    thr = read_csv(test_out / "throughput_summary.csv")
    logs = read_csv(test_out / "log_validation.csv")
    phases = read_csv(test_out / "phase_windows.csv")
    icmp = read_csv(test_out / "icmp_processes.csv")

    for rows in [rtt, thr, logs, phases, icmp]:
        add_phase_specific_rate(rows, load_meta)
        rows[:] = augment_rows(rows, load_meta, test_dir)

    index_row = {
        **engine.parse_config_from_path(test_dir),
        "test_number": n,
        "status": "PASS",
        "test_dir": str(test_dir),
        "pcap": str(pcap),
        **load_meta,
        "n_rtt_summary_rows": len(rtt),
        "n_throughput_summary_rows": len(thr),
        "output_dir": str(test_out),
    }

    return index_row, {
        "rtt": rtt,
        "throughput": thr,
        "logs": logs,
        "phases": phases,
        "icmp": icmp,
    }



def build_load_curve_rows(index_rows: List[dict]) -> List[dict]:
    """Compact Test-level table intended for plotting load/capacity behavior."""
    keep = [
        "mechanism", "band", "environment", "condition", "bandwidth_mhz",
        "test_number", "reference_load_per_sta_mbps",
        "reference_load_aggregate_mbps", "reference_load_source",
        "tcp_achieved_sender_mbps", "tcp_achieved_receiver_mbps",
        "tcp_sender_as_pct_of_reference", "tcp_receiver_as_pct_of_reference",
        "udp_offered_sender_mbps", "udp_achieved_receiver_mbps",
        "udp_reported_jitter_ms", "udp_reported_loss_pct",
        "ffmpeg_target_rate_mbps", "udp_ffmpeg_difference_pct",
        "load_resolution_status", "load_resolution_note",
    ]
    return [{k: row.get(k) for k in keep} for row in index_rows]


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Batch-process every Test N folder using the validated analyze_test_v4.py engine."
        )
    )
    ap.add_argument(
        "--root",
        required=True,
        type=Path,
        help='Folder containing Test 1, Test 2, ... e.g. "D:\\...\\Prueba_Siemens2"',
    )
    ap.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Batch output directory.",
    )
    ap.add_argument(
        "--tshark",
        default=None,
        help='Optional explicit path, e.g. "C:\\Program Files\\Wireshark\\tshark.exe"',
    )
    ap.add_argument("--server-ip", default=engine.DEFAULT_SERVER_IP)
    ap.add_argument(
        "--sta-ip",
        dest="sta_ips",
        action="append",
        default=None,
        help="STA IP. Supply twice to override defaults.",
    )
    ap.add_argument(
        "--load-match-tolerance-pct",
        type=float,
        default=2.0,
        help=(
            "Maximum relative difference between UDP sender reference rate and ffmpeg "
            "SDP target before the Test is flagged for inspection. TCP is not part of "
            "this consistency test. Default: 2%%."
        ),
    )
    ap.add_argument(
        "--reuse-existing",
        action="store_true",
        help=(
            "Reuse existing per-Test v3 outputs in --out when present. This avoids "
            "re-reading large PCAPs and is useful for regenerating MASTER files after "
            "metadata/load-interpretation changes."
        ),
    )
    ap.add_argument(
        "--only-tests",
        nargs="*",
        type=int,
        default=None,
        help="Optional test numbers to process, e.g. --only-tests 1 2 3",
    )

    args = ap.parse_args()

    root = args.root.resolve()
    out = args.out.resolve()

    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Root folder does not exist: {root}")

    sta_ips = args.sta_ips if args.sta_ips else list(engine.DEFAULT_STA_IPS)
    if len(sta_ips) != 2:
        raise SystemExit("Exactly two --sta-ip values are required for this study.")

    tshark = engine.find_tshark(args.tshark)
    tests = discover_test_dirs(root)

    if args.only_tests:
        wanted = set(args.only_tests)
        tests = [p for p in tests if test_number(p) in wanted]

    if not tests:
        raise SystemExit(f"No Test N folders found directly below: {root}")

    out.mkdir(parents=True, exist_ok=True)

    print("\n============================================================")
    print("iPCF-2 / WLAN BATCH ANALYSIS")
    print("============================================================")
    print(f"Root:   {root}")
    print(f"Output: {out}")
    print(f"Tests:  {', '.join(str(test_number(p)) for p in tests)}")
    print(f"TShark: {tshark}")
    print("============================================================\n")

    master_rtt: List[dict] = []
    master_thr: List[dict] = []
    master_logs: List[dict] = []
    master_phases: List[dict] = []
    master_icmp: List[dict] = []
    index_rows: List[dict] = []
    error_rows: List[dict] = []

    total = len(tests)

    for i, test_dir in enumerate(tests, start=1):
        n = test_number(test_dir)
        print(f"\n[{i}/{total}] Processing {test_dir.name}")
        print("-" * 60)

        try:
            index_row, data = process_one_test(
                test_dir=test_dir,
                out_dir=out,
                tshark=tshark,
                server_ip=args.server_ip,
                sta_ips=sta_ips,
                tolerance_pct=args.load_match_tolerance_pct,
                reuse_existing=args.reuse_existing,
            )

            index_rows.append(index_row)
            master_rtt.extend(data["rtt"])
            master_thr.extend(data["throughput"])
            master_logs.extend(data["logs"])
            master_phases.extend(data["phases"])
            master_icmp.extend(data["icmp"])

            print(
                f"PASS {test_dir.name}: reference load per STA = "
                f"{index_row['reference_load_per_sta_mbps']} Mbps; "
                f"TCP achieved={index_row['tcp_achieved_sender_mbps']} Mbps; "
                f"status={index_row['load_resolution_status']}"
            )

        except Exception as exc:
            print(f"FAIL {test_dir.name}: {exc}")
            error_rows.append({
                **engine.parse_config_from_path(test_dir),
                "test_number": n,
                "status": "FAIL",
                "test_dir": str(test_dir),
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "traceback": traceback.format_exc(),
            })

        # Persist cumulative master files after EVERY test so completed work is
        # not lost if the computer/repository/drive is interrupted later.
        write_csv(out / "MASTER_TEST_INDEX.csv", index_rows)
        write_csv(out / "MASTER_LOAD_CURVE.csv", build_load_curve_rows(index_rows))
        write_csv(out / "MASTER_RTT_VARIATION.csv", master_rtt)
        write_csv(out / "MASTER_THROUGHPUT.csv", master_thr)
        write_csv(out / "MASTER_LOG_VALIDATION.csv", master_logs)
        write_csv(out / "MASTER_PHASE_WINDOWS.csv", master_phases)
        write_csv(out / "MASTER_ICMP_PROCESSES.csv", master_icmp)
        write_csv(out / "BATCH_ERRORS.csv", error_rows)

    # Human-readable QC summary.
    qc = out / "BATCH_QC_REPORT.txt"
    with qc.open("w", encoding="utf-8") as f:
        f.write("iPCF-2 / WLAN batch QC report\n")
        f.write("================================\n\n")
        f.write(f"Root: {root}\n")
        f.write(f"Processed tests: {len(index_rows)}\n")
        f.write(f"Failed tests: {len(error_rows)}\n\n")

        f.write("Successful tests / reference loads and achieved rates\n")
        f.write("---------------------------------\n")
        for row in index_rows:
            f.write(
                f"Test {row['test_number']}: "
                f"reference_per_sta={row['reference_load_per_sta_mbps']} Mbps; "
                f"reference_source={row['reference_load_source']}; "
                f"TCP_achieved_sender={row['tcp_achieved_sender_mbps']} Mbps; "
                f"UDP_offered_sender={row['udp_offered_sender_mbps']} Mbps; "
                f"UDP_achieved_receiver={row['udp_achieved_receiver_mbps']} Mbps; "
                f"UDP_loss={row['udp_reported_loss_pct']}%; "
                f"ffmpeg_target={row['ffmpeg_target_rate_mbps']} Mbps; "
                f"status={row['load_resolution_status']}\n"
            )
            if row.get("load_resolution_note"):
                f.write(f"  {row['load_resolution_note']}\n")

        if error_rows:
            f.write("\nFailed tests\n")
            f.write("------------\n")
            for row in error_rows:
                f.write(
                    f"Test {row['test_number']}: {row['error_type']}: "
                    f"{row['error_message']}\n"
                )

        f.write("\nDefinitions used\n")
        f.write("----------------\n")
        f.write("RTT_i = 1000 * (t_reply - t_request) [ms]\n")
        f.write("J_i = |RTT_i - RTT_(i-1)| within same ICMP process\n")
        f.write("Q_q = x_(ceil(q*N)) [nearest-rank / inverse ECDF]\n")
        f.write("Throughput = transport/application payload bits observed / time\n")
        f.write("Reference load per STA is taken from rate-controlled UDP sender rate; ffmpeg target is a consistency check.\nTCP sender/receiver rates are retained as achieved throughput and may plateau under saturation.\n")

    print("\n============================================================")
    print("BATCH COMPLETE")
    print("============================================================")
    print(f"PASS: {len(index_rows)}")
    print(f"FAIL: {len(error_rows)}")
    print(f"Master output: {out}")
    print("\nKey files:")
    for name in [
        "MASTER_TEST_INDEX.csv",
        "MASTER_LOAD_CURVE.csv",
        "MASTER_RTT_VARIATION.csv",
        "MASTER_THROUGHPUT.csv",
        "MASTER_LOG_VALIDATION.csv",
        "BATCH_ERRORS.csv",
        "BATCH_QC_REPORT.txt",
    ]:
        print(f"  - {name}")


if __name__ == "__main__":
    main()
