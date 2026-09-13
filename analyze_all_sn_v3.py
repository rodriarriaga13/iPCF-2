#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
analyze_all_sn_v3.py
=================

Top-level batch runner for the stationary no-interference (SN) dataset.

It discovers every top-level configuration folder matching:

    iPCF2_*_SN_BW*MHz
    iWLAN_*_SN_BW*MHz

under the SSD root (for example D:\), finds the directory that directly
contains Test 1, Test 2, ... inside each configuration, runs the validated
`analyze_folder_batch_v4.py` workflow, and finally merges the per-configuration
MASTER CSVs into study-wide MASTER_ALL_SN files.

Scientific conventions inherited from the validated analyzers
---------------------------------------------------------------
* RTT_i = 1000 * (t_reply - t_request) [ms]
* RTT variation J_i = |RTT_i - RTT_(i-1)| within the same ICMP process
* Quantiles use nearest-rank / inverse ECDF: Q_q = x_(ceil(q*N))
* Reference load per STA comes from the rate-controlled UDP sender rate
* TCP sender/receiver rates are achieved throughput, not offered load
* Only SN configurations are included by this script. CN is deliberately ignored.
* Test numbers are load levels, NOT independent experimental repetitions.

Required files in the same directory as this script
----------------------------------------------------
    analyze_test_v4.py
    analyze_folder_batch_v4.py

Example
-------
py .\analyze_all_sn_v3.py `
  --ssd-root "D:\\" `
  --out "C:\\Users\\rarriaga\\Documents\\ipcf_2 analisis\\ALL_SN_RESULTS" `
  --tshark "C:\\Program Files\\Wireshark\\tshark.exe" `
  --existing-results-root "C:\\Users\\rarriaga\\Documents\\ipcf_2 analisis"

The --existing-results-root option lets the script reuse an already-completed
folder such as:

    results_iPCF2_5GHz_CamAne_SN_BW20MHz

instead of processing its PCAPs again.
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


CONFIG_RE = re.compile(
    r"^(iPCF2|iWLAN)_(24GHz|5GHz)_(CamAne|Lab)_SN_BW(\d+)MHz$",
    re.IGNORECASE,
)
TEST_RE = re.compile(r"^Test\s*(\d+)$", re.IGNORECASE)

PER_CONFIG_MASTER_FILES = [
    "MASTER_TEST_INDEX.csv",
    "MASTER_LOAD_CURVE.csv",
    "MASTER_RTT_VARIATION.csv",
    "MASTER_THROUGHPUT.csv",
    "MASTER_LOG_VALIDATION.csv",
    "MASTER_PHASE_WINDOWS.csv",
    "MASTER_ICMP_PROCESSES.csv",
    "BATCH_ERRORS.csv",
]

MERGE_MAP = {
    "MASTER_TEST_INDEX.csv": "MASTER_ALL_SN_TESTS.csv",
    "MASTER_LOAD_CURVE.csv": "MASTER_ALL_SN_LOAD_CURVE.csv",
    "MASTER_RTT_VARIATION.csv": "MASTER_ALL_SN_RTT_VARIATION.csv",
    "MASTER_THROUGHPUT.csv": "MASTER_ALL_SN_THROUGHPUT.csv",
    "MASTER_LOG_VALIDATION.csv": "MASTER_ALL_SN_LOG_VALIDATION.csv",
    "MASTER_PHASE_WINDOWS.csv": "MASTER_ALL_SN_PHASE_WINDOWS.csv",
    "MASTER_ICMP_PROCESSES.csv": "MASTER_ALL_SN_ICMP_PROCESSES.csv",
    "BATCH_ERRORS.csv": "MASTER_ALL_SN_ERRORS.csv",
}


def read_csv(path: Path) -> List[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fields: List[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fields.append(key)

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def config_metadata(config_dir: Path) -> dict:
    m = CONFIG_RE.fullmatch(config_dir.name)
    if not m:
        return {}
    mechanism = m.group(1)
    return {
        "configuration_name": config_dir.name,
        "mechanism": mechanism,
        "operating_mode": "iPCF2_ON" if mechanism.lower() == "ipcf2" else "iPCF2_OFF_iWLAN",
        "band": m.group(2),
        "environment": m.group(3),
        "condition": "SN",
        "bandwidth_mhz": m.group(4),
    }


def discover_config_dirs(ssd_root: Path) -> List[Path]:
    configs = []
    for p in ssd_root.iterdir():
        if p.is_dir() and CONFIG_RE.fullmatch(p.name):
            configs.append(p)
    return sorted(configs, key=lambda p: p.name.lower())


def test_number_from_name(name: str) -> Optional[int]:
    m = TEST_RE.fullmatch(name)
    return int(m.group(1)) if m else None


def test_has_pcap(test_dir: Path) -> bool:
    """Return True only if this Test directory contains a raw PCAP/PCAPNG.

    We intentionally inspect only the common shallow capture locations. This
    prevents folders such as ``Cliente1/Test 0`` or ``Cliente1/Test 1`` from
    being mistaken for the experiment root when they contain client-side logs
    but no packet capture.
    """
    try:
        # Common layout: Test N/pcap/rep_1.pcap
        for child in test_dir.iterdir():
            if not child.is_dir():
                continue
            if child.name.lower() in {"pcap", "pcaps", "capture", "captures"}:
                try:
                    if any(
                        f.is_file() and f.suffix.lower() in {".pcap", ".pcapng"}
                        for f in child.iterdir()
                    ):
                        return True
                except (OSError, PermissionError):
                    pass

        # Conservative fallback: a capture directly inside Test N.
        if any(
            f.is_file() and f.suffix.lower() in {".pcap", ".pcapng"}
            for f in test_dir.iterdir()
        ):
            return True
    except (OSError, PermissionError):
        return False
    return False


def direct_test_stats(path: Path) -> Tuple[int, int, List[str]]:
    """Return (valid_tests_with_pcap, numbered_tests>=1, diagnostics)."""
    valid = 0
    numbered = 0
    diag: List[str] = []
    try:
        children = list(path.iterdir())
    except (OSError, PermissionError):
        return 0, 0, diag

    for p in children:
        if not p.is_dir():
            continue
        n = test_number_from_name(p.name)
        if n is None or n < 1:
            continue
        numbered += 1
        has_capture = test_has_pcap(p)
        if has_capture:
            valid += 1
        diag.append(f"{p.name}: {'PCAP_OK' if has_capture else 'NO_PCAP'}")
    return valid, numbered, diag


def find_test_container(config_dir: Path, max_depth: int = 3) -> Path:
    """Find the *experimental* directory that directly contains Test N folders.

    A candidate is accepted only when at least one ``Test N`` (N>=1) contains
    a PCAP/PCAPNG.  This is deliberately stricter than merely counting folders
    named ``Test 0``/``Test 1`` because some configurations also contain
    auxiliary client branches such as ``Cliente1`` that are not the capture
    source.

    Candidates are ranked by:
      1. largest number of Test N folders that actually contain PCAPs;
      2. largest total number of numbered Test N folders;
      3. shallower depth;
      4. preference for names containing ``prueba``/``siemens``.
    """
    candidates: List[Tuple[int, int, int, int, Path]] = []
    inspected: List[str] = []
    frontier: List[Tuple[Path, int]] = [(config_dir, 0)]

    while frontier:
        current, depth = frontier.pop(0)
        valid, numbered, diag = direct_test_stats(current)
        if numbered:
            inspected.append(
                f"{current} -> numbered={numbered}, with_pcap={valid}; " + ", ".join(diag)
            )
        if valid > 0:
            lname = current.name.lower()
            preferred = 1 if ("prueba" in lname or "siemens" in lname) else 0
            candidates.append((-valid, -numbered, depth, -preferred, current))
            # A real Test container should not be traversed into its Test dirs.
            continue

        if depth >= max_depth:
            continue

        try:
            children = [p for p in current.iterdir() if p.is_dir()]
        except (OSError, PermissionError):
            continue

        for child in children:
            if TEST_RE.fullmatch(child.name):
                continue
            lname = child.name.lower()
            if lname.startswith("results") or lname in {"pcap", "pcaps", "__pycache__"}:
                continue
            frontier.append((child, depth + 1))

    if not candidates:
        details = "\n  ".join(inspected) if inspected else "(no Test N folders found)"
        raise FileNotFoundError(
            f"Could not find an experimental Test container with PCAP files below {config_dir} "
            f"within depth {max_depth}. Candidates inspected:\n  {details}"
        )

    candidates.sort(key=lambda x: (x[0], x[1], x[2], x[3], str(x[4]).lower()))
    return candidates[0][4]

def completed_results_dir(path: Path) -> bool:
    required = [
        path / "MASTER_TEST_INDEX.csv",
        path / "MASTER_LOAD_CURVE.csv",
        path / "MASTER_RTT_VARIATION.csv",
        path / "MASTER_THROUGHPUT.csv",
        path / "BATCH_QC_REPORT.txt",
    ]
    if not all(p.exists() for p in required):
        return False

    index = read_csv(path / "MASTER_TEST_INDEX.csv")
    if not index:
        return False
    return all((r.get("status") or "").upper() == "PASS" for r in index)


def find_existing_results(existing_root: Optional[Path], config_name: str) -> Optional[Path]:
    if existing_root is None or not existing_root.exists():
        return None

    exact_candidates = [
        existing_root / f"results_{config_name}",
        existing_root / config_name,
    ]
    for p in exact_candidates:
        if p.is_dir() and completed_results_dir(p):
            return p

    # Also allow already-created config subfolders below ALL_SN_RESULTS.
    for p in existing_root.iterdir():
        if p.is_dir() and p.name.lower() in {
            f"results_{config_name}".lower(), config_name.lower()
        } and completed_results_dir(p):
            return p
    return None


def run_folder_batch(
    batch_script: Path,
    test_root: Path,
    config_out: Path,
    tshark: str,
    python_exe: str,
    reuse_existing: bool,
    tolerance_pct: float,
) -> None:
    cmd = [
        python_exe,
        str(batch_script),
        "--root", str(test_root),
        "--out", str(config_out),
        "--tshark", tshark,
        "--load-match-tolerance-pct", str(tolerance_pct),
    ]
    if reuse_existing:
        cmd.append("--reuse-existing")

    print("COMMAND:")
    print("  " + " ".join(f'\"{x}\"' if " " in x else x for x in cmd))
    subprocess.run(cmd, check=True)


def add_global_traceability(rows: Iterable[dict], meta: dict, results_dir: Path) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        merged = dict(row)
        # Preserve the analyzer's original columns, then append global traceability.
        merged["configuration_name"] = meta.get("configuration_name", "")
        merged["operating_mode"] = meta.get("operating_mode", "")
        merged["global_results_dir"] = str(results_dir)
        out.append(merged)
    return out


def merge_all(results_sources: List[Tuple[Path, dict]], out_root: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {}

    for source_name, target_name in MERGE_MAP.items():
        rows: List[dict] = []
        for results_dir, meta in results_sources:
            rows.extend(add_global_traceability(read_csv(results_dir / source_name), meta, results_dir))

        # Stable scientific ordering when columns are available.
        def sort_key(r: dict):
            mech = (r.get("mechanism") or "").lower()
            band = r.get("band") or ""
            env = r.get("environment") or ""
            try:
                bw = int(float(r.get("bandwidth_mhz") or 0))
            except ValueError:
                bw = 0
            try:
                test = int(float(r.get("test_number") or r.get("test") or 0))
            except ValueError:
                test = 0
            phase = r.get("phase") or ""
            try:
                probe = float(r.get("probe_interval_s") or 0)
            except ValueError:
                probe = 0.0
            sta = r.get("sta_ip") or ""
            return (mech, band, env, bw, test, phase, probe, sta)

        rows.sort(key=sort_key)
        write_csv(out_root / target_name, rows)
        counts[target_name] = len(rows)

    # User-facing primary master: one row per Test/configuration. This is an
    # explicit alias of the global test index rather than mixing incompatible
    # RTT/throughput row granularities in one table.
    test_rows = read_csv(out_root / "MASTER_ALL_SN_TESTS.csv")
    write_csv(out_root / "MASTER_ALL_SN.csv", test_rows)
    counts["MASTER_ALL_SN.csv"] = len(test_rows)

    return counts


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Process and merge all stationary no-interference (SN) iPCF2/iWLAN configurations."
    )
    ap.add_argument("--ssd-root", required=True, type=Path, help='SSD root, e.g. "D:\\"')
    ap.add_argument("--out", required=True, type=Path, help="Global output directory.")
    ap.add_argument(
        "--tshark", required=True,
        help='Explicit tshark path, e.g. "C:\\Program Files\\Wireshark\\tshark.exe"',
    )
    ap.add_argument(
        "--existing-results-root", type=Path, default=None,
        help=(
            "Optional folder containing previously completed results_<configuration> directories. "
            "Completed configurations are reused without re-reading their PCAPs."
        ),
    )
    ap.add_argument(
        "--python-exe", default=sys.executable,
        help="Python executable used to launch analyze_folder_batch_v4.py. Default: current interpreter.",
    )
    ap.add_argument(
        "--load-match-tolerance-pct", type=float, default=2.0,
        help="UDP-vs-ffmpeg target consistency tolerance. Default: 2%%.",
    )
    ap.add_argument(
        "--only-config", action="append", default=None,
        help="Optional exact configuration folder name. May be supplied multiple times.",
    )
    ap.add_argument(
        "--skip-config", action="append", default=None,
        help="Optional exact configuration folder name to skip. May be supplied multiple times.",
    )
    ap.add_argument(
        "--max-search-depth", type=int, default=3,
        help="Maximum depth below each configuration when locating the Test container. Default: 3.",
    )
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    batch_script = script_dir / "analyze_folder_batch_v4.py"
    engine_script = script_dir / "analyze_test_v4.py"
    if not batch_script.exists() or not engine_script.exists():
        raise SystemExit(
            "Place analyze_all_sn_v3.py, analyze_folder_batch_v4.py and analyze_test_v4.py "
            "in the same folder before running this script."
        )

    ssd_root = args.ssd_root.resolve()
    out_root = args.out.resolve()
    existing_root = args.existing_results_root.resolve() if args.existing_results_root else None

    if not ssd_root.exists() or not ssd_root.is_dir():
        raise SystemExit(f"SSD root does not exist: {ssd_root}")

    configs = discover_config_dirs(ssd_root)
    if args.only_config:
        wanted = {x.lower() for x in args.only_config}
        configs = [p for p in configs if p.name.lower() in wanted]
    if args.skip_config:
        skipped = {x.lower() for x in args.skip_config}
        configs = [p for p in configs if p.name.lower() not in skipped]

    if not configs:
        raise SystemExit(
            f"No top-level SN configuration folders matching iPCF2/iWLAN naming were found in {ssd_root}"
        )

    out_root.mkdir(parents=True, exist_ok=True)
    per_config_root = out_root / "per_configuration"
    per_config_root.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 72)
    print("MASTER SN ANALYSIS - iPCF-2 ON vs iWLAN / iPCF-2 OFF")
    print("=" * 72)
    print(f"SSD root: {ssd_root}")
    print(f"Global output: {out_root}")
    print(f"Configurations found: {len(configs)}")
    for p in configs:
        print(f"  - {p.name}")
    print("CN folders are intentionally ignored.")
    print("=" * 72 + "\n")

    status_rows: List[dict] = []
    results_sources: List[Tuple[Path, dict]] = []

    for idx, config_dir in enumerate(configs, start=1):
        meta = config_metadata(config_dir)
        print("\n" + "#" * 72)
        print(f"[{idx}/{len(configs)}] {config_dir.name}")
        print("#" * 72)

        try:
            test_root = find_test_container(config_dir, max_depth=args.max_search_depth)
            print(f"Test container: {test_root}")

            existing = find_existing_results(existing_root, config_dir.name)
            if existing is not None:
                results_dir = existing
                mode = "REUSED_EXISTING_COMPLETE_RESULTS"
                print(f"REUSE COMPLETE CONFIGURATION: {results_dir}")
            else:
                results_dir = per_config_root / config_dir.name
                # If a prior interrupted run already generated some Test outputs
                # in this global output, reuse those per-Test files and continue.
                reuse_partial = results_dir.exists()
                run_folder_batch(
                    batch_script=batch_script,
                    test_root=test_root,
                    config_out=results_dir,
                    tshark=args.tshark,
                    python_exe=args.python_exe,
                    reuse_existing=reuse_partial,
                    tolerance_pct=args.load_match_tolerance_pct,
                )
                mode = "PROCESSED_WITH_PARTIAL_REUSE" if reuse_partial else "PROCESSED_FROM_PCAP"

            if not completed_results_dir(results_dir):
                raise RuntimeError(
                    f"Configuration batch finished but required PASS master outputs are incomplete: {results_dir}"
                )

            idx_rows = read_csv(results_dir / "MASTER_TEST_INDEX.csv")
            results_sources.append((results_dir, meta))
            status_rows.append({
                **meta,
                "status": "PASS",
                "processing_mode": mode,
                "source_config_dir": str(config_dir),
                "test_container": str(test_root),
                "results_dir": str(results_dir),
                "n_tests": len(idx_rows),
                "error_type": "",
                "error_message": "",
            })
            print(f"PASS {config_dir.name}: {len(idx_rows)} tests available for global merge.")

        except Exception as exc:
            print(f"FAIL {config_dir.name}: {exc}")
            status_rows.append({
                **meta,
                "status": "FAIL",
                "processing_mode": "",
                "source_config_dir": str(config_dir),
                "test_container": "",
                "results_dir": "",
                "n_tests": 0,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "traceback": traceback.format_exc(),
            })

        # Persist configuration status after every configuration.
        write_csv(out_root / "MASTER_ALL_SN_CONFIG_STATUS.csv", status_rows)
        # Rebuild global masters after every successful configuration so an
        # interrupted long run retains all completed merged results.
        if results_sources:
            merge_all(results_sources, out_root)

    counts = merge_all(results_sources, out_root) if results_sources else {}

    n_pass = sum(1 for r in status_rows if r.get("status") == "PASS")
    n_fail = sum(1 for r in status_rows if r.get("status") == "FAIL")

    qc_path = out_root / "MASTER_ALL_SN_QC_REPORT.txt"
    with qc_path.open("w", encoding="utf-8") as f:
        f.write("MASTER ALL SN QC REPORT\n")
        f.write("=======================\n\n")
        f.write(f"SSD root: {ssd_root}\n")
        f.write(f"Configurations discovered: {len(configs)}\n")
        f.write(f"Configurations PASS: {n_pass}\n")
        f.write(f"Configurations FAIL: {n_fail}\n")
        f.write("CN configurations: excluded by design\n\n")

        f.write("Configuration status\n")
        f.write("--------------------\n")
        for r in status_rows:
            f.write(
                f"{r.get('configuration_name')}: {r.get('status')}; "
                f"mode={r.get('processing_mode')}; tests={r.get('n_tests')}; "
                f"results={r.get('results_dir')}\n"
            )
            if r.get("error_message"):
                f.write(f"  ERROR: {r.get('error_type')}: {r.get('error_message')}\n")

        f.write("\nMerged row counts\n")
        f.write("-----------------\n")
        for name, n in counts.items():
            f.write(f"{name}: {n}\n")

        f.write("\nScientific definitions / scope\n")
        f.write("------------------------------\n")
        f.write("Only *_SN_* configurations are included. *_CN_* folders are not processed.\n")
        f.write("Test N denotes an offered-load level, not an independent experimental repetition.\n")
        f.write("Reference load per STA is the rate-controlled UDP sender rate; ffmpeg target is a consistency check.\n")
        f.write("TCP sender/receiver rates are achieved throughput and may plateau under saturation.\n")
        f.write("RTT_i = 1000*(t_reply-t_request) ms.\n")
        f.write("RTT variation J_i = |RTT_i-RTT_(i-1)| within the same ICMP process.\n")
        f.write("Quantiles use nearest-rank Q_q=x_(ceil(q*N)).\n")

    print("\n" + "=" * 72)
    print("MASTER SN BATCH COMPLETE")
    print("=" * 72)
    print(f"Configurations PASS: {n_pass}")
    print(f"Configurations FAIL: {n_fail}")
    print(f"Output: {out_root}")
    print("\nPrimary files:")
    for name in [
        "MASTER_ALL_SN.csv",
        "MASTER_ALL_SN_TESTS.csv",
        "MASTER_ALL_SN_LOAD_CURVE.csv",
        "MASTER_ALL_SN_RTT_VARIATION.csv",
        "MASTER_ALL_SN_THROUGHPUT.csv",
        "MASTER_ALL_SN_ERRORS.csv",
        "MASTER_ALL_SN_CONFIG_STATUS.csv",
        "MASTER_ALL_SN_QC_REPORT.txt",
    ]:
        print(f"  - {name}")

    if n_fail:
        print("\nWARNING: At least one configuration failed. Inspect MASTER_ALL_SN_CONFIG_STATUS.csv before using the global dataset for publication.")


if __name__ == "__main__":
    main()
