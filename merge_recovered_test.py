#!/usr/bin/env python3
"""Integrate one recovered Test output into an existing ALL_SN_RESULTS_FINAL tree.

This script does NOT re-read the PCAP. It:
  1) copies recovered compact CSV/TXT outputs into the target per-configuration Test_N folder;
  2) rebuilds that configuration's compact MASTER files with analyze_folder_batch_v4.py
     using --reuse-existing and --only-tests N;
  3) rebuilds the global MASTER_ALL_SN* CSVs from existing per-configuration masters;
  4) updates MASTER_ALL_SN_CONFIG_STATUS.csv and QC summary;
  5) creates a backup of global master files before patching.

Expected companion files in the same folder:
  analyze_test_v4.py
  analyze_folder_batch_v4.py
  analyze_all_sn_v3.py
"""
from __future__ import annotations
import argparse, csv, shutil, subprocess, sys
from pathlib import Path
from datetime import datetime

COMPACT_FILES = [
    "phase_windows.csv",
    "icmp_processes.csv",
    "rtt_samples.csv",
    "rtt_variation_samples.csv",
    "rtt_variation_summary.csv",
    "throughput_1s.csv",
    "throughput_summary.csv",
    "log_validation.csv",
    "qc_report.txt",
]

GLOBAL_PREFIXES = ("MASTER_ALL_SN",)


def read_csv(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields=[]
    seen=set()
    for r in rows:
        for k in r.keys():
            if k not in seen:
                fields.append(k); seen.add(k)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w=csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--all-results", required=True, type=Path,
                    help="Existing ALL_SN_RESULTS_FINAL directory")
    ap.add_argument("--recovered", required=True, type=Path,
                    help="Recovered single-Test output directory from analyze_test_v5.py")
    ap.add_argument("--config-name", required=True,
                    help="e.g. iWLAN_5GHz_Lab_SN_BW40MHz")
    ap.add_argument("--test-number", required=True, type=int)
    ap.add_argument("--test-root", required=True, type=Path,
                    help="Raw configuration Test container, e.g. D:\\...\\Prueba_Siemens2")
    ap.add_argument("--tshark", required=True)
    args=ap.parse_args()

    script_dir=Path(__file__).resolve().parent
    folder_script=script_dir/"analyze_folder_batch_v4.py"
    all_script=script_dir/"analyze_all_sn_v3.py"
    test_script=script_dir/"analyze_test_v4.py"
    for p in (folder_script, all_script, test_script):
        if not p.exists():
            raise SystemExit(f"Missing companion script: {p}")

    all_root=args.all_results.resolve()
    rec=args.recovered.resolve()
    if not all_root.is_dir(): raise SystemExit(f"ALL results directory not found: {all_root}")
    if not rec.is_dir(): raise SystemExit(f"Recovered directory not found: {rec}")

    missing=[f for f in COMPACT_FILES if not (rec/f).exists()]
    if missing: raise SystemExit("Recovered directory is incomplete. Missing: " + ", ".join(missing))

    config_out=all_root/"per_configuration"/args.config_name
    test_out=config_out/f"Test_{args.test_number:02d}"
    config_out.mkdir(parents=True, exist_ok=True)
    test_out.mkdir(parents=True, exist_ok=True)

    # Backup global masters only (small files, no bulky per-Test CSVs).
    stamp=datetime.now().strftime("%Y%m%d_%H%M%S")
    backup=all_root/f"_backup_before_recovery_{stamp}"
    backup.mkdir(parents=True, exist_ok=True)
    for p in all_root.iterdir():
        if p.is_file() and (p.name.startswith("MASTER_ALL_SN") or p.name=="MASTER_ALL_SN.csv"):
            shutil.copy2(p, backup/p.name)
    print(f"Backup created: {backup}")

    # Copy recovered outputs into canonical Test_N directory.
    for f in COMPACT_FILES:
        shutil.copy2(rec/f, test_out/f)
    print(f"Recovered outputs copied to: {test_out}")

    # Rebuild only this configuration master using existing recovered compact files.
    # discover_pcap may see the truncated PCAP, but --reuse-existing prevents TShark from reading it.
    cmd=[sys.executable, str(folder_script),
         "--root", str(args.test_root),
         "--out", str(config_out),
         "--tshark", args.tshark,
         "--only-tests", str(args.test_number),
         "--reuse-existing"]
    print("\nRebuilding recovered configuration master WITHOUT reading PCAP:")
    print("  " + " ".join(f'\"{x}\"' if " " in x else x for x in cmd))
    subprocess.run(cmd, check=True)

    # Import the global merge functions from the already-validated master script.
    sys.path.insert(0, str(script_dir))
    import analyze_all_sn_v3 as master

    results_sources=[]
    per_root=all_root/"per_configuration"
    for d in sorted([p for p in per_root.iterdir() if p.is_dir()], key=lambda x:x.name.lower()):
        # Include only configurations with a non-empty PASS index and compact masters.
        idx=read_csv(d/"MASTER_TEST_INDEX.csv")
        required=[d/"MASTER_LOAD_CURVE.csv", d/"MASTER_RTT_VARIATION.csv", d/"MASTER_THROUGHPUT.csv"]
        if idx and all(p.exists() for p in required):
            # config_metadata parses the folder name; the actual raw config directory is not needed for merging.
            meta=master.config_metadata(Path(d.name))
            results_sources.append((d, meta))

    counts=master.merge_all(results_sources, all_root)

    # Patch config-status row for the recovered configuration; preserve other rows.
    status_path=all_root/"MASTER_ALL_SN_CONFIG_STATUS.csv"
    status=read_csv(status_path)
    new_status=[]
    replaced=False
    idx_rows=read_csv(config_out/"MASTER_TEST_INDEX.csv")
    meta=master.config_metadata(Path(args.config_name))
    for r in status:
        if (r.get("configuration_name") or "").lower()==args.config_name.lower():
            nr=dict(r)
            nr.update(meta)
            nr.update({
                "status":"PASS",
                "processing_mode":"RECOVERED_PARTIAL_CAPTURE_NO_PCAP_REREAD",
                "test_container":str(args.test_root),
                "results_dir":str(config_out),
                "n_tests":str(len(idx_rows)),
                "error_type":"",
                "error_message":"",
            })
            new_status.append(nr); replaced=True
        else:
            new_status.append(r)
    if not replaced:
        new_status.append({**meta,
            "status":"PASS",
            "processing_mode":"RECOVERED_PARTIAL_CAPTURE_NO_PCAP_REREAD",
            "source_config_dir":str(args.test_root.parent),
            "test_container":str(args.test_root),
            "results_dir":str(config_out),
            "n_tests":str(len(idx_rows)),
            "error_type":"", "error_message":""})
    new_status.sort(key=lambda r:(r.get("configuration_name") or "").lower())
    write_csv(status_path,new_status)

    # Updated lightweight QC report.
    n_pass=sum(1 for r in new_status if (r.get("status") or "").upper()=="PASS")
    n_fail=sum(1 for r in new_status if (r.get("status") or "").upper()=="FAIL")
    qc=all_root/"MASTER_ALL_SN_QC_REPORT.txt"
    with qc.open("w",encoding="utf-8") as f:
        f.write("MASTER SN QC REPORT - AFTER RECOVERY PATCH\n")
        f.write("==========================================\n\n")
        f.write(f"Configurations PASS: {n_pass}\n")
        f.write(f"Configurations FAIL: {n_fail}\n")
        f.write(f"Recovered configuration: {args.config_name}\n")
        f.write(f"Recovered Test: {args.test_number}\n")
        f.write("Recovery status: USABLE_PARTIAL_CAPTURE\n")
        f.write("QC note: PARTIAL_CAPTURE_TRUNCATED_AFTER_EXPERIMENT_END\n")
        f.write("No previously analyzed PCAP was re-read during this integration.\n\n")
        f.write("Merged row counts:\n")
        for k in sorted(counts): f.write(f"  {k}: {counts[k]}\n")
        f.write("\nConfiguration status:\n")
        for r in new_status:
            f.write(f"  {r.get('configuration_name')}: {r.get('status')} (n_tests={r.get('n_tests','')})\n")

    print("\nDONE")
    print(f"Global masters rebuilt from existing compact CSVs only: {all_root}")
    print(f"Configurations PASS={n_pass}, FAIL={n_fail}")
    print(f"Recovered configuration tests in master: {len(idx_rows)}")
    print("No previously processed PCAP was re-read.")

if __name__=="__main__":
    main()
