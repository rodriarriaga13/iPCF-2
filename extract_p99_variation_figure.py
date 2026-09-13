import csv
from collections import defaultdict

FILE = r"ALL_SN_RESULTS_FINAL\MASTER_ALL_SN_RTT_VARIATION.csv"

groups = defaultdict(list)

with open(FILE, encoding="utf-8-sig", newline="") as f:
    for r in csv.DictReader(f):

        if r["band"] != "5GHz":
            continue

        if r["environment"] != "CamAne":
            continue

        if r["condition"] != "SN":
            continue

        try:
            if abs(float(r["probe_interval_s"]) - 0.05) > 1e-9:
                continue
        except:
            continue

        phase = r["phase"].lower()

        if "ffmpeg" in phase:
            workload = "FFMPEG"
        elif "tcp" in phase:
            workload = "TCP"
        elif "udp" in phase:
            workload = "UDP"
        else:
            continue

        try:
            load = float(r["reference_load_per_sta_mbps"])
            p99var = float(r["variation_P99"])
            bw = int(float(r["bandwidth_mhz"]))
        except:
            continue

        mode = r["operating_mode"]

        key = (workload, mode, bw, load)
        groups[key].append(p99var)


result = []

for (workload, mode, bw, load), values in groups.items():

    worst = max(values)

    result.append(
        (workload, mode, bw, load, worst, len(values))
    )


result.sort(
    key=lambda x: (
        {"TCP":0, "UDP":1, "FFMPEG":2}[x[0]],
        x[2],
        x[1],
        x[3]
    )
)


current = None

for workload, mode, bw, load, worst, nsta in result:

    header = (workload, bw, mode)

    if header != current:

        print()
        print("=" * 72)
        print(f"{workload} | {bw} MHz | {mode}")
        print("=" * 72)

        current = header

    print(
        f"({load:g},{worst:.6f})"
        f"    # n_STA={nsta}"
    )
