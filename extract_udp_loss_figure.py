import csv

FILE = r"ALL_SN_RESULTS_FINAL\MASTER_ALL_SN_RTT_VARIATION.csv"

rows = {}

with open(FILE, encoding="utf-8-sig", newline="") as f:
    for r in csv.DictReader(f):

        if r["band"] != "5GHz":
            continue
        if r["environment"] != "CamAne":
            continue
        if r["condition"] != "SN":
            continue

        # We only need one representative row per test/configuration,
        # because the iperf3 UDP loss summary is repeated across the
        # phase/probe rows belonging to that test.
        try:
            load = float(r["reference_load_per_sta_mbps"])
            bw = int(float(r["bandwidth_mhz"]))
            loss = float(r["udp_reported_loss_pct"])
        except:
            continue

        mode = r["operating_mode"]
        test = r["test"]

        key = (mode, bw, test, load)

        if key not in rows:
            rows[key] = loss


result = []

for (mode, bw, test, load), loss in rows.items():
    result.append((bw, mode, load, loss, test))


result.sort(
    key=lambda x: (
        x[0],
        x[1],
        x[2]
    )
)


current = None

for bw, mode, load, loss, test in result:

    header = (bw, mode)

    if header != current:

        print()
        print("=" * 72)
        print(f"UDP LOSS | {bw} MHz | {mode}")
        print("=" * 72)

        current = header

    print(
        f"({load:g},{loss:.6f})"
        f"    # Test {test}"
    )
