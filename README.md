# iPCF-2 Experimental Dataset and Analysis

This repository contains the analysis scripts, processed datasets, experimental metadata,
and figure-generation utilities associated with the study:

**Experimental Characterization of the Deterministic Performance of Siemens iPCF-2 and Standard Wi-Fi 6 in a Stationary Industrial WLAN**

The experiments compare Siemens iPCF-2 enabled operation with standard iWLAN operation
on the same IEEE 802.11ax industrial hardware platform.

## Experimental scope

The experimental topology consists of:

- 1 Siemens access point (AP)
- 2 simultaneously active Siemens stations (STAs)
- stationary uplink operation
- 2.4 GHz and 5 GHz frequency bands
- 20, 40, and 80 MHz channel bandwidths, where supported
- TCP traffic generated with iperf3
- rate-controlled UDP traffic generated with iperf3
- H.264 multimedia traffic transported over RTP/UDP using ffmpeg
- concurrent ICMP RTT measurements

The principal comparison reported in the manuscript uses the SN dataset,
corresponding to experiments without intentionally injected interference.

## Repository structure

```text
.
├── README.md
├── scripts/
│   ├── analyze_test_v4.py
│   ├── analyze_test_v5.py
│   ├── analyze_folder_batch_v4.py
│   ├── analyze_all_sn_v3.py
│   ├── merge_recovered_test.py
│   ├── extract_p99_figure.py
│   ├── extract_p99_variation_figure.py
│   └── extract_udp_loss_figure.py
│
└── data_processed/
    ├── MASTER_ALL_SN_RTT_VARIATION.csv
    ├── MASTER_ALL_SN_THROUGHPUT.csv
    ├── MASTER_ALL_SN_LOAD_CURVE.csv
    ├── MASTER_ALL_SN_TESTS.csv
    ├── MASTER_ALL_SN_PHASE_WINDOWS.csv
    ├── MASTER_ALL_SN_ICMP_PROCESSES.csv
    ├── MASTER_ALL_SN_LOG_VALIDATION.csv
    ├── MASTER_ALL_SN_CONFIG_STATUS.csv
    └── MASTER_ALL_SN_QC_REPORT.txt
