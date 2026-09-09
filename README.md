# iPCF-2 Experimental Dataset and Analysis
This repository contains the analysis scripts, processed datasets,
experimental metadata, and figure-generation resources associated with 
the experimental characterization of Siemens iPCF-2 and standard Wi-Fi 
6 on the same industrial hardware platform.

## Experimental scope

- 1 AP
- 2 STAs
- Stationary topology
- 2.4 GHz and 5 GHz
- Channel bandwidths: 20, 40, and 80 MHz where supported
- iPCF-2 enabled and standard WLAN operating modes
- iperf3 TCP
- iperf3 UDP
- ffmpeg RTP/UDP traffic

## Repository structure

- `scripts/`: data processing and analysis scripts
- `data_processed/`: processed experimental data used for the article
- `metadata/`: test configuration and experimental documentation
- `figures/`: figure-generation resources

## Raw packet captures

Raw PCAP traces are not hosted directly in this GitHub repository due
to their size. Their permanent archive will be referenced here.

## Authors

Rodrigo Arriaga-Tarqui et al.
