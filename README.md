# Feature Extraction Library

This repository contains tools for automating the detection of network-based threats using machine learning. The feature extraction library (feature_extraction.py) transforms raw packet capture (PCAP) data into structured feature vectors suitable for training and evaluating ML models, including classifiers and ensemble models like those discussed in my research [Advancing Network Threat Detection through Standardized Feature Extraction and Dynamic Ensemble Learning](https://www.researchgate.net/publication/390023779_Advancing_Network_Threat_Detection_through_Standardized_Feature_Extraction_and_Dynamic_Ensemble_Learning/references).

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/) for packet parsing
- NumPy
  
## Key Features

- Uses a 5-tuple (Source IP, Destination IP, Source Port, Destination Port, Protocol) flow key to track individual network flows
- Distinguishes between forward and backward traffic, capturing direction-specific statistics like packet lengths and inter-arrival times
- Calculates the number of packets in the last "T" seconds using a sliding window to detect bursty or high-frequency anomalies
- Generates a fixed-length, 49-dimension vector than encompasses:
  - Flow duration and total packet counts
  - Statistical measures for packet lengths and inter-arrival times including mean, min, max, and std
  - Aggregated TCP flag counts
  - Mean Time-to-Live (TTL) values
  - Scalable processing for efficient iteration of large PCAP files

## Usage

```python
from feature_extraction import extract_features_from_pcap

# Process a PCAP file to get numeric vectors and detailed flow metadata
numeric_vector, flow_metadata = extract_features_from_pcap("traffic.pcap")
```

## What's new in this version

- Transitioned from generic flow identification to a stateful tracking system with bidirectional statistical analysis
- Major Changes
  - Replaced the generic flow_key with a proper per-flow identifier based on source/destination IPs, ports, and protocols
  - Implemented logic to identify the first packet of a flow to establish forward and backward directionality
  - Added separate tracking for fwd_packet_lengths, bwd_packets_lengths, fwd_iat_times, bwd_iat_times
  - Revised tracking of TCP flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR) to provide more signals for detecting scanning and handshake anomalies
  - Implemented a fixed-length output vector with zero-padding

## Authors
[Jason Ford](http://www.jasonsford.com)

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
