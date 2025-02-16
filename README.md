# Feature Extraction Library

This script processes PCAP files to gather flow-level statistics and metadata. 

It was developed as part of the research "Advancing Network Threat Detection through Standardized Feature Extraction and Dynamic Ensemble Learning".

## Requirements

- Python 3.7+
- [Scapy](https://scapy.net/) for packet parsing
- NumPy
  
## Features

- Flow-level tracking of packet sizes, direction, and timestamps
- TCP flags
- Time-based metrics (flow duration, inter-arrival times)
- Aggregates: mean, min, max, std

## Output

- A NumPy array of fixed length
- A dictionary of raw flow statistics

## Authors
[Jason Ford](http://www.jasonsford.com)

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
