# feature_extraction.py
# This script is part of a cybersecurity toolkit aimed at automating the detection of network-based threats. 
# It extracts features from PCAP (Packet Capture) files, which are used for training and evaluating an network intrustion detection ML models.
# 
# github.com/jasonsford
# 19 February 2026
# v0.29

from scapy.all import PcapReader, TCP, IP
import numpy as np
from collections import defaultdict, deque

FIXED_FEATURE_LENGTH = 49  # Define the length of the final feature vector
TIME_WINDOW = 60  # Define the time window (in seconds) for time-based features

def update_flow_duration(flow, current_time):

    # Updates the duration of a flow by calculating the difference between the start time and the current packet time.
    flow['flow_duration'] = current_time - flow['start_time']

def update_time_based_features(flow, current_time):
    
    # Updates time-based features by maintaining a deque of timestamps and calculating the number of packets in the last defined time window.
    while flow['packet_times'] and current_time - flow['packet_times'][0] > TIME_WINDOW:
        flow['packet_times'].popleft()
    flow['packets_in_last_T_seconds'] = len(flow['packet_times'])

def extract_flow_features(packet, flow_features):
    
    # Extracts and updates flow-level features from the packet. This includes calculating flow duration, forward and backward packet statistics, inter-arrival times, and TCP flags.
    try:
        current_time = packet.time  # Use packet's timestamp

        # Build the flow based on source and destination IP address and port
        if IP in packet:
            proto = packet[IP].proto
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport if TCP in packet else getattr(packet, "sport", 0)
            dport = packet[TCP].dport if TCP in packet else getattr(packet, "dport", 0)
            flow_key = f"{src}-{dst}-{sport}-{dport}-{proto}"
        else:
            return


        # Initialize flow if not present
        if flow_key not in flow_features:
            flow_features[flow_key] = {
                'start_time': current_time,
                'packet_sizes': [],
                'packet_times': deque(),  # Deque for storing packet timestamps
                'last_packet_time': current_time,
                'total_packets': 0,
                'flow_duration': 0,
                'packets_in_last_T_seconds': 0,
                'tcp_flags': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'ECE': 0, 'CWR': 0},
                'ttl_values': [],
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
                'fwd_iat_times': [],
                'bwd_iat_times': [],
                'total_fwd_packets': 0,
                'total_bwd_packets': 0,
                # Store the IP addresses of the first packet to identify forward direction
                'first_src_ip': packet[IP].src,
                'first_dst_ip': packet[IP].dst,
            }

        flow = flow_features[flow_key]
        flow['total_packets'] += 1
        flow['packet_sizes'].append(len(packet))

        # Add current time to packet_times and update time-based features
        flow['packet_times'].append(current_time)
        update_time_based_features(flow, current_time)
        update_flow_duration(flow, current_time)

        if IP in packet:
            ip_layer = packet[IP]
            flow['ttl_values'].append(ip_layer.ttl)

            if TCP in packet:
                tcp_header = packet[TCP]
                # Track TCP flags
                flags = tcp_header.flags
                for flag in ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']:
                    if hasattr(flags, flag):
                        flow['tcp_flags'][flag] += int(getattr(flags, flag))
                
                # Determine forward (FWD) or backward (BWD) direction
                if ip_layer.src == flow['first_src_ip'] and ip_layer.dst == flow['first_dst_ip']:
                    # Forward direction
                    flow['fwd_packet_lengths'].append(len(packet))
                    flow['total_fwd_packets'] += 1
                    if flow['fwd_iat_times']:
                        flow['fwd_iat_times'].append(current_time - flow['fwd_iat_times'][-1])
                    else:
                        flow['fwd_iat_times'].append(0)
                else:
                    # Backward direction
                    flow['bwd_packet_lengths'].append(len(packet))
                    flow['total_bwd_packets'] += 1
                    if flow['bwd_iat_times']:
                        flow['bwd_iat_times'].append(current_time - flow['bwd_iat_times'][-1])
                    else:
                        flow['bwd_iat_times'].append(0)

    except Exception as e:
        print(f"An error occurred: {e}")

def flow_features_to_feature_vector(flow_features):
    
    # Converts flow-level features into a numeric feature vector and a full feature dictionary. Includes statistical calculations like mean, min, max, and standard deviation for forward and backward packets.
    
    numeric_feature_vector = []
    full_feature_dict = defaultdict(dict)

    for flow_key, features in flow_features.items():
        # Calculate statistical features from the flow data
        fwd_packet_lengths = np.array(features['fwd_packet_lengths'], dtype=np.float64)
        bwd_packet_lengths = np.array(features['bwd_packet_lengths'], dtype=np.float64)

        # Flow statistics
        fwd_packet_length_mean = np.mean(fwd_packet_lengths) if fwd_packet_lengths.size > 0 else 0
        fwd_packet_length_min = np.min(fwd_packet_lengths) if fwd_packet_lengths.size > 0 else 0
        fwd_packet_length_max = np.max(fwd_packet_lengths) if fwd_packet_lengths.size > 0 else 0
        bwd_packet_length_mean = np.mean(bwd_packet_lengths) if bwd_packet_lengths.size > 0 else 0
        bwd_packet_length_min = np.min(bwd_packet_lengths) if bwd_packet_lengths.size > 0 else 0
        bwd_packet_length_max = np.max(bwd_packet_lengths) if bwd_packet_lengths.size > 0 else 0

        fwd_iat_times = np.array(features['fwd_iat_times'], dtype=np.float64)
        bwd_iat_times = np.array(features['bwd_iat_times'], dtype=np.float64)

        # Inter-arrival times
        fwd_iat_mean = np.mean(fwd_iat_times) if fwd_iat_times.size > 0 else 0
        bwd_iat_total = np.sum(bwd_iat_times) if bwd_iat_times.size > 0 else 0
        bwd_iat_mean = np.mean(bwd_iat_times) if bwd_iat_times.size > 0 else 0
        bwd_iat_std = np.std(bwd_iat_times) if bwd_iat_times.size > 0 else 0

        # Add the calculated features to the numeric feature vector
        numeric_feature_vector.extend([
            features['total_packets'],
            fwd_packet_length_mean,
            fwd_packet_length_min,
            fwd_packet_length_max,
            bwd_packet_length_mean,
            bwd_packet_length_min,
            bwd_packet_length_max,
            features['flow_duration'],
            fwd_iat_mean,
            bwd_iat_total,
            bwd_iat_mean,
            bwd_iat_std,
            # TCP flags
            features['tcp_flags']['FIN'],
            features['tcp_flags']['SYN'],
            features['tcp_flags']['RST'],
            features['tcp_flags']['PSH'],
            features['tcp_flags']['ACK'],
            features['tcp_flags']['URG'],
            features['tcp_flags']['ECE'],
            features['tcp_flags']['CWR'],
            # TTL
            np.mean(features['ttl_values']) if features['ttl_values'] else 0,
        ])

        # Store full features for analysis
        full_feature_dict[flow_key] = features

    # Pad or truncate the numeric_feature_vector to the fixed length
    if len(numeric_feature_vector) < FIXED_FEATURE_LENGTH:
        numeric_feature_vector.extend([0] * (FIXED_FEATURE_LENGTH - len(numeric_feature_vector)))
    else:
        numeric_feature_vector = numeric_feature_vector[:FIXED_FEATURE_LENGTH]

    return np.array(numeric_feature_vector), full_feature_dict

def extract_features_from_pcap(pcap_file):

    # Main function to extract features from a PCAP file. Iterates through packets in the PCAP file and extracts flow-level features, which are then converted into a numeric feature vector.

    flow_features = defaultdict(dict)

    with PcapReader(pcap_file) as packets:
        for packet in packets:
            if IP in packet:
                extract_flow_features(packet, flow_features)

    # Convert the flow features into a flat feature vector and a full features dictionary
    numeric_feature_vector, full_feature_dict = flow_features_to_feature_vector(flow_features)

    return numeric_feature_vector, full_feature_dict
