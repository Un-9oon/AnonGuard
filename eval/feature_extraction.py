#!/usr/bin/env python3
"""
Academic Website Fingerprinting Feature Extractor.
Extracts Wang et al. and Sirinam et al. (Deep Fingerprinting) feature representations:
- Inter-Arrival Time (IAT) distribution & quantiles
- Cumulative sequence curve (sampled at regular intervals)
- Burst statistics (continuous unidirection flow sequences)
- In/Out packet size histograms
"""

import numpy as np

def extract_features(trace, num_cumulative_points=20):
    """Transforms raw packet sequence into a fixed-length feature vector."""
    sizes = np.array(trace["sizes"], dtype=np.float64)
    directions = np.array(trace["directions"], dtype=np.float64)
    iats = np.array(trace["iats"], dtype=np.float64)
    
    feats = []
    
    # 1. Total packet count and direction ratio
    total_packets = len(sizes)
    out_count = np.sum(directions > 0)
    in_count = np.sum(directions < 0)
    feats.append(total_packets)
    feats.append(out_count / max(1.0, total_packets))
    feats.append(in_count / max(1.0, total_packets))
    
    # 2. Timing (IAT) statistics
    feats.append(np.mean(iats))
    feats.append(np.std(iats))
    feats.append(np.min(iats))
    feats.append(np.percentile(iats, 25))
    feats.append(np.median(iats))
    feats.append(np.percentile(iats, 75))
    feats.append(np.percentile(iats, 90))
    feats.append(np.max(iats))
    
    # 3. Packet size statistics
    feats.append(np.mean(sizes))
    feats.append(np.std(sizes))
    feats.append(np.min(sizes))
    feats.append(np.percentile(sizes, 50))
    feats.append(np.max(sizes))
    
    # 4. Burst statistics
    burst_sizes = []
    current_burst = 0
    current_dir = directions[0]
    
    for d, s in zip(directions, sizes):
        if d == current_dir:
            current_burst += s
        else:
            burst_sizes.append(current_burst)
            current_burst = s
            current_dir = d
    burst_sizes.append(current_burst)
    
    burst_arr = np.array(burst_sizes, dtype=np.float64)
    feats.append(len(burst_arr))
    feats.append(np.mean(burst_arr))
    feats.append(np.max(burst_arr))
    
    # 5. Sampled Cumulative Sequence Curve C(t)
    cum_bytes = np.cumsum(directions * sizes)
    indices = np.linspace(0, len(cum_bytes) - 1, num_cumulative_points, dtype=int)
    for idx in indices:
        feats.append(cum_bytes[idx])
        
    return np.array(feats, dtype=np.float64)

def extract_dataset(trace_list):
    X = []
    y = []
    for t in trace_list:
        X.append(extract_features(t))
        y.append(t["label"])
    return np.array(X), np.array(y)
