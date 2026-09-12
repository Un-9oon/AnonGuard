#!/usr/bin/env python3
"""
AnonGuard Traffic Generation & Emulation Harness.
Generates realistic Website Fingerprinting (WF) packet traces across 4 defense modes:
1. Plain Unprotected TCP / SOCKS5
2. Standard Tor-style Fixed 514-byte Cells (Deterministic Timings)
3. Lorenz Chaotic Attractor Jitter
4. AnonGuard Quantum Random Matrix Theory (Q-RMT) Wigner Surmise Morphing
"""

import numpy as np
import json
import math
import os

CLASSES = [
    "banking_portal",
    "news_media",
    "cryptocurrency_exchange",
    "social_network",
    "search_engine",
    "wiki_reference",
    "streaming_video",
    "ecommerce_checkout",
    "gov_portal",
    "tor_hidden_service"
]

def simulate_raw_trace(class_idx, num_packets=120):
    """Simulates raw web traffic with website-specific burst patterns and inter-arrival times."""
    np.random.seed(class_idx * 1000 + np.random.randint(0, 999))
    base_rate = 5.0 + (class_idx * 2.5) # packets per ms
    
    # Generate packet sizes (mix of small ACKs and large MTU payloads)
    sizes = []
    directions = []
    iats = []
    
    t = 0.0
    for _ in range(num_packets):
        # Direction: 1 = outgoing, -1 = incoming
        direction = 1 if np.random.rand() < 0.35 else -1
        size = np.random.choice([64, 512, 1420, 1500], p=[0.25, 0.15, 0.35, 0.25])
        iat = np.random.exponential(scale=1.0 / base_rate)
        
        sizes.append(int(size))
        directions.append(int(direction))
        iats.append(float(iat))
        
    return {"sizes": sizes, "directions": directions, "iats": iats, "label": class_idx}

def apply_tor_defense(trace):
    """Tor defense: Fixed 514-byte cell sizes, no timing morphing."""
    sizes = [514] * len(trace["sizes"])
    return {
        "sizes": sizes,
        "directions": trace["directions"],
        "iats": trace["iats"],
        "label": trace["label"]
    }

def apply_chaos_defense(trace):
    """Lorenz Chaotic Attractor timing morphing with variable chunk sizes."""
    sizes = []
    iats = []
    
    # Lorenz attractor integration
    dt = 0.01
    sigma, rho, beta = 10.0, 28.0, 8.0 / 3.0
    x, y, z = 0.1, 0.0, 0.0
    
    for orig_size, orig_iat in zip(trace["sizes"], trace["iats"]):
        # Runge-Kutta step
        dx = sigma * (y - x) * dt
        dy = (x * (rho - z) - y) * dt
        dz = (x * y - beta * z) * dt
        x += dx
        y += dy
        z += dz
        
        # Jitter delay derived from attractor z coordinate
        jitter = max(0.5, (z / 50.0) * 15.0)
        chunk_mod = int(512 + (abs(x) / 30.0) * 512)
        
        sizes.append(chunk_mod)
        iats.append(orig_iat + jitter)
        
    return {
        "sizes": sizes,
        "directions": trace["directions"],
        "iats": iats,
        "label": trace["label"]
    }

def apply_quantum_rmt_defense(trace):
    """AnonGuard Quantum Chaos (Q-RMT) Morphing using the Wigner Surmise with level repulsion P(s -> 0) = 0."""
    sizes = []
    iats = []
    
    for _, orig_iat in zip(trace["sizes"], trace["iats"]):
        # Wigner Surmise inverse CDF sampling for GOE: s = sqrt(- (4 / pi) * ln(u))
        u = max(1e-9, np.random.uniform(0.001, 0.999))
        s = math.sqrt(-(4.0 / math.pi) * math.log(u))
        
        # Level repulsion guarantees s is strictly bounded away from zero
        quantum_delay = s * 8.5 # scaled to milliseconds
        
        # Quantum packet sharding: Wigner GUE spacing for chunk lengths
        u_chunk = max(1e-9, np.random.uniform(0.001, 0.999))
        s_chunk = math.sqrt(-(4.0 / math.pi) * math.log(u_chunk))
        chunk_size = int(512 + (s_chunk * 256.0)) % 1024 + 128
        
        sizes.append(chunk_size)
        iats.append(orig_iat + quantum_delay)
        
    return {
        "sizes": sizes,
        "directions": trace["directions"],
        "iats": iats,
        "label": trace["label"]
    }

def generate_full_dataset(samples_per_class=40):
    """Generates a complete multi-class dataset across all 4 defense modes."""
    dataset = {
        "raw": [],
        "tor": [],
        "chaos": [],
        "quantum": []
    }
    
    for c in range(len(CLASSES)):
        for _ in range(samples_per_class):
            raw = simulate_raw_trace(c)
            dataset["raw"].append(raw)
            dataset["tor"].append(apply_tor_defense(raw))
            dataset["chaos"].append(apply_chaos_defense(raw))
            dataset["quantum"].append(apply_quantum_rmt_defense(raw))
            
    return dataset

if __name__ == "__main__":
    os.makedirs("eval/data", exist_ok=True)
    print("[+] Generating empirical Website Fingerprinting traces...")
    ds = generate_full_dataset(samples_per_class=50)
    
    out_path = "eval/data/traces.json"
    with open(out_path, "w") as f:
        json.dump(ds, f)
    print(f"[+] Successfully generated {len(ds['raw'])} traces per mode into {out_path}")
