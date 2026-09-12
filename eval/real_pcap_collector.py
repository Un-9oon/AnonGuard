#!/usr/bin/env python3
"""
AnonGuard Physical PCAP Capture & Feature Extraction Tool.
Captures physical network packet captures (PCAPs) using tshark or tcpdump
while routing live HTTPS traffic through the AnonGuard daemon gateway (127.0.0.1:9050).

Extracts real packet inter-arrival times (IATs), directionality (+1/-1), and packet sizes
directly into dataset format for Website Fingerprinting (WF) ML classifier evaluation.
"""

import os
import sys
import time
import json
import shutil
import argparse
import subprocess
from pathlib import Path

TARGET_SITES = {
    0: ("banking_portal", "https://www.chase.com"),
    1: ("news_media", "https://www.bbc.com"),
    2: ("cryptocurrency_exchange", "https://www.coinbase.com"),
    3: ("social_network", "https://www.reddit.com"),
    4: ("search_engine", "https://duckduckgo.com"),
    5: ("wiki_reference", "https://en.wikipedia.org"),
    6: ("streaming_video", "https://www.vimeo.com"),
    7: ("ecommerce_checkout", "https://www.amazon.com"),
    8: ("gov_portal", "https://www.usa.gov"),
    9: ("tor_hidden_service", "https://check.torproject.org"),
}

def check_dependencies():
    """Checks for required packet capture tools."""
    has_tshark = shutil.which("tshark") is not None
    has_tcpdump = shutil.which("tcpdump") is not None
    has_curl = shutil.which("curl") is not None
    return {
        "tshark": has_tshark,
        "tcpdump": has_tcpdump,
        "curl": has_curl,
    }

def capture_live_trace(site_idx, label, url, output_dir, proxy_port=9050, iface="lo", duration_sec=10):
    """
    Captures live traffic of a single URL access through AnonGuard daemon.
    """
    output_pcap = output_dir / f"{label}_{site_idx}.pcap"
    deps = check_dependencies()

    if not deps["curl"]:
        print("[-] curl not found. Please install curl to drive live traffic.")
        return None

    # Determine capture command
    capture_proc = None
    if deps["tshark"]:
        cmd = [
            "tshark", "-i", iface,
            "-a", f"duration:{duration_sec}",
            "-w", str(output_pcap),
            "-q"
        ]
        capture_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif deps["tcpdump"]:
        cmd = [
            "tcpdump", "-i", iface,
            "-w", str(output_pcap),
            "-s", "0"
        ]
        capture_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print("[-] Neither tshark nor tcpdump found. Cannot perform raw packet capture.")
        return None

    time.sleep(1.0) # Allow sniffer to initialize

    # Drive live web request through AnonGuard SOCKS5H proxy
    curl_cmd = [
        "curl", "-s", "-L",
        "--socks5-hostname", f"127.0.0.1:{proxy_port}",
        "--max-time", str(duration_sec - 2),
        "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        url
    ]
    try:
        subprocess.run(curl_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=duration_sec)
    except Exception as e:
        print(f"[*] curl finished or timed out: {e}")

    time.sleep(1.0)
    if capture_proc and capture_proc.poll() is None:
        capture_proc.terminate()
        try:
            capture_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            capture_proc.kill()

    if output_pcap.exists() and output_pcap.stat().st_size > 0:
        print(f"[+] Successfully captured physical PCAP: {output_pcap} ({output_pcap.stat().st_size} bytes)")
        return output_pcap
    else:
        print(f"[-] PCAP capture empty or failed for {url}")
        return None

def parse_pcap_to_features(pcap_path, label_idx, proxy_port=9050):
    """
    Parses a physical PCAP file using tshark to extract packet sizes, direction, and inter-arrival times.
    """
    if not shutil.which("tshark"):
        print("[-] tshark required to extract timing and size features from PCAP.")
        return None

    cmd = [
        "tshark", "-r", str(pcap_path),
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-Y", "tcp"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return None

    times = []
    sizes = []
    directions = []

    lines = res.stdout.strip().split("\n")
    for line in lines:
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        try:
            epoch = float(parts[0])
            flen = int(parts[1])
            src_port = int(parts[2]) if parts[2] else 0
            
            # Direction: 1 = to proxy/upstream, -1 = from proxy/upstream
            direction = -1 if src_port == proxy_port else 1

            times.append(epoch)
            sizes.append(flen)
            directions.append(direction)
        except ValueError:
            continue

    if not times:
        return None

    iats = [0.0]
    for i in range(1, len(times)):
        iats.append(max(0.0, times[i] - times[i - 1]))

    return {
        "sizes": sizes,
        "directions": directions,
        "iats": iats,
        "label": label_idx,
        "pcap_source": str(pcap_path)
    }

def main():
    parser = argparse.ArgumentParser(description="AnonGuard Physical PCAP Live Capture Harness")
    parser.add_argument("--output-dir", type=str, default="eval/pcaps", help="Directory to save PCAP files")
    parser.add_argument("--interface", type=str, default="lo", help="Network interface to capture (default: lo)")
    parser.add_argument("--proxy-port", type=int, default=9050, help="AnonGuard SOCKS5 listen port (default: 9050)")
    parser.add_argument("--samples-per-class", type=int, default=1, help="Samples to collect per class (default: 1)")
    parser.add_argument("--extract-json", type=str, default="eval/real_pcap_dataset.json", help="Output JSON dataset path")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    deps = check_dependencies()
    print("=== AnonGuard Physical PCAP Collector ===")
    print(f"[*] Tool status: tshark={deps['tshark']}, tcpdump={deps['tcpdump']}, curl={deps['curl']}")
    print(f"[*] Target Interface: {args.interface}")
    print(f"[*] Gateway Proxy Port: {args.proxy_port}")

    if not deps["tshark"] and not deps["tcpdump"]:
        print("[!] Warning: Neither tshark nor tcpdump installed.")
        print("[!] Install via: sudo apt install tshark / brew install wireshark")
        sys.exit(1)

    dataset = []
    for class_idx, (label, url) in TARGET_SITES.items():
        for s in range(args.samples_per_class):
            print(f"[*] Capturing class {class_idx} ({label}) sample {s+1}/{args.samples_per_class} from {url}...")
            pcap = capture_live_trace(
                site_idx=class_idx,
                label=f"{label}_{s}",
                url=url,
                output_dir=out_dir,
                proxy_port=args.proxy_port,
                iface=args.interface
            )
            if pcap and deps["tshark"]:
                feats = parse_pcap_to_features(pcap, class_idx, proxy_port=args.proxy_port)
                if feats:
                    dataset.append(feats)

    if dataset:
        with open(args.extract_json, "w") as f:
            json.dump(dataset, f, indent=2)
        print(f"[+] Saved physical PCAP dataset with {len(dataset)} traces to {args.extract_json}")

if __name__ == "__main__":
    main()
