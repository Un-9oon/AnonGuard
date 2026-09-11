# AnonGuard: Cross-Layer Anonymity and Anti-Attribution Engine

AnonGuard is a research-grade privacy and anti-attribution framework designed to protect security tools, automated agents, and penetration testing scanners against modern multi-layer surveillance, AI-driven WAFs, and traffic analysis.

## Core Capabilities

- **Zero-Leak Kernel & Transport Enforcement:** Fail-closed state machine with socket kill switch, remote DNS resolution (`socks5h`), and IPv6 blackholing.
- **Layer 7 Anti-Fingerprinting:** JA4/JA3 TLS signature normalization and deterministic HTTP/2 header sequencing.
- **Traffic Analysis Defenses:** Poisson-distributed timing jitter and MTU packet length padding to mitigate machine-learning flow correlation attacks.
- **Dynamic Routing Mesh:** Multi-protocol proxy pooling (SOCKS4/5/HTTP), latency sorting, and automated rotation on WAF block.
- **Cross-Layer Usability:** Seamless integration as a Python library (`from anonguard import AnonGuard`) or standalone local gateway daemon (`127.0.0.1:9050`).

## Installation

```bash
cd /home/we/AnonGuard

# Install Rust engine
cargo build --release

# Install Python SDK (editable mode)
pip install -e .
```

## Quick Start (Python SDK)

```python
from anonguard import AnonGuard, GuardConfig

# Initialize AnonGuard with proxy nodes
guard = AnonGuard(
    proxies=["socks5://127.0.0.1:9050"],
    config=GuardConfig(strict_killswitch=True, enable_jitter=True)
)

# Acquire a guarded session with fail-closed kill switch
session = guard.get_guarded_session()
response = session.get("https://api.ipify.org?format=json")
print("Anonymized IP:", response.json()["ip"])
```

### GuardConfig Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `strict_killswitch` | `bool` | `True` | Immediately block all traffic if proxy fails |
| `enforce_remote_dns` | `bool` | `True` | Force SOCKS5h remote FQDN resolution |
| `disable_ipv6` | `bool` | `True` | Block IPv6 to prevent dual-stack leaks |
| `verify_ip_before_start` | `bool` | `True` | Pre-flight IP leak verification |
| `enable_jitter` | `bool` | `False` | Poisson timing jitter for anti-correlation |
| `verification_timeout` | `float` | `8.0` | Timeout for IP verification endpoints (seconds) |

## Running as Local Gateway

```bash
# Start the daemon on default port 9050
./target/release/anonguard-daemon

# Or with custom options
./target/release/anonguard-daemon --listen 127.0.0.1:9050 --proxy socks5://127.0.0.1:1080 --jitter
```

## Running Tests

```bash
# Rust unit tests
cargo test

# Python research benchmarks (requires PYTHONPATH)
PYTHONPATH=python:$PYTHONPATH python3 python/research_benchmarks/leak_audit.py
PYTHONPATH=python:$PYTHONPATH python3 python/research_benchmarks/timing_classifier.py

# Full packet inspection test (localhost, no external dependencies)
PYTHONPATH=python:$PYTHONPATH python3 research_benchmarks/packet_verifier.py
```
