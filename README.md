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
pip install -e .
```

## Quick Start (Python SDK)

```python
from anonguard import AnonGuard, GuardConfig

# Initialize AnonGuard with proxy nodes
guard = AnonGuard(
    proxies=["socks5://127.0.0.1:9050"],
    config=GuardConfig(strict=True, enable_jitter=True)
)

# Acquire a guarded session with fail-closed kill switch
session = guard.get_guarded_session()
response = session.get("https://api.ipify.org?format=json")
print("Anonymized IP:", response.json()["ip"])
```

## Running as Local Gateway

```bash
anonguard serve --listen 127.0.0.1:9050 --pool proxies.txt
```
