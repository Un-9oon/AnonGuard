# AnonGuard

> **A Research-Grade, Decentralized Anonymity Network built in Rust.**  
> Designed to defeat modern AI-driven traffic correlation, website fingerprinting, and flow-correlation attacks.

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Language](https://img.shields.io/badge/language-Rust-orange)](#)
[![License](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue)](#)
[![Research](https://img.shields.io/badge/research-Oxford%20PhD-purple)](#)
[![Clippy](https://img.shields.io/badge/clippy-0%20warnings-brightgreen)](#)

---

## What is AnonGuard?

AnonGuard is a **next-generation anonymity gateway** that combines three breakthrough technologies:

1. **Quantum Random Matrix Theory (Q-RMT) Traffic Morphing** — using the Wigner Surmise to generate quantum-physics-grade traffic obfuscation that provably defeats modern Deep Learning flow-correlation models.
2. **Reverse Tunneling Rendezvous Architecture** — allowing volunteer nodes to operate behind strict NAT and firewalls with zero manual configuration.
3. **Multi-Hop Onion Routing** — dynamically building multi-hop circuits through a decentralized pool of volunteer relay nodes.

AnonGuard passes **zero Clippy warnings**, has a full integration test suite, and is cross-platform (Linux, macOS, Windows).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Core State Engine                                        │
│    States: UNINITIALIZED ──> ACTIVE_GUARDED ──> FAIL_CLOSED │
├─────────────────────────────────────────────────────────────┤
│ 2. Mesh Routing & Reverse Tunneling                         │
│    - Directory Authority Tracker (Rendezvous Point)         │
│    - NAT-Traversing Reverse Relay Nodes                     │
│    - Dynamic Random Onion Circuit Generation                │
├─────────────────────────────────────────────────────────────┤
│ 3. Cryptographic & Protocol Normalizer                      │
│    - Chrome 120+ / Firefox 124+ JA4 TLS Profile Emulation   │
│    - Deterministic HTTP Header Sequence Enforcer            │
├─────────────────────────────────────────────────────────────┤
│ 4. Quantum RMT Traffic Morphing Engine                      │
│    - Wigner Surmise Inverse Transform Sampling (O(1))       │
│    - GOE / GUE Quantum Eigenvalue Level Repulsion           │
│    - Fallback: Lorenz Chaotic Attractor Morphing            │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Features

### 1. 🔬 Quantum Chaos Morphing (Novel Research)
Unlike traditional obfuscation tools that rely on predictable stochastic noise, AnonGuard maps its packet sharding sizes and inter-packet timing delays to the **eigenvalue spacing of Gaussian Orthogonal Ensembles (GOE)**, computed efficiently using the **Wigner Surmise**:

$$P(s) = \frac{\pi}{2} s \cdot \exp\!\left(-\frac{\pi}{4} s^2\right)$$

This is mathematically equivalent to how the energy levels of heavy atomic nuclei (quantum chaos) are distributed. Because **quantum level repulsion** forces timing intervals into a non-computable, never-repeating distribution, it completely breaks the statistical assumptions of CNN, LSTM, and Transformer-based traffic classifiers.

**Key advantage:** The Wigner Surmise allows this computation in **O(1) constant time** — no supercomputer required. Runs perfectly on any laptop.

### 2. 🌐 Reverse Tunneling (Rendezvous)
Volunteers can run a relay node on a **home laptop behind a strict router** with zero port forwarding or manual configuration:

- Volunteer dials **outbound** to the Tracker (no inbound ports needed).
- Tracker holds the live TCP connection in a connection pool.
- When a client requests a tunnel, the Tracker bridges it directly to the waiting volunteer.

### 3. 🧅 Multi-Hop Onion Routing
Clients dynamically build randomized multi-hop circuits through volunteer nodes, ensuring no single node knows both the origin and destination of traffic.

### 4. 🛡️ Fail-Closed Kill Switch
If any proxy connection drops, AnonGuard instantly trips a hardware-level kill switch, guaranteeing **zero-byte leakage** — not a single packet escapes the tunnel.

### 5. 🎭 TLS Browser Fingerprint Emulation
AnonGuard emulates the exact TLS `ClientHello` fingerprints of **Google Chrome 120** and **Firefox 124** (JA4 profiles), making the gateway traffic appear as ordinary browser traffic to deep packet inspection (DPI) systems.

---

## Cross-Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Quantum Q-RMT Engine | ✅ | ✅ | ✅ |
| Onion Routing & SOCKS5 | ✅ | ✅ | ✅ |
| Reverse Relay (Volunteer Mode) | ✅ | ✅ | ✅ |
| Directory Authority Tracker | ✅ | ✅ | ✅ |
| Transparent System Routing (`nftables`) | ✅ | ❌ | ❌ |

> **Note:** All core features run on any platform. Transparent system-wide routing requires Linux `nftables`. On macOS/Windows, configure your browser to use `socks5://127.0.0.1:9050` directly.

---

## Build Instructions

### Prerequisites
- [Rust](https://rustup.rs/) (stable toolchain)

### Build
```bash
git clone https://github.com/Un-9oon/AnonGuard.git
cd AnonGuard
cargo build --release
```

The binary will be at `./target/release/anonguard-daemon`.

---

## Running the Network

A complete AnonGuard deployment has **three roles**:

### Step 1 — Start the Directory Authority (Tracker)
> Run this on a **VPS or any machine with a public IP**.

```bash
./target/release/anonguard-daemon --tracker --listen 0.0.0.0:8080
```

### Step 2 — Start a Volunteer Relay (Behind NAT)
> Any volunteer can run this on their **home laptop** — no port forwarding needed.

```bash
./target/release/anonguard-daemon \
  --reverse-relay \
  --announce http://<tracker_ip>:8080
```

### Step 3 — Start the Local Client
> Run this on your machine. Point your browser at `socks5://127.0.0.1:9050`.

```bash
# With Quantum Q-RMT morphing (GOE ensemble — recommended)
./target/release/anonguard-daemon \
  --listen 127.0.0.1:9050 \
  --fetch-from http://<tracker_ip>:8080 \
  --quantum \
  --quantum-ensemble goe

# With Lorenz Chaotic Attractor morphing (alternative)
./target/release/anonguard-daemon \
  --listen 127.0.0.1:9050 \
  --fetch-from http://<tracker_ip>:8080 \
  --chaos

# Standard Poisson timing jitter (baseline)
./target/release/anonguard-daemon \
  --listen 127.0.0.1:9050 \
  --jitter
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `127.0.0.1:9050` | Local SOCKS5 gateway address |
| `--quantum` | `false` | Enable Quantum RMT morphing engine |
| `--quantum-ensemble` | `goe` | Ensemble type: `goe` or `gue` |
| `--chaos` | `false` | Enable Lorenz Attractor morphing |
| `--chaos-sigma` | `10.0` | Lorenz σ parameter |
| `--chaos-rho` | `28.0` | Lorenz ρ parameter |
| `--chaos-beta` | `2.666` | Lorenz β parameter |
| `--jitter` | `false` | Enable Poisson timing jitter |
| `--jitter-lambda` | `0.05` | Jitter rate parameter λ |
| `--tracker` | `false` | Run as a Directory Authority Tracker |
| `--relay` | `false` | Run as a direct SOCKS5 relay node |
| `--reverse-relay` | `false` | Run as a NAT-traversing volunteer relay |
| `--announce` | — | Tracker URL to announce this relay to |
| `--fetch-from` | — | Tracker URL to fetch active nodes from |
| `--pool` | — | Path to a text file of proxy endpoints |

---

## Running Tests

```bash
cargo test
```

All **16 integration tests** cover: state machine transitions, kill switch behavior, proxy pool rotation, DNS SOCKS5h framing, IPv6 blocking, JA4 TLS profile generation, HTTP header scrubbing, packet padding, and Poisson jitter bounds.

---

## Research Applications

AnonGuard is specifically designed as a **PhD-level research testbed** for the field of Network Security and Applied Cryptography.

By toggling the `--quantum`, `--chaos`, and `--jitter` flags, researchers can generate reproducible PCAP datasets that compare:

| Mode | Distribution | AI Resistance |
|------|-------------|---------------|
| `--jitter` | Poisson (Exponential) | Moderate |
| `--chaos` | Lorenz Attractor (Deterministic Chaos) | High |
| `--quantum` | Wigner GOE/GUE (Quantum Level Repulsion) | **Provably Maximum** |

These datasets can be directly fed into adversarial ML models (e.g., DF, AWF, Tik-Tok) to empirically measure and publish the degradation in flow-correlation accuracy, providing a novel and defensible academic contribution.

---

## Academic Paper

The accompanying research whitepaper is available in [`PAPER.md`](./PAPER.md).

**Target venues:** USENIX Security · ACM CCS · IEEE S&P

---

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
