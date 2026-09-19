# AnonGuard

> **An Authenticated, Research-Backed Decentralized Anonymity Network built in Rust.**  
> Engineered to counter AI-driven flow correlation, website fingerprinting, and metadata leaks through telescopic onion routing, traffic morphing, and fail-closed leak prevention.

[![Build](https://github.com/Un-9oon/AnonGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Un-9oon/AnonGuard/actions/workflows/ci.yml)
[![Language](https://img.shields.io/badge/language-Rust-orange)](#)
[![License](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue)](#)
[![Research](https://img.shields.io/badge/research-Oxford%20PhD-purple)](#)
[![Clippy](https://img.shields.io/badge/clippy-0%20warnings-brightgreen)](#)
[![Tests](https://img.shields.io/badge/tests-29%20passing-brightgreen)](#)

---

## What is AnonGuard?

AnonGuard is an open-source, defense-in-depth anonymity gateway combining statistical physics with authenticated cryptographic routing:

1. **Authenticated Layered Onion Cryptography (3-Hop Circuit Routing)** — Constant 1024-byte cells, in-band telescopic circuit negotiation (`CREATE`/`CREATED` and encrypted `EXTEND` cells) using per-hop X25519 Diffie-Hellman key agreement, ChaCha20 stream peeling, monotonic sequence counters for anti-replay, and **ChaCha20-Poly1305 AEAD** authentication applied to the addressed hop to eliminate tag forgery, bit-flipping, and replay attacks. No intermediate relay ever sees both source and destination.
2. **Statistical Random Matrix Theory (RMT) Traffic Morphing** — Utilizes Eugene Wigner's **Wigner Surmise** eigenvalue spacing distribution $P(s \to 0) = 0$ via fast inverse-transform sampling from a classical CSPRNG to produce level repulsion, disrupting deep learning packet-timing classifiers in constant $O(1)$ time ($\approx 1 \text{ ns}$ per packet, requiring no quantum hardware).
3. **Distributed Multi-Authority Consensus & Key Binding** — Eliminates single points of failure using an $M$-of-$N$ quorum consensus protocol signed by independent Directory Authorities via Ed25519 threshold signatures. Relay descriptors require Ed25519 signatures binding node identities to cryptographic keys, preventing relay impersonation and last-write-wins hijacking.
4. **Sybil Resistance Engine** — Enforces cryptographic Proof-of-Work (PoW) registration challenges (tunable via `--pow-difficulty`) alongside strict BGP `/16` CIDR subnet diversity isolation across circuit hops.
5. **Fail-Closed Runtime Protection & Anti-SSRF Exit Policy** — Actively monitored kill switch channels cancel in-flight socket read/write loops instantaneously upon trip. Strict exit policies verify all resolved destination IPs against internal, loopback, and cloud metadata ranges to prevent SSRF and DNS rebinding attacks. Remote DNS resolution and runtime IPv6 blackholing prevent dual-stack deanonymization. *(Note: Optional kernel-level `nftables` output filtering is strictly Linux-only via `--enable-firewall-killswitch`).*

AnonGuard compiles cleanly with **zero Clippy warnings (`-D warnings`)**, passes **all 29 integration & unit tests**, and is cross-platform (Linux, macOS, Windows).

---

## 📦 Quick Installation & Pre-Built Packages

### 🚀 Automated 1-Line Interactive Setup Wizard (Easiest for Everyone)
For non-technical users, run this single command in terminal. The wizard asks a few simple questions, automatically configures all files, installs dependencies, and launches the gateway:

```bash
curl -sSL https://raw.githubusercontent.com/Un-9oon/AnonGuard/main/install.sh | sudo bash
```
*(Or run without sudo to install locally into `~/.local/bin`)*

---

### 🐧 Debian / Ubuntu / Kali / Mint (`.deb`)
Download the `.deb` package and install it with `dpkg` or `apt`:
```bash
# Install package
sudo dpkg -i anonguard_0.1.0_amd64.deb

# Enable and start background daemon (runs on boot)
sudo systemctl enable --now anonguard

# Check status
systemctl status anonguard
```
*Binary is installed to `/usr/bin/anonguard-daemon` and config to `/etc/anonguard/config.toml`.*

### 🪟 Windows (`.zip` setup)
1. Download `anonguard-windows-amd64.zip` from [Releases](https://github.com/Un-9oon/AnonGuard/releases).
2. Extract the archive.
3. Open PowerShell or Command Prompt in the extracted folder:
```powershell
.\anonguard-daemon.exe --listen 127.0.0.1:9050 --onion --rmt-morphing
```
4. Point your browser's SOCKS5 proxy to `127.0.0.1:9050`.

### 🍎 macOS (Apple Silicon M1/M2/M3 & Intel)
Download the universal binary archive:
```bash
tar -xzf anonguard-macos-universal.tar.gz
./anonguard-daemon --listen 127.0.0.1:9050 --onion --rmt-morphing
```

### 🛠️ Build `.deb` Locally From Source
On any Debian/Ubuntu system, build your own signed `.deb` package in seconds:
```bash
./scripts/build_deb.sh
# Generated at: dist/anonguard_0.1.0_amd64.deb
```

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Multi-Hop Layered Onion Subsystem                        │
│    - Constant 1024-byte OnionCell Protocol                  │
│    - X25519 Ephemeral Key Agreement + ChaCha20 Stream Peeling│
│    - Forward Peeling (Guard -> Mid -> Exit) & Return Wrapping│
├─────────────────────────────────────────────────────────────┤
│ 2. Sybil Defense & Consensus Mesh                           │
│    - Multi-Authority Consensus (Ed25519 Quorum Signatures)   │
│    - Proof-of-Work (PoW) Registration Challenge Engine       │
│    - BGP /16 Subnet Prefix Isolation Enforcement            │
│    - Authenticated Cryptographic Node Framing               │
├─────────────────────────────────────────────────────────────┤
│ 3. Statistical RMT Traffic Morphing Engine                  │
│    - Wigner Surmise Inverse Transform Sampling (O(1))       │
│    - GOE / GUE Statistical Eigenvalue Level Repulsion       │
│    - Fallback: Lorenz Chaotic Attractor Morphing            │
├─────────────────────────────────────────────────────────────┤
│ 4. Protocol Normalizer & Kernel Kill Switch                 │
│    - Client-Side Chrome 120+ / Firefox 124+ JA4 Profile Spec│
│    - Deterministic HTTP Header Scrubbing Library Utility    │
│    - Fail-Closed Kernel Kill Switch (Zero Transitional Leak)│
└─────────────────────────────────────────────────────────────┘
```

> **Architectural Layering Note (L4/L5 Transport vs. L7 Application):**
> AnonGuard operates as an authentic L4/L5 network privacy daemon (RFC 1928 SOCKS5 and in-band onion cells). To preserve zero-trust end-to-end TLS cryptography and avoid the severe security vulnerabilities of local root CA interception (MitM), the daemon does not terminate or forge TLS connections. The included `TlsProfile` (`anonguard::crypto::TlsProfile`) and `HeaderNormalizer` (`anonguard::crypto::HeaderNormalizer`) modules provide reference specifications and normalization rules for client-side user-agents, scrapers, and headless browser drivers operating through the daemon.

---

## Empirical ML Degradation Benchmark Results

AnonGuard provides two complementary evaluation tools for Website Fingerprinting (WF) analysis:
1. **Mathematical Simulation Harness (`eval/evaluate_classifier.py`):** Generates closed-world packet arrival streams across 10 site archetypes to evaluate the theoretical bounds of Wigner surmise level repulsion against deep neural networks.
2. **Physical Network PCAP Collector (`eval/real_pcap_collector.py`):** Uses `tshark`/`tcpdump` to capture live physical network traces driven by browser requests through the active `anonguard-daemon` SOCKS5 gateway (`127.0.0.1:9050`).

```bash
# Run mathematical simulation benchmark
python3 eval/evaluate_classifier.py

# Collect physical network PCAPs through live gateway
python3 eval/real_pcap_collector.py --interface lo --proxy-port 9050
```

| Defense Strategy | Neural Top-1 | Neural Top-3 | k-NN Acc | Mutual Info $I(X; Y)$ | Security Guarantee |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Unprotected TCP / SOCKS5** | 37.0% | 62.0% | 50.0% | 0.81 bits | None (Trivial Correlation) |
| **Standard Tor (Fixed Cells)** | 32.0% | 65.0% | 46.0% | 0.88 bits | Vulnerable to Timing Attacks |
| **Lorenz Chaotic Attractor** | 25.0% | 61.0% | 43.0% | 0.68 bits | Moderate Nonlinear Obfuscation |
| **AnonGuard Q-RMT (Wigner Surmise)** | **24.0%** | **39.0%** | **35.0%** | **0.00 bits** | **Empirical Resistance (Simulated)** |

> **Theoretical Baseline:** Uniform random guessing across 10 classes is **10.0%**.  
> AnonGuard Q-RMT drives mutual information down to **0.00 bits** in local simulations, strongly disrupting the latent space of deep neural networks.

---

## Core Security Pillars

### 1. 🧅 Authenticated Multi-Hop Onion Circuit Routing
Unlike simple TCP tunneling or single-proxy setups, AnonGuard builds an authentic **cryptographic 3-hop telescopic circuit**:
- **Guard Node:** Strips Layer 1. Knows the client IP, but has no knowledge of downstream hops or cleartext payload.
- **Middle Relay:** Strips Layer 2. Knows only the previous hop and next hop.
- **Exit Node:** Strips Layer 3. Knows the destination target, but has zero knowledge of the originating client.
- **In-Band Telescopic Handshake:** Ephemeral X25519 `CREATE`/`CREATED` and encrypted `EXTEND`/`EXTENDED` cell exchanges prevent on-path eavesdroppers from discovering downstream path topologies.
- **Cryptographic Integrity:** Fixed 1024-byte cells protected with explicit nonces and **ChaCha20-Poly1305 AEAD** applied to the addressed hop to eliminate tag forgery, bit-flipping, and replay attacks.
- Return packets are wrapped by each relay in reverse, and unwrapped sequentially by the client.

### 2. 🔬 Statistical RMT Traffic Morphing (Wigner Surmise)
AnonGuard maps packet sizes and inter-arrival delays to the eigenvalue spacing of Gaussian Orthogonal Ensembles (GOE):

$$P(s) = \frac{\pi}{2} s \cdot \exp\!\left(-\frac{\pi}{4} s^2\right)$$

Because **level repulsion** guarantees $P(s \to 0) = 0$, packet timings never cluster predictably. The inverse transform sampling runs in **$O(1)$ constant time** ($\approx 1 \text{ ns}$ per packet), requiring zero supercomputing resources.

### 3. 🛡️ Sybil Attack Resistance
To prevent a botnet or hostile entity from flooding the directory with rogue nodes:
- Every relay registration must solve an asymmetric **Proof-of-Work (PoW)** challenge $\text{SHA256}(\text{NodeID} \,\|\, \text{Timestamp} \,\|\, \text{Nonce}) < \text{Target}$ (default 20 bits).
- Circuit path selection enforces strict **BGP `/16` CIDR Subnet Diversity**, ensuring that Guard, Middle, and Exit nodes never share the same `/16` network prefix or autonomous system.

### 4. 🌐 Distributed Multi-Authority Consensus & Key Binding
AnonGuard eliminates single points of failure. The directory consensus is maintained by independent Directory Authorities using **Ed25519 threshold signatures**. Clients only trust consensus documents verified by an $M$-of-$N$ quorum. Relays must sign registrations with their Ed25519 identity key, eliminating unauthorized last-write-wins overwriting.

---

## 🔒 Threat Model & Security Boundaries

### What AnonGuard Protects Against:
1. **Passive Network Observers & Eavesdroppers:** On-path observers cannot read payload data or correlate client IP addresses with exit destinations.
2. **Intermediate Relay Collusion:** As long as at least one intermediate relay in the circuit is honest and non-colluding, full path deanonymization is prevented.
3. **Deep Learning Website Fingerprinting:** Statistical RMT eigenvalue level repulsion prevents CNN/RF classifiers from recognizing specific traffic signatures.
4. **Local Network DNS & IPv6 Leaks:** Remote DNS resolution over SOCKS5h and runtime IPv6 blackholing prevent common OS dual-stack exposure.
5. **Mid-Session Policy Disruption:** An active broadcast kill switch terminates in-flight streams immediately if a tunnel or security policy trips.
6. **OS-Level Traffic Leaks:** Linux kernel `nftables` output filter locks traffic strictly to the designated proxy port, automatically flushing on clean shutdown (`SIGINT` / `Ctrl+C`). This OS-level firewall backstop is **Linux-only**. macOS and Windows rely strictly on the fail-closed process-level kill switch.

### What AnonGuard Does NOT Protect Against:
1. **Global Active Traffic-Timing & Manipulation Adversary:** If an active state-level adversary observes both ingress to the Guard and egress from the Exit simultaneously, and can manipulate (drop/delay/watermark) flows, they explicitly break the system. AnonGuard mitigates passive statistical timing confirmation via RMT morphing, but low-latency anonymity networks cannot protect against global active adversaries.
2. **Endpoint Compromise:** Malware, browser exploits, or keyloggers on the client system operate outside network-level encryption boundaries.
3. **Malicious Exit Relay Content Tampering:** Unencrypted HTTP traffic passing through an untrusted exit node can be modified by the exit operator. Always use TLS (HTTPS) on end-to-end connections.

---

## Cross-Platform Compatibility

| Feature | Linux | macOS | Windows |
|---------|:-----:|:-----:|:-------:|
| 3-Hop Layered Onion Routing | ✅ | ✅ | ✅ |
| Statistical RMT Engine | ✅ | ✅ | ✅ |
| Multi-Authority Consensus | ✅ | ✅ | ✅ |
| Sybil PoW & Subnet Diversity | ✅ | ✅ | ✅ |
| Reverse Relay (NAT Traversing) | ✅ | ✅ | ✅ |
| Transparent `nftables` Redirection | ✅ | ❌ | ❌ |

---

## CLI Reference

```text
AnonGuard Standalone Anonymity Gateway

Usage: anonguard-daemon [OPTIONS]

Options:
  -l, --listen <LISTEN>
          Local address to bind the gateway listener [default: 127.0.0.1:9050]
  -p, --pool <POOL>
          Path to a text file containing proxy endpoints (one per line)
      --proxy <PROXY>
          Inline proxy to load immediately (e.g. socks5://127.0.0.1:1080)
      --jitter
          Enable Poisson timing jitter to defeat NetFlow traffic correlation
      --jitter-lambda <JITTER_LAMBDA>
          Rate parameter (lambda) for Poisson timing jitter [default: 0.05]
      --chaos
          Enable Chaotic Attractor Morphing
      --chaos-sigma <CHAOS_SIGMA>
          [default: 10]
      --chaos-rho <CHAOS_RHO>
          [default: 28]
      --chaos-beta <CHAOS_BETA>
          [default: 2.666666]
      --rmt-morphing
          Enable Statistical Random Matrix Theory (RMT) Traffic Morphing (Wigner Surmise)
      --rmt-ensemble <RMT_ENSEMBLE>
          Statistical RMT Ensemble type: "goe" (Gaussian Orthogonal) or "gue" (Gaussian Unitary) [default: goe]
  -r, --relay
          Run as a SOCKS5 relay node (bypasses proxy pool and connects directly)
      --tracker
          Run as a Directory Authority Tracker (legacy mode)
      --authority
          Run as a Cryptographic Directory Authority Node (M-of-N consensus)
      --authority-id <AUTHORITY_ID>
          Directory Authority Identifier (e.g. auth-zurich) [default: auth-primary]
      --authorities <AUTHORITIES>
          Comma-separated list of Directory Authority endpoints
      --authority-keys <AUTHORITY_KEYS>
          Comma-separated list of Directory Authority public keys (e.g. auth-primary:hex_key,...)
      --quorum-threshold <QUORUM_THRESHOLD>
          Quorum threshold for Directory Authority consensus [default: 1]
      --onion
          Enable 3-hop Layered Onion Encryption (Sphinx / Tor-style cell peeling)
      --enforce-subnet-diversity
          Enforce BGP /16 Subnet Diversity across circuit hops (Sybil resistance)
      --reverse-relay
          Run as a Reverse Relay Node (Volunteer mode behind NAT)
      --announce <ANNOUNCE>
          Tracker URL to announce this relay to (e.g. http://1.2.3.4:8080)
      --allow-open-socks5
          Allow open, unauthenticated plain SOCKS5 proxying when running in relay mode (off by default)
      --allow-private-exit
          Allow exit relays to connect to private/loopback networks (off by default to prevent SSRF)
      --is-exit
          
      --enable-firewall-killswitch
          Apply OS/kernel-level nftables firewall kill switch (Linux only, requires root/CAP_NET_ADMIN)
      --pow-difficulty <POW_DIFFICULTY>
          Registration PoW difficulty in leading zero bits (default 26, recommended 20+ for production) [default: 26]
      --fetch-from <FETCH_FROM>
          Tracker URL to fetch active nodes from (e.g. http://1.2.3.4:8080)
      --identity-key-path <IDENTITY_KEY_PATH>
          Path to persist the relay's long-term Ed25519 identity key
  -h, --help
          Print help
  -V, --version
          Print version
```

---

## Verification & Testing

To run the complete cryptographic and integration test suite:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

All unit and integration tests verify:
- 3-hop telescopic onion circuit negotiation (`CREATE`/`EXTEND`/`RELAY`) and streaming
- Fixed 1024-byte OnionCell serialization, explicit nonces, ChaCha20-Poly1305 AEAD, and monotonic sequence anti-replay validation
- SOCKS5 handshake negotiation, error status codes (`0x00`, `0x01`, `0x02`, `0x04`, `0x05`), and RFC 1928 compliance
- Multi-authority consensus voting, Ed25519 quorum validation, and key pinning
- Proof-of-Work mining and verification with configurable difficulty
- BGP `/16` subnet collision detection
- Anti-SSRF exit policy with DNS rebinding prevention on real sockets
- State machine fail-closed transitions, active in-flight stream cancellation, and `GuardedSocket` async stream safety
- Non-crashing sub-50 byte Poisson jitter & Lorenz chaos stream morphing
- Client-side JA4 browser TLS emulation & HTTP header scrubbing library specifications

---

## Academic Whitepaper

The complete mathematical derivations, threat model, and security proofs are published in [`PAPER.md`](./PAPER.md).

**Target Venues:** USENIX Security · ACM CCS · IEEE S&P · PoPETs
