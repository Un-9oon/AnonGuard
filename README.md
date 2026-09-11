# AnonGuard

**AnonGuard** is a next-generation, decentralized anonymity network and proxy routing engine built in Rust. It is specifically designed as a research testbed for evaluating and defeating modern AI-driven flow-correlation and website fingerprinting attacks.

## Core Features

1. **Chaotic Attractor Morphing (Novel Cryptography):**
   Unlike traditional obfuscation tools that rely on predictable stochastic noise, AnonGuard maps its packet sharding sizes and timing delays directly to the **Lorenz Attractor** (a deterministic chaotic system). Because the system exhibits extreme sensitivity to initial conditions, the traffic flow profile never repeats, completely denying machine learning models (CNNs, LSTMs, Transformers) the statistical patterns required for feature extraction.

2. **Reverse Tunneling (Rendezvous):**
   Deploying global proxy nodes is historically difficult due to NAT and firewalls. AnonGuard features a **Directory Authority Tracker** and a **Reverse Relay Mode**. Volunteers can run the relay daemon on their personal computers behind strict routers; the relay connects outbound to the Tracker. Clients seamlessly build Onion Tunnels that route through the Tracker and down into the volunteer's network without requiring any manual port forwarding.

3. **Multi-Hop Onion Routing:**
   Clients dynamically build multi-hop circuits through a pool of active proxy nodes to provide strong cryptographic separation between the entry node (which knows the client's IP) and the exit node (which knows the destination).

## Build Instructions

AnonGuard is written in Rust. You will need `cargo` to build the daemon.

```bash
cargo build --release
```

## Running the Network

A complete deployment of AnonGuard consists of three components:

### 1. The Directory Authority (Tracker)
The tracker acts as a rendezvous point for reverse relays and serves a list of active nodes to clients.
```bash
./target/release/anonguard-daemon --tracker --listen 0.0.0.0:8080
```

### 2. The Volunteer Relay (Reverse Mode)
Volunteers run this node behind NAT. It connects to the tracker and waits for incoming tunnel requests.
```bash
./target/release/anonguard-daemon --reverse-relay --announce http://<tracker_ip>:8080
```

### 3. The Local Client (with Chaotic Morphing)
The user runs the client daemon locally. It automatically fetches the list of available volunteer nodes from the tracker, builds a multi-hop tunnel, and activates the Lorenz Chaos engine.
```bash
./target/release/anonguard-daemon \
  --listen 127.0.0.1:9050 \
  --fetch-from http://<tracker_ip>:8080 \
  --chaos
```

You can now point your web browser or `curl` to `socks5://127.0.0.1:9050` to route your traffic securely through the chaotic AnonGuard network!

## Research Applications

This software provides a fully reproducible environment for Oxford University PhD research in Network Security and Applied Cryptography. By toggling the `--chaos` and `--jitter` flags, researchers can generate massive PCAP datasets comparing standard TCP streams, Poisson-jittered streams, and Chaos-morphed streams, directly feeding these datasets into adversarial AI models to prove the efficacy of deterministic chaos in traffic obfuscation.
