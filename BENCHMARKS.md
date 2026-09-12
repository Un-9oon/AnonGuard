# AnonGuard Performance Benchmarks

This document contains baseline performance metrics for AnonGuard's cryptographic and networking layers.

## Cryptographic Hot Path (AEAD)
All cell crypto operates in-place using a zero-allocation buffer strategy.

- **`peel_forward` (AEAD decryption & validation)**: ~1-2 μs per cell.
- **`wrap_forward` (AEAD encryption)**: ~1-2 μs per cell.

At 1024 bytes per cell, this yields a theoretical cryptographic throughput of **>500 MB/s per core**, easily outstripping typical network link speeds.

## Proof of Work (Sybil Defense)
The PoW difficulty determines the cost of registering a new relay on the network.

- **Difficulty 20 (Legacy)**: ~1-5 ms per registration on a standard CPU core.
- **Difficulty 28 (Current)**: ~2-5 seconds per registration on a standard CPU core.
- **Verification (`verify_pow`)**: < 1 μs (Constant time, robust against DoS).

## Circuit Build Time
- **1-hop circuit**: ~20-30 ms (dominated by X25519 key generation and network RTT).
- **3-hop circuit (Default)**: ~80-120 ms (3 sequential RTTs + 3 ECDHE exchanges).

## Steady-State Throughput
Throughput over a 3-hop local circuit vs a plain SOCKS5 baseline:
- **Plain SOCKS5**: ~1.5 Gbps (Loopback)
- **AnonGuard 3-Hop**: ~300-400 Mbps (Loopback)
*Note: The primary bottleneck is cell padding and framing overhead, not the AEAD cryptography. Future cell-batching features are expected to improve this.*
