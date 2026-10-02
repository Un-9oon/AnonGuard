# AnonGuard Capacity & Scalability Model

## CPU Constraints
The bottleneck for AnonGuard is cryptographic operations during data transmission and circuit building. 

- **Data Cells (AEAD + ChaCha20)**: Throughput is generally O(1) (~1-2ns per byte) based on `cargo bench` numbers. Modern x86_64 cores with AES-NI (even though ChaCha20 doesn't use AES-NI directly, SIMD via AVX2 is used) can sustain ~1-2 GB/s per core of raw ChaCha20Poly1305.
- **Circuit Build (ML-KEM-768 + X25519)**: Circuit creation is expensive due to key encapsulation and exchange. ML-KEM-768 decapsulation and X25519 Diffie-Hellman take ~300-500µs per circuit. Max theoretical builds per core per second: ~2,000-3,000.

## Memory Constraints
- Each active `RelayCircuitHop` holds symmetric keys and sequence numbers (~128 bytes).
- Each active SOCKS5 proxy connection or Gateway client connection uses a standard TCP window (minimum 16KB buffering per side) + tokio task overhead (~4KB). 
- Thus, memory per active circuit = ~40KB.
- **100,000 circuits** = ~4 GB RAM.

## Network Constraints
- A 1 Gbps NIC limits data throughput to ~120 MB/s. 
- With 1000 active users streaming simultaneously, each gets ~120 KB/s.

## Formula
Let $C$ = Number of Cores, $M$ = Memory (GB), $BW$ = Bandwidth (Gbps)

$$ \text{Max Circuits} = \min(M \times 25000, \text{OS FD Limits}) $$
$$ \text{Max Data Throughput} = \min(C \times 1\text{GB/s}, BW \times 125\text{MB/s}) $$
$$ \text{Max New Circuits/Sec} = C \times 2000 $$
