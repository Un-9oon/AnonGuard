# AnonGuard Architecture and Design Choices

This document outlines architectural decisions, trade-offs, and future considerations for AnonGuard.

## Circuit Lifecycle and Teardown
- **Lifetime**: Circuits are intentionally bound to the active session. Once a stream is closed or a network error occurs, the circuit is destroyed via a `DESTROY` cell propagated recursively downstream.
- **Key Rotation**: Mid-circuit key rotation is *not* implemented. For long-lived proxies, this means a single set of derived X25519 session keys is used for the entire life of the circuit. This is a deliberate design choice prioritizing low-latency proxying over extreme duration, as the sequence number (32-bit) safely guards up to ~4 billion cells (4 TB of data) before exhaustion.
- **Teardown**: When a relay encounters an unrecoverable AEAD tag failure or TCP closure, it scrubs local state, sends `DESTROY` downstream, and de-allocates the `RelayCircuitHop` struct.

## Flow Control and Backpressure
- Currently, AnonGuard's internal multiplexer relies heavily on the underlying TCP stream's natural backpressure. 
- When a fast writer (e.g., local proxy) writes to the gateway, the bytes are packed into fixed-size cells. If a downstream relay is slow or congested, the TCP buffer fills, which naturally suspends the asynchronous `tokio` read tasks. 
- **Future Item**: A dedicated window-based flow control protocol at the cell layer to handle granular stream congestion without blocking the entire circuit multiplexer.

## Cell Formats
- **Fixed Cells (Current)**: AnonGuard uses fixed 2048-byte cells (upgraded from 1024 bytes to accommodate post-quantum ML-KEM-768 public keys and ciphertexts during circuit establishment). This minimizes metadata leakage through packet lengths but adds padding overhead.
- **Hybrid Post-Quantum Key Exchange**: Handshake cells (`CREATE`/`CREATED`, `EXTEND`/`EXTENDED`) perform hybrid key agreement combining classical X25519 ECDH (32B) with post-quantum ML-KEM-768 / FIPS 203 (1184B public key, 1088B ciphertext). Hop session keys are derived from the 64-byte concatenated secret `$S = S_{\text{X25519}} \| S_{\text{ML-KEM-768}}$`.
- **Variable-Length Cells (Future)**: We are considering variable-length cells or cell-batching to improve raw bandwidth for bulk downloads. This is an acknowledged trade-off between strict Traffic Analysis (TA) defense and usability.
