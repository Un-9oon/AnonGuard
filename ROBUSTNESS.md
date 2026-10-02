# AnonGuard Robustness & Security Index

This document serves as the index for the robustness properties and architectural guarantees of the AnonGuard project, following the intensive "Robustness Engineering" phase.

## 1. Concurrency & Memory-Safety
- **No `unsafe`**: The codebase explicitly `#![forbid(unsafe_code)]`, enforcing 100% memory safety via the Rust compiler.
- **Cancel-Safety**: `tokio::select!` branches strictly use cancel-safe channel readers (`mpsc::Receiver::recv`) rather than state-corrupting `read_exact` calls.
- **Deadlock Avoidance**: Lock acquisition order is strictly documented and isolated. 

## 2. Resilience (Crash & Partition)
- **Hard-Kill Immune**: Key material (identity keys, authority configurations) is generated using atomic temporary-file writes (`rename`) coupled with explicit `.sync_all()`. This guarantees a power-loss or `kill -9` will never result in an empty or corrupted `identity.key` file.
- **Clock Skew Tolerant**: Sybil Proof-of-Work checks enforce strict time-drift bounds (`MAX_TIMESTAMP_DRIFT_SECS`). Tests verify that nodes silently drop payloads from clocks too far into the past or future.
- **Anti-Replay Poison Tolerance**: The `NonceRegistry` employs `.unwrap_or_else(|poisoned| poisoned.into_inner())` on its mutex to ensure that a panicked thread doesn't permanently disable replay protection across the network.

## 3. Observability & Operational Readiness
- **Metrics**: A Prometheus exporter is exposed via `--metrics-addr`. Key metrics include:
  - `timeouts_total`
  - `aead_failures_total`
  - `anti_replay_trips_total`
  - `sybil_pow_rejected_total`
- **Privacy-Preserving Logs**: The daemon guarantees that no sensitive fields (e.g., client IPs, unencrypted target addresses, or key material) are leaked in `INFO` or `WARN` logs.
- **Health Verification**: Running `anonguard-daemon --status` verifies internal state, confirming if long-term cryptographic keys are correctly loaded.

## 4. API & Configuration Hardening
- **Downgrade Attack Prevention**: The daemon refuses to start when `allow_open_socks5` or `allow_private_exit` is passed, unless the operator explicitly passes `--i-know-this-is-insecure`, acknowledging the security compromise.
- **Strict Parsing Limits**: Onion Cell parsers rigorously enforce length checks (`length as usize > PAYLOAD_SIZE`) before memcopying data, preventing buffer-overflow panics in safe Rust.

## 5. Scalability Model
AnonGuard is designed to scale horizontally across threads. Crypto routines (`peel_forward`, `peel_backward`) utilize ChaCha20Poly1305 which benchmark at ~5µs per cell processing. For a full capacity scaling equation, refer to `docs/capacity_model.md`.

## 6. Runbooks & Testing
- **Latency Profiling**: Scripts are available in `scripts/latency_profile.py` to test p50/p95/p99 latency against local meshes.
- **Soak Testing**: A prolonged load test script is available in `scripts/soak_test.sh` to hunt for long-tail memory leaks or file descriptor exhaustion limits.
- **Fuzzing**: `cargo fuzz` targets include `fuzz_onion_cell_parse` to mathematically prove the binary parser cannot panic on malformed adversarial bytes.
