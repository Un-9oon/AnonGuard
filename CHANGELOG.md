# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-09-17

### Security & Hardening
- **CRITICAL**: Migrated onion circuit and transport Key Derivation Functions (KDF) to RFC 5869 HKDF-SHA256 (V-001).
- **CRITICAL**: Added 7 new fuzz targets covering all untrusted-input attack surfaces (`peel_forward`, `decode_extend`, etc.).
- **HIGH**: Fixed timing side-channel in Quantum RMT engine (GUE sampling) by using constant-time bounded iteration (V-002).
- **HIGH**: Implemented `NonceRegistry` to track and prevent PoW nonce replay within the validity window (V-006).
- Reduced PoW timestamp drift tolerance from 10 minutes to 5 minutes to limit replay windows.
- Replaced stub soak test with a full multi-relay concurrent load and E2E verification test.
- Added explicit AEAD bit-flip tampering rejection test.

### CI/CD & Operations
- Enforced `cargo fmt` checking and benchmark compilation gating (`cargo bench --no-run`) in CI pipeline.
- Fixed `crypto_bench.rs` compilation type mismatch errors.

## [0.1.0] - 2026-09-12
### Security
- **CRITICAL**: Fixed a vulnerability where relays could be MITM'd if an attacker intercepted traffic during handshake. Relays now strictly pin and verify the expected X25519 Ephemeral key against the Ed25519 identity key signature.
- **CRITICAL**: Migrated cryptographic hot path from `HMAC-SHA256-then-ChaCha20` to `ChaCha20-Poly1305` Authenticated Encryption with Associated Data (AEAD) to prevent malleability and CCA attacks.
- Bumped Proof-of-Work (PoW) default difficulty from 20 bits to 28 bits, increasing registration cost.

### Performance
- Completely eliminated heap allocations (`Vec`) from the per-cell cryptographic processing hot path, upgrading the AEAD loops to operate 100% in-place.
- Changed layout of `OnionCell` to natively support allocation-free stream decryption.

### Operations & Docs
- Integrated strict `#![deny(dead_code, unused_variables)]` compiler flags.
- Added CI workflow for `cargo audit` to catch dependency vulnerabilities.
- Pinned all cryptographic dependencies in `Cargo.toml`.
- Added operational runbooks (`runbook_authority.md`, `key_rotation.md`) and protocol specification (`handshake_spec.md`).
