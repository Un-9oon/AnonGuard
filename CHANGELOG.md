# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-09-12

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
