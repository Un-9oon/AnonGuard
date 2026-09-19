# AnonGuard Documentation & Supply-Chain Integrity Guide

Welcome to the AnonGuard documentation directory.

## Documentation Index
- [`architecture.md`](architecture.md): Subsystem architecture, cell specifications, and design trade-offs.
- [`handshake_spec.md`](handshake_spec.md): Telecopic onion circuit handshake protocol & key agreement specification.
- [`key_rotation.md`](key_rotation.md): Session key derivation and forward secrecy guarantees.
- [`runbook_authority.md`](runbook_authority.md): Deployment runbook for Directory Authority nodes.

---

## Supply-Chain Integrity & Verification Guide

AnonGuard release binaries are built with embedded dependency Software Bill of Materials (SBOM) metadata via `cargo-auditable` and signed cryptographically using Sigstore `cosign`.

### 1. Verifying Binary Signatures with Cosign

To verify the integrity and origin of an official release archive or binary:

1. Install `cosign` (v2.0+):
   ```bash
   go install github.com/sigstore/cosign/v2/cmd/cosign@latest
   # Or via brew on macOS:
   brew install cosign
   ```

2. Download the release archive, signature bundle (`.sigstore.json`), and `SHA256SUMS`.

3. Verify the binary signature against the official AnonGuard repository identity:
   ```bash
   cosign verify-blob \
     --bundle anonguard-linux-amd64.tar.gz.sigstore.json \
     --certificate-identity-regex "^https://github.com/Un-9oon/AnonGuard/.*" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     anonguard-linux-amd64.tar.gz
   ```

4. Verify the SHA256 checksum:
   ```bash
   sha256sum -c SHA256SUMS
   ```

### 2. Inspecting Embedded Dependency SBOM with `cargo-auditable`

AnonGuard embeds its exact dependency tree directly inside compiled binaries using `cargo-auditable`. You can inspect and audit dependencies of a compiled `anonguard-daemon` binary without needing source code:

1. Install `cargo-auditable`:
   ```bash
   cargo install cargo-auditable
   ```

2. Audit the compiled binary for known vulnerabilities (VEX/Advisories):
   ```bash
   cargo audit binary ./anonguard-daemon
   ```

3. Extract the raw JSON dependency SBOM from the binary:
   ```bash
   cargo auditable get ./anonguard-daemon
   ```

This ensures full supply-chain transparency and tamper-evidence for production deployments.
