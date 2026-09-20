# AnonGuard — Task J Mesh, Consensus, Transport, and Gateway Code Audit Findings

This report documents the 8 findings (1 Medium, 7 Low) identified during the line-by-line logical code review of `src/mesh/authority.rs`, `src/mesh/consensus.rs`, `src/mesh/transport.rs`, and `src/gateway/server.rs`.

## Summary Table

| File | Line(s) | Severity | Finding | Justification |
| :--- | :--- | :--- | :--- | :--- |
| `src/gateway/server.rs` | 168–192 | **Medium** | Unauthenticated outbound transport handshake in relay background registration loop. | The relay connects to directory authorities using `SecureTransportSession::client_handshake(stream, None)` without pinning authority verifying key. Rated Medium because while the transport layer is unauthenticated, the registration payload (`REGISTER_RELAY <json>`) carries an Ed25519-signed `RelayDescriptor` (`sign_with_key` line 161) and PoW challenge verified by the authority, preventing impersonation. |
| `src/mesh/authority.rs` | 285–320 | **Low** | Peer authority fetch error/timeout logged as `warn!` without failing local consensus. | In `reconcile_relays()`, peer fetch timeouts log a warning and increment `quorum_reconciliation_failures`. Rated Low because authority high availability requires that an unreachable peer authority does not prevent local consensus generation from available relays. |
| `src/mesh/authority.rs` | 83–126 | **Low** | Authority key file read/write failure triggers hardcoded `std::process::exit(1)`. | Key loading failures call `std::process::exit(1)`. Rated Low because immediate process termination is an intentional security design to prevent generating an ephemeral key on disk corruption, which would invalidate all previously signed consensus documents. |
| `src/mesh/consensus.rs` | 193–207 | **Low** | Invalid or unrecognized authority signatures skipped without rejecting consensus. | `verify_quorum()` ignores malformed or untrusted signatures as long as `quorum_threshold` valid signatures exist. Rated Low because standard M-of-N quorum consensus requires only $M$ valid signatures from trusted authorities; extra invalid signatures do not pollute valid quorums. |
| `src/mesh/consensus.rs` | 236–253 | **Low** | `merge_signatures_from()` returns 0 if consensus content SHA-256 digests differ. | If `self.compute_digest() != other.compute_digest()`, no signatures are merged. Rated Low because strict content digest validation is a necessary cryptographic backstop preventing cross-document signature injection. |
| `src/mesh/transport.rs` | 201–205, 255–259 | **Low** | Nonce counter overflow returns `io::Error` requiring session key rotation. | `send_counter` and `recv_counter` checked additions fail on overflow. Rated Low because $2^{64}-1$ frames is practically unreachable, but explicit error handling prevents ChaCha20-Poly1305 AEAD nonce reuse. |
| `src/mesh/transport.rs` | 226–233, 246–253 | **Low** | Hardcoded 15-second frame header and payload read timeouts in `read_frame()`. | `read_exact()` calls are wrapped in 15-second timeouts. Rated Low because hardcoded 15s timeouts are a standard, intentional Slowloris DoS defense for streaming framed TCP connections. |
| `src/gateway/server.rs` | 255–273 | **Low** | `IpGuard::drop` decrements `ip_connections` tracking map inside a spawned `tokio::spawn` task. | Per-IP active connection count is decremented asynchronously when `IpGuard` drops. Rated Low because acquiring a write lock on `ip_connections` inside the spawned task guarantees thread-safe, atomic map updates without race conditions or leak. |

## Detailed Breakdown

### 1. Gateway Server: Unauthenticated Registration Handshake (Medium)
In `src/gateway/server.rs:168-192`, when an AnonGuard relay registers with directory authorities, it initiates an outbound connection via `SecureTransportSession::client_handshake(stream, None)`. The `None` parameter indicates that the client does not enforce a pinned authority identity key during the transport-layer Diffie-Hellman exchange.

- **Risk**: An active network attacker could perform a MITM attack on the transport framing layer between the relay and the directory authority.
- **Mitigation**: The registration payload (`REGISTER_RELAY <json>`) contains a `RelayDescriptor` signed with the relay's long-term Ed25519 private identity key (`desc.sign_with_key(&identity_key)` at line 161) and a solved Proof-of-Work challenge. The authority verifies both the cryptographic signature (`desc.verify_identity()` in `authority.rs:192`) and PoW solution (`verify_pow()` in `authority.rs:197`), preventing an attacker from altering the node identity or impersonating another relay.

### 2. Directory Authority: Non-Fatal Peer Reconciliation (Low)
In `src/mesh/authority.rs:285-320`, `reconcile_relays()` attempts to fetch active relay descriptors from configured peer authorities with a 500ms timeout. If a peer authority fails to respond or returns an error, the error is logged as a warning (`warn!`), the metric `quorum_reconciliation_failures` is incremented, and local consensus generation continues with the local relay view. This ensures directory authorities remain resilient against single-node network outages.

### 3. Directory Authority: Fatal Key Load Errors (Low)
In `src/mesh/authority.rs:83-126`, `load_or_create_signing_key()` encounters an unreadable or corrupted key file on disk, it explicitly logs a fatal error and calls `std::process::exit(1)`. This fail-closed design prevents the directory authority from silently generating a fresh ephemeral key, which would break authority signature pinning across the mesh.

### 4. Directory Consensus: Resilient Quorum Verification (Low)
In `src/mesh/consensus.rs:193-207`, `verify_quorum()` iterates through authority signatures attached to a consensus document. If a signature is corrupt or originates from an unrecognized authority ID, it is skipped. The document is declared valid as long as the total count of valid signatures from recognized authorities meets or exceeds `quorum_threshold`.

### 5. Directory Consensus: Digest-Guarded Signature Merging (Low)
In `src/mesh/consensus.rs:236-253`, `merge_signatures_from()` allows a client to aggregate signatures from multiple directory authorities into a single `ConsensusDocument`. Before adding any signature, it verifies that `self.compute_digest() == other.compute_digest()`. If the digests differ, 0 signatures are merged, guaranteeing that authorities cannot co-sign divergent consensus states.

### 6. Transport: AEAD Monotonic Nonce Counter Guard (Low)
In `src/mesh/transport.rs:201-205` and `255-259`, `write_frame()` and `read_frame()` increment 64-bit monotonic counters (`send_counter`, `recv_counter`) used to construct 96-bit ChaCha20-Poly1305 nonces. If a counter exceeds `u64::MAX`, `checked_add(1)` returns `None`, causing the stream operation to fail with an explicit `io::Error`. This prevents nonce reuse under AEAD encryption.

### 7. Transport: Slowloris DoS Frame Timeouts (Low)
In `src/mesh/transport.rs:226-233` and `246-253`, `read_frame()` wraps header (4 bytes) and payload reads in a hardcoded 15-second `tokio::time::timeout`. If a remote peer opens a connection and holds it open without transmitting frame bytes, the read times out and returns `io::ErrorKind::TimedOut`, closing the socket and protecting memory/file descriptor limits.

### 8. Gateway Server: Asynchronous IP Connection Teardown (Low)
In `src/gateway/server.rs:255-273`, active client connections use `IpGuard` RAII structs to track per-IP connection limits (`MAX_CONCURRENT_PER_IP = 64`). Upon drop, `IpGuard` spawns an asynchronous tokio task to acquire a write lock on `ip_connections` and decrement the connection count. Lock acquisition ensures atomic map mutation without race conditions or memory leaks.
