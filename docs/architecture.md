# AnonGuard v6 architecture

This maintained overview summarizes [the wire contract](PROTOCOL_V3.md).
Package/source version `0.2.0`, wire protocol v6 and Debian revision numbers are
separate identifiers. The protocol filename is retained for existing links.

## Roles and trust boundaries

A client authenticates a fresh, exact-snapshot directory quorum greater than two
thirds of configured authority identities. It builds a 3–8-hop path (CLI default
3–5), using a persistent pinned guard, non-exit middles and an exit. Prefix and
endpoint diversity do not prove independent ownership. A bridge sees its client's
network address; an exit sees destination metadata and plaintext unless protected
by destination TLS. Relays may collude and strong observers may correlate flows.

Adjacent links use pinned TLS 1.3 with mandatory cover-policy ALPN (`anonguard/6` or `anonguard/6-cover40`), hybrid
X25519/ML-KEM-768 key exchange and exporter-bound Ed25519 plus ML-DSA-65 proofs.
Circuit handshakes separately bind hybrid key exchange to the transcript and
relay identity. This composition still needs independent review; it is not QKD
or universal quantum protection.

## Cells and flow control

Cells are 8192 bytes, with a 61-byte header and 8131-byte payload. The header's
random padding is not a Sphinx header. Layered encryption and authentication are
specified in the wire contract; fixed cells do not imply fixed IP packet sizes.
`src/onion/flow.rs` implements a 32-cell authenticated cumulative delivery window.
Padded sessions add per-stream bounded queues, round-robin scheduling and a
maximum of 16 streams. TCP backpressure remains relevant; cell-layer credit is
already implemented rather than future work.

## Lifecycle and shaping

The legacy single-destination path and optional multiplexed padded sessions have
separate lifecycles. Padded sessions have a 300-second hard lifetime and bounded
profile-specific idle/volume closure. Failed connections are closed without
transparent application replay. Mid-circuit key rotation is not implemented;
new circuits establish fresh keys. Forward sequence exhaustion and per-origin
29-bit backward counter exhaustion fail closed; there is no safe-capacity claim
based on four billion interchangeable cells.

Mandatory covered links use bounded buffers and authenticated fixed envelopes.
Strict cover uses 20-ms slots; session profiles schedule cells within that link.
The writer preserves phase for ordinary write costs and skips missed slots.
Optional fixed-window closure and research samplers have documented costs and
limits in [scheduling](MULTIHOP_SCHEDULING.md) and [sessions](PADDED_SESSIONS.md).
No schedule conceals arbitrary TCP congestion or global timing correlation.

## Device and browser boundary

Native Linux setup provisions client or non-exit volunteer roles. Restricted
headless containment and managed Firefox ESR are separate profiles with separate
acceptance gates. The browser uses Mozilla privacy controls and an isolation
extension; a maintained ESR, signed addon and authentic operator configuration
are prerequisites. Routing cannot protect a compromised host or conceal a
person's logged-in account. Read [readiness](PRODUCTION_READINESS.md) for open gates.
