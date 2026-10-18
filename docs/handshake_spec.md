# Circuit handshake specification

The maintained specification is the [v6 protocol contract](PROTOCOL_V3.md).
This filename is retained as a navigation entry for older links; the former
1024-byte/X25519-only layout is obsolete and must not guide implementations.

Current circuit cells are 8192 bytes. Circuit creation/extension uses hybrid
X25519 + ML-KEM-768 key exchange, transcript binding and Ed25519 + ML-DSA-65
identity proofs. Adjacent TLS links have their own pinned, exporter-bound hybrid
authentication. Exact encodings, domain separation, counter rules and rejection
conditions belong to the linked contract and source, not an alternate layout here.

Upgrade clients, relays and authorities together following
[post-quantum migration](POST_QUANTUM_MIGRATION.md). Independent protocol review
and interoperability validation remain release gates.
