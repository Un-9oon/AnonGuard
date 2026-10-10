# Coordinated v6 post-quantum migration

The network now requires Ed25519 AND ML-DSA-65 identity proofs. Both signatures
must pass; there is no classical-only fallback. This uses post-quantum algorithms
on ordinary computers, not quantum hardware or QKD. Protocol review and live
acceptance remain release gates.

Implemented network boundaries:

- Composite pins bind the version and both public keys. Descriptors, authority
  votes, retirement policies and circuit responses carry full dual proofs.
  Quorum/admission checks reject reused component keys under different identities.
- Directory transport AGDIR004 uses ephemeral X25519 + ML-KEM-768, mandatory
  pinned dual authentication, transcript-bound directional keys and bilateral AEAD
  key confirmation. Missing pins, old versions and noncanonical KEM keys refuse.
- Relay TLS requires anonguard/6, only X25519MLKEM768 key exchange, AES-256 or
  ChaCha20, no resumption/early data, a certificate-bound composite identity,
  and dual proof bound to a fresh challenge and TLS exporter before cells pass.
- v6 onion cells are **8192 bytes**, with a 6525-byte CREATED payload. This explicit
  size change accommodates the 5373-byte self-contained composite proof without
  truncation. Per-hop authentication ordering is preserved. All participants must
  upgrade together; these cells cannot communicate with v5 relays.
- Adjacent links independently schedule 8196-byte cell/padding envelopes every
  20 ms. Padding is discarded before onion sequence/flow-credit processing.
  Queues, deadlines, flush and graceful drain are bounded. Cover costs roughly
  **409.8 kB/s per direction per active link before TLS**, about four times the
  former 2048-byte/20-ms cell size. This cost must be measured and budgeted.
- Compact base64 proofs and authenticated document segmentation preserve the
  1-MiB frame cap: at most six chunks/six MiB per document. Failed or cancelled
  frame/document operations permanently poison a retained session.

## Migration ceremony

1. Stop the owned test deployment and privately archive identities, authority
   vote journals, guard pins, directory rollback and cumulative retirement state.
   Do not overwrite files or delete journals to bypass startup refusal.
2. Generate new paired identities under **new protected paths** with
   `anonguard-daemon --initialize-identity --identity-key-path NEW_FILE`.
   The 72-byte format holds independent private seeds. Legacy 32-byte files fail
   closed. Authenticate `public_key_hybrid_pin` and the full public identity to
   every operator through an independent trusted channel.
3. Update every authority/client/relay/bridge pin and native bootstrap version
   (now 6). Preserve existing guard assignments using an independently
   authenticated old/new identity mapping. Do not silently select new guards.
4. Migrate guards explicitly to `protocol_version: 6` and composite pins. Old guard
   formats and directory rollback files are refused. Establish a fresh v6 authority
   snapshot through a trusted operator ceremony while archiving rollback evidence.
   Previous-protocol digests are not v6 digests.
5. Preserve all retired identities and authenticated successor mappings. Advance
   retirement generation and sign v2 policies against the exact new authority set.
   Preserve enrolled journals; never unenroll by deleting a journal. Old authority
   votes cannot be reused under replacement keys. Initialize new journals under
   new paths after a recorded maintenance epoch.
6. Upgrade participants together; verify old-version refusal, exact quorum,
   restart/persistence, relay loss, response draining and leak tests. Mixed versions
   deliberately produce an outage rather than weaker authentication.

Do not rehearse this ceremony first on a public anonymity network. Operator
identity mapping and configuration edits are administrative trust actions, not
automatic proof that old and new operators are the same entity.

## Evidence and remaining limits

RustCrypto ml-dsa is pinned to 0.1.1 with zeroization. The publisher states that
its implementation has not been independently audited. It is beyond the patched
ranges of its [timing advisory](https://github.com/RustCrypto/signatures/security/advisories/GHSA-hcp2-x6j4-29j7)
and [decoding advisory](https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9).
ML-DSA is specified in [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
All 210 imported external Wycheproof ML-DSA-65 verification vectors passed locally.
This is backend evidence, not an independent protocol or side-channel audit.

External HTTPS/DoT, Mozilla signing and OS updates remain separate classical
trust surfaces. Timing, connection lifetime, congestion, colluding relays and
compromised endpoints do not become safe merely by adding PQ algorithms. Repeat
live correlation and resource measurements on v6; earlier v5 packet results do
not establish that this change fixes correlation.
