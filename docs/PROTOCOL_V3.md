# AnonGuard protocol v6

Status: implemented experimental coordinated protocol migration, requiring
independent review and fresh release-commit validation. The historical filename
is retained for existing links; this document describes **v6**, not v3 or v5.
Integer wire fields are big endian unless an enclosing standard says otherwise.

## Composite identities and trust bootstrap

A network identity comprises independent Ed25519 and ML-DSA-65 key components.
Both signatures are mandatory; verification is an AND operation. The public-key
encoding is `AGID0001` (8 bytes), Ed25519 public key (32), and ML-DSA-65 public key
(1952): 1992 bytes total. Its 32-byte pin is SHA-256 over domain
`AnonGuard-HybridIdentity-Pin-v1` followed by that exact encoding. Pins are not raw
Ed25519 keys despite having the same length.

A signature encoding is `AGID0001` (8), Ed25519 signature (64), ML-DSA-65 signature
(3309): 3381 bytes. A self-contained network proof carries the full public-key
encoding followed by this signature encoding: 5373 bytes. The common primitive
signs `AnonGuard-HybridIdentity-Proof-v1`, the composite pin, a one-byte purpose
length and purpose, then an eight-byte message length and message. Network
identity proofs use purpose `network-identity-v6`; directory transport uses its
separate `directory-transport-v4` purpose. Proof JSON uses bounded base64 encoding.
Legacy 64-byte signatures are rejected.

Private storage is an explicit 72-byte paired-seed bundle: `AGID0001`, Ed25519
seed (32), ML-DSA seed (32). Production generation uses independent OS randomness.
Publication is exclusive and durable; corrupt or legacy 32-byte identity files
are refused rather than silently overwritten. Unix keys deny group/other access.
Deterministic fixture constructors are test facilities, not production key setup.

The operator authenticates authority identity/address/composite-pin bindings
out of band. Native bootstrap JSON requires version 6, at most 16 distinct
bound authorities and quorum strictly greater than two thirds. Different keys
are not evidence of independent operators. Private transport bindings, guards,
revocation and accepted snapshots bind the new identity meaning explicitly.

## Directory transport and consensus

The initiator sends `AGDIR004`, ephemeral X25519 public key (32), and ephemeral
ML-KEM-768 encapsulation key (1184): 1224 bytes total. The responder returns
`AGDIR004`, fresh X25519 public key (32), ML-KEM ciphertext (1088), full composite
public-key encoding (1992), and mandatory dual signature (3381). The proof
covers domain `AnonGuard-directory-transport-v4/initiator/responder` followed by
the exact complete initiator hello and unsigned responder response. The pin is
checked against the full response identity before accepting the proof.

Both parties reject non-contributory X25519. Before encapsulation, ML-KEM public
keys must have the correct length and every encoded 12-bit polynomial coefficient
below 3329. The two shared secrets form `X25519 || ML-KEM`, 64 bytes. HKDF-SHA256
uses a salt hashing the transcript and signature, with distinct v4 directional
labels. Each side exchanges an encrypted role-specific confirmation frame before
returning a usable session. The total handshake has a ten-second deadline.
Missing identities, old `AGDIR003` and authentication failure have no fallback.
The responder is identity authenticated; initiators remain anonymous unless a
higher-level operation authenticates them.

Frames carry a four-byte ciphertext length and ChaCha20-Poly1305 ciphertext with
16-byte tag. Plaintext is at most one MiB. Directional nonces use four zero bytes
and a monotonic eight-byte counter. Exhaustion, tampering, replay, I/O error or
cancelled partial operation poisons the retained session; reconnect instead of
resuming a partially consumed stream. Frame I/O deadlines are bounded.

Directory documents use an authenticated `AGDOC006` frame containing a four-byte
plaintext-document length, followed by exactly the required number of encrypted
frames. Total length is 1..6 MiB, at most six chunks; nonfinal chunks are exactly
one MiB and the final chunk has the exact remainder. The entire document has a
15-second deadline. Raw JSON fallback and malformed envelopes are refused.
Control RPCs continue using individual frames. Connection limits remain necessary
because timeouts do not preempt synchronous cryptographic computation.

Relay descriptors use domain `AnonGuard-RelayDescriptor-v6`: length-prefixed
ASCII node ID and canonical host, port, X25519 onion key, composite identity pin,
exit flag, PoW nonce and registration timestamp. Node IDs are at most 128 bytes;
hosts are canonical IP literals or lowercase ASCII DNS names of at most 253
bytes. Ports must be nonzero. A self-contained dual proof authenticates the
entire descriptor. Registration also requires fresh PoW (production default 26
bits), with bounded replay retention. PoW does not prove operator independence.

Snapshot digests use `AnonGuard-Consensus-v6`, validity times and deterministically
sorted relay fields. Exact-snapshot proofs combine; descriptor intersection does
not form consensus. Duplicate composite or component identities are rejected at
admission/quorum boundaries. Limits remain 512 relays and 16 authority signatures.
Authorities freeze and durably sign one view per 300-second epoch, valid for 600
seconds. Clients persist accepted epoch/digest before directory replacement;
rollback, same-epoch conflict and invalid descriptors fail closed. Concurrent
reconciliation has bounded per-peer deadlines. Partitions and divergent frozen
views can prevent quorum until a later epoch: this is quorum-signed distribution,
not a complete Byzantine agreement/liveness protocol.

## Relay TLS authentication and hop-local cover

Adjacent links require TLS 1.3, ALPN `anonguard/6`, and the hybrid TLS group
`X25519MLKEM768`; classical-only group negotiation is excluded. Allowed ciphers
are AES-256-GCM or ChaCha20-Poly1305. Early data, tickets and resumption are disabled.
The current certificate signature/SPKI remains Ed25519. Its custom extension
`2.25.2676937280591097606` carries the composite public identity; the certificate
must have exactly one such extension, match the expected composite pin and Ed
component, be valid now, and pass TLS signature verification.

Before returning the stream, the initiator sends a fresh 32-byte challenge. The
responder returns a 5373-byte network proof over
`AnonGuard-relay-channel-auth-v6`, ALPN, challenge, and a 32-byte TLS exporter using
label `AnonGuard-link-auth-v6` and challenge context. Both identity components
verify against the pinned composite identity. TLS and supplemental proof steps
have separate bounded deadlines. There is no accept-all certificate workaround,
plaintext path or Ed-only fallback. Anonymous clients do not present identity
certificates. This custom composition requires independent protocol review;
external web PKI, addon signing and operating-system trust are separate surfaces.

After authentication, each direction uses a hop-local covered stream: a fixed
8196-byte encrypted-TLS envelope every 20 ms while the link is alive, with a
random starting phase. Four envelope bytes precede either an 8192-byte onion cell
or random link-local dummy payload. Dummies do not reach the onion parser.
Queues are bounded; partial cells, invalid envelopes, prolonged silence or blocked
writes close the link. Missed scheduling opportunities do not cause catch-up
bursts. Dropping a stream cancels its workers. Cover begins after authentication
and ends with connection lifetime. Handshake boundaries, lifetime, congestion and
multi-link correlation remain observable. Scheduled cost is about 409.8 kB/s per
direction per link before TLS/TCP overhead, regardless of session profile.

## Onion cells and circuit establishment

V6 cells are **8192 bytes**, with 61-byte header and 8131-byte payload. Header:
circuit ID (4), sequence (4), command (1), stream ID (2), length (2), random
padding (32), AEAD tag (16). Random padding is not a Sphinx header. Onion layers
consume usable payload capacity; callers must use circuit-derived capacity.

CREATE carries 1222 bytes: hop index (1), client X25519 key (32), ML-KEM-768 key
(1184), handshake context ID (4), version byte (6). CREATED carries responder
X25519 key (32), composite identity pin (32), self-contained dual proof (5373),
and ML-KEM ciphertext (1088): **6525 bytes**. Exact version/length and composite
pin verification are required. Domain `AnonGuard-handshake-v6` binds context ID,
hop index, pin and all exchange material; context-bound HKDF combines the two
shared secrets before creating directional onion keys.

EXTEND authenticates the directory-authorized next relay, uses a fresh downstream
link ID, and preserves the encrypted handshake context. Intermediates translate
link-local circuit IDs and validate downstream responses. Sequence metadata is
AEAD authenticated; overflow closes circuits. Context visibility does not prevent
relay collusion. Circuit construction and extension have bounded deadlines.

Paths contain 3..8 hops, CLI default range 3..5, with persistent identity-pinned
entry guards, non-exit middles and an exit. Entry-only failure cooldown is 60
seconds; downstream failure does not rotate the guard. Subnet diversity is a
heuristic, not verified AS/operator independence. Longer routes are not inherently
more anonymous.

## Streams, sessions and exits

Legacy single-destination circuits retain bounded DATA/ACK windows, directional
keys, upload half-close and acknowledged response termination. Optional padded
sessions authenticate an exact profile inside the circuit and multiplex bounded
streams. Balanced schedules 40 ms; strict 20 ms; research RMT/Poisson modes use
bounded samplers. Session DATA warm-up, idle duration/volume tails and finish
handshakes are separate from mandatory 20-ms adjacent-link cover. The profile
encoding remains its internal version 1 inside the mandatory v6 channel.

SOCKS credentials are local context labels, not password authentication; they are
not sent to relays. Browser isolation supplies distinct contexts; ordinary
no-auth clients share the default context. Sessions cap streams, queues, credit
and lifetime. Failed streams are closed/reset without direct fallback or
transparent transaction replay. The current larger cells and mandatory link cover
change throughput and cost materially; old v5 performance measurements do not
measure v6.

Exit policy validates all DNS results, rejects private/special ranges by default,
and bounds DNS/connect fallback. Explicit private-exit permission is lab-only.
`.onion` services are unsupported. End-to-end HTTPS and account/cookie identity
remain application responsibilities. Linux native firewall and restricted
headless containment provide separate documented trust boundaries; neither
protects against a compromised administrator/kernel or arbitrary host IPC.

## Coordinated migration and evidence limits

Upgrade authorities, relays, clients and generated deployment artifacts together.
V5 ALPN, old directory transport, raw Ed pins/signatures, old cell sizes and
legacy identity bundles are incompatible. Guard/transport/snapshot version checks
must not be bypassed. Back up and protect existing keys, votes, revocation journals,
guards and rollback state; perform an explicit reviewed migration with freshly
authenticated composite pins. Do not erase journals or silently reinterpret old
pins to make startup pass. Revocation policy version 2 retires composite pins;
it remains offline, quorum authorized and effective at coordinated restart.

No automated ceremony proves continuity from a legacy Ed-only trust root to a new
PQ identity. Independent crypto review, external known-answer/interoperability
validation, fuzzing, current-commit VM acceptance and traffic-analysis experiments
remain release gates. Post-quantum algorithms here are conventional software;
RMT is a classical statistical sampler, not quantum hardware or QKD. No complete
quantum protection, undetectability, global correlation resistance or Tor
superiority is established by this specification.
