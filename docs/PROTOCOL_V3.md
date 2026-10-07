# AnonGuard protocol v3

Status: implemented experimental protocol, requiring independent review. This document describes the standard onion gateway, not historical multipath or tracker experiments. All integer wire fields are big endian.

## Bootstrap and directory

Every authority endpoint is bound to an operator-provided Ed25519 public key. The daemon requires distinct identities, endpoints and keys, at most 16 authorities, and a quorum strictly greater than two thirds of the configured authorities. Operator independence is an external trust assumption, not something different keys prove.

Directory transport starts with `AGDIR003`. The initiator and responder exchange ephemeral X25519 public keys. The responder signs a domain-separated transcript containing the version, both ephemeral keys, authentication flag and its Ed25519 identity. Pinned clients reject missing or incorrect authentication and non-contributory DH. HKDF incorporates the transcript and derives separate directional ChaCha20-Poly1305 keys. Frames carry a four-byte ciphertext length and ciphertext including a 16-byte tag; plaintext is bounded to 1 MiB. Monotonic 64-bit counters produce directional nonces; exhaustion closes the session. Frame reads and writes have deadlines. Unauthenticated test transport is not an anonymity bootstrap.

Relay descriptors use domain `AnonGuard-RelayDescriptor-v3`, length-prefixed relay ID and host, followed by port, X25519 key, Ed25519 identity, exit flag, PoW nonce and registration timestamp. Relay IDs are at most 128 bytes, hosts at most 253 bytes, ports nonzero and signatures exactly 64 bytes. Descriptors require strict Ed25519 verification and fresh registration PoW. Authorities bound their directory to 512 relays. The current PoW difficulty is 26 bits; admission is probabilistic and does not prove independent operators.

A snapshot digest binds the validity interval and deterministically sorted relay fields. Only signatures over the identical snapshot combine; descriptor intersection is not consensus. Authorities freeze one signed view per 300-second epoch, valid for 600 seconds, and persist their votes before publication. Client acceptance persists the highest epoch and digest before replacing the entire directory. Same-epoch conflicts, rollback, duplicate relay identities/endpoints and invalid descriptors fail acceptance. Expiry is exclusive and prevents new circuits and directory-authorized mesh connections. Existing circuits have a separate lifetime bound.

This is quorum-signed snapshot distribution. Inconsistent initial views, partitions or failed reconciliation can prevent quorum until another epoch. It is not a complete Byzantine agreement or liveness protocol.

## Relay links and circuit establishment

Every adjacent relay link uses TLS 1.3 with mandatory ALPN `anonguard/3`. A self-signed Ed25519 certificate must contain the directory-pinned public key, be currently valid, and pass TLS handshake signature verification. Early data and resumption are disabled. TLS authenticates the receiving relay; anonymous clients are not required to present a certificate. Wrong identity, protocol version or deadline closes the connection, without plaintext fallback.

Cells are 2048 bytes. The outer layout is circuit ID (4), sequence (4), command (1), stream ID (2), length (2), random padding (32), AEAD tag (16), payload (1987). The legacy `ephemeral_key` member is random padding, not a Sphinx header or proof of unlinkability. Layered routing consumes some payload capacity; callers use the circuit's maximum usable payload rather than the raw 1987-byte field.

CREATE carries 1222 bytes: hop index (1), client X25519 public key (32), ML-KEM-768 encapsulation key (1184), handshake context ID (4), version byte (3). CREATED carries fresh responder key material and an Ed25519 signature binding the v3 domain, context ID, hop index, relay identity and handshake key material. The client verifies the expected identity and hybrid response before adding a hop. HKDF binds the signed transcript to the combined X25519 and ML-KEM secrets. Ephemeral state is discarded and designated secret containers zeroize on drop; this is not a formal implementation proof.

EXTEND opens a pinned TLS connection to a directory-authorized next relay and creates a fresh random downstream link ID. Intermediate nodes translate incoming and outgoing IDs, validating the downstream ID on responses. The handshake context is retained inside encrypted transport. Independent directional hop keys and sequence counters protect onion layers. Link-local IDs are excluded from end-to-end AEAD associated data because relays translate them; TLS authenticates them on each link. Sequence metadata is authenticated, and sequence overflow terminates the circuit. The context remains visible to participating relays and does not prevent collusion.

Circuit construction has a 30-second overall deadline; extension has a 20-second deadline. Setup errors terminate the circuit. Entry guards are identity pinned and persisted, with a bounded initial set of three. A failed entry TCP/TLS connection receives a 60-second cooldown. Downstream failure does not rotate the guard. Missing guards do not expand the set without explicit operator state reset. Subnet diversity is a placement heuristic, not verified AS or operator independence.

## Stream state and flow control

One circuit serves one destination TCP stream, stream ID 1. RELAY opens the validated destination; CONNECTED and all stream responses must be authenticated as originating at the selected exit. Other hops cannot legitimately supply application DATA or acknowledgements.

DATA (7) carries bytes. DATA_ACK (8) carries the four-byte cumulative number of DATA cells consumed. Each direction permits at most 32 outstanding DATA cells. Acknowledgements must increase and cannot exceed transmitted data. Receivers grant credit after writing to their application or destination socket. Credit and cell sequence exhaustion are errors. DUMMY (9) carries padding, END (10) ends only the upload direction, and DESTROY (4) terminates the circuit. Malformed or inappropriate commands close the connection.

Application reads, cell queues and flow-control windows are bounded. Client upload buffering is 64 KiB. Client and exit each share DATA, coalesced ACK and DUMMY traffic on an anchored 20 ms clock, skipping missed ticks rather than producing a catch-up burst. DATA and ACK slots alternate when both are pending. This profile limits throughput and adds cover-traffic cost; it is not a proven website-fingerprinting defense. TLS record framing, TCP segmentation, setup, termination, intermediate jitter and network load remain observable.

After application EOF, the client drains buffered upload and sends END, while continuing acknowledgements and padding. The exit shuts only the destination write half, continues reading the response, and sends DESTROY after destination EOF and acknowledgement of all transmitted DATA. Destination writes and important relay writes are bounded to 30 seconds. Exit idle progress is bounded to 60 seconds and circuit lifetime to one hour. Failure closes the stream; there is no silent destination reconnection or transaction replay.

## Exit and local isolation boundaries

Exit policy validates all DNS results before connecting, blocks private/special addresses by default, and shares one deadline across DNS and address fallback. Unsupported `.onion` destinations are refused. Development private-network permission is an explicit insecure option. End-to-end application TLS remains the application's responsibility.

Linux protection creates a fresh namespace with loopback only. nftables input/output policies are DROP, allowing only the numeric loopback proxy endpoint and its loopback return traffic. Rules are installed before loopback is brought up. A private Unix socket bridges to the host gateway. The helper verifies namespace identity before listening, and bridge tasks cancel on kill-switch activation or helper failure. No host-wide firewall is modified. Protected applications must be launched in the namespace as an unprivileged user. Rules survive daemon exit; namespace removal is explicit after those applications stop.

Windows and macOS do not implement kernel isolation. Strict fail-closed startup refuses those platforms. Filesystem access, privileged escape, browser identity and applications outside the namespace are not protected.

## Migration and exclusions

Upgrade all authorities, relays and clients together. Previous descriptors and plaintext links are incompatible. Preserve private keys and durable v3 votes/rollback state; migrate legacy address-only guards through an explicit administrative reset. Corrupt security state fails startup. There is no automated authority-key rotation ceremony or seamless circuit rekey: fresh circuits replace expired ones, without replaying existing streams.

Multipath gateway transport is retired. Onion services, rendezvous discovery, censorship-resistant bridges, browser isolation and a universal public-network deployment are not implemented by v3. Research utilities remaining in the tree are not supported runtime features.
