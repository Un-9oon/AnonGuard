# Private reverse rendezvous

The optional tracker is a private capability-based tunnel service. It is separate
from the signed directory and does not enroll NAT nodes into public onion circuits.
The onion gateway still refuses reverse entries. VMs are not required.

All tracker controls now require pinned TLS 1.3, X25519MLKEM768, the distinct
`anonguard-tracker/2` ALPN and an exporter-bound Ed25519 + ML-DSA-65 proof.
Legacy plaintext tracker commands and unpinned connections are refused.
This changes the tracker wire format; upgrade participants together.

Initialize a tracker identity using `--initialize-identity --identity-key-path PATH`.
Distribute its `public_key_hybrid_pin` over an authenticated operator channel.
Run `--tracker --listen HOST:PORT --identity-key-path PATH`. Preserve the paired
identity key across restarts. The public pin may be logged; private key bytes must
never be shared.

Provision a separate 256-bit random capability for each reverse relay, using a
cryptographically secure generator. Store its 64 lowercase hexadecimal characters
(with at most one trailing newline) in a private, non-symlink regular file, at most
65 bytes. On Unix, group/other permissions must be absent. Do not put capabilities
in public directory listings, shell history, screenshots or logs. Share the
capability only with authorized clients over a protected channel.

Run the volunteer with `--reverse-relay --announce HOST:PORT --tracker-key PIN
--reverse-token-file PRIVATE_FILE --identity-key-path RELAY_KEY`. Its node ID is
its stable composite identity pin encoded as exactly 64 lowercase hex characters.
Registration requires a fresh tracker challenge and a mandatory Ed25519 +
ML-DSA-65 signature over the exact command, challenge and TLS exporter. The
tracker verifies both signatures against the claimed node pin before recording
PoW or creating the capability entry. Another identity cannot claim that node,
and proofs cannot be replayed on a different channel. Identity ownership does
not certify an operator's independence or honesty. Restrict tracker admission
to your private operator environment. This is not public relay enrollment.
The tracker retains up to three
outbound waiting streams per node. It requests fresh proof-of-work per stream;
solving runs outside async I/O workers with independent random starting nonces.

For the existing optional plain SOCKS chain, provision `reverse://TOKEN@NODE_ID:0`
in a private proxy file and configure `--fetch-from HOST:PORT --tracker-key PIN`.
`--fetch-from` supplies the authenticated rendezvous endpoint; IDs returned by
`NODES` are never automatically added as authorized proxies. Plain SOCKS exit
service still requires the explicit `--allow-open-socks5` operator opt-in.
This service does not provide an onion anonymity guarantee by itself.

Controls are length-prefixed UTF-8, bounded to 32 KiB. Registration receives
`AUTH_CHALLENGE` followed by the bounded composite ownership proof, then
`REGISTERED`, then `READY` at handoff; an authorized consumer receives `OK` before
application bytes. Buffered bytes remain owned by the transport across handoff.
Unrequested early relay data terminates a waiting registration. EOF and a
60-second waiting deadline release its slot and connection permit. The server
allows 128 waiting registrations within 512 total connections, reserving capacity
for consumers. Active tunnel lifetime is at most one hour. These limits do not
prevent a distributed attacker exhausting the full admission budget. Separate
16-slot admission limits bound concurrent TLS/server-proof work and registration
proof exchanges. Excess accepted handshakes are closed immediately rather than
queued. These permits are released before waiting/tunneling, and failed or
cancelled exchanges release them automatically. A listener-owned token bucket also limits expensive handshake starts to a burst
of 32 and a refill of 16 per second; failed/completed handshakes do not refund
rate credit. The listener closes excess sockets without creating a waiting task.
These global budgets do not provide per-source fairness or guarantee public
availability against distributed CPU/bandwidth denial of service.

Keep public PoW difficulty at the configured policy. Tests use zero difficulty
and local private destinations solely as laboratory fixtures. The tracker and
adjacent participants can observe connection metadata; this mechanism does not
establish censorship resistance, global-observer protection or public-network
production readiness.

## Source-group admission follow-up

Before expensive TLS/server-proof work, a source group has at most four concurrent
handshakes and a burst of 64 starts refilling at at most 12/s. Global 16 concurrent
handshakes and global 32-start/refill16/s budgets remain authoritative. IPv4-mapped
IPv6 addresses share the IPv4 group; other IPv6 addresses share a /64 group.
Source refusal does not spend global rate credit. No socket/task waits for a
source permit, and the permit drops after channel authentication, before queued
registration or tunnel lifetime. Registration-proof exchanges retain their
separate existing budget.

At most 4096 source groups are retained in memory; exhausted accounting refuses a
new group instead of growing without bound. Idle entries expire after 120 seconds
and are collected during admission or a 30-second periodic sweep. A group with an
outstanding permit is never evicted, preventing semaphore replacement from
resetting its live concurrency count. This is ephemeral accounting, not a durable
IP log. Listener cancellation also drops owned handshake tasks/permits.

These are bounded engineering defaults, not measured globally optimal public
settings. Shared NAT clients and IPv6 /64 users share a budget; legitimate busy
shared networks may be throttled. A TCP forwarder or bridge that replaces peer
addresses also shares one source group: do not trust unauthenticated forwarded
address claims to bypass this policy. The policy does not identify independent
operators, provide weighted fair scheduling, prevent distributed floods, or hide
the direct tracker/relay protocol. Sustained load/NAT measurements remain required.
