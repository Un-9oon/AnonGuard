# Private reverse rendezvous

The optional tracker is a private capability-based tunnel service. It is separate
from the signed directory and does not enroll NAT nodes into public onion circuits.
The onion gateway still refuses reverse entries. VMs are not required.

All tracker controls now require pinned TLS 1.3, X25519MLKEM768, the distinct
`anonguard-tracker/1` ALPN and an exporter-bound Ed25519 + ML-DSA-65 proof.
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
its stable composite identity pin encoded as hex. This is a label: the tracker
does not verify a volunteer signature over registration or certify node ownership.
Its first live registration establishes the capability for that label; another
party can race registration and deny availability. Restrict tracker admission
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
`REGISTERED`, then `READY` at handoff; an authorized consumer receives `OK` before
application bytes. Buffered bytes remain owned by the transport across handoff.
Unrequested early relay data terminates a waiting registration. EOF and a
60-second waiting deadline release its slot and connection permit. The server
allows 128 waiting registrations within 512 total connections, reserving capacity
for consumers. Active tunnel lifetime is at most one hour. These limits do not
prevent a distributed attacker exhausting the full admission budget.

Keep public PoW difficulty at the configured policy. Tests use zero difficulty
and local private destinations solely as laboratory fixtures. The tracker and
adjacent participants can observe connection metadata; this mechanism does not
establish censorship resistance, global-observer protection or public-network
production readiness.
