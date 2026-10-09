# AnonGuard

Experimental authenticated onion-routing software written in Rust. No superiority to Tor or production anonymity certification has been established.

## Supported protocol

- One destination TCP stream through an authenticated randomized 3–8-hop circuit (CLI default range 3–5).
- TLS 1.3 between adjacent nodes, mandatory `anonguard/5` ALPN, and Ed25519 identity pins from a signed directory.
- Per-link circuit identifiers, hybrid X25519/ML-KEM-768 circuit handshakes, transcript-bound keys, and layered encryption.
- Exact-snapshot directory quorum verification with persistent rollback/equivocation rejection.
- Identity-pinned entry guards, bounded authenticated flow control, upload half-close, and explicit circuit teardown.
- A continuous cell scheduler with bounded buffers and dummy cells: fixed 20 ms by default, or experimental RMT/Poisson/Lorenz timing when configured. See [multi-hop and scheduling contracts](docs/MULTIHOP_SCHEDULING.md). Traffic-analysis protection is unproven.
- Linux application isolation in a loopback-only namespace, with a private Unix-socket bridge to the gateway outside it.
- Optional obfs4 first-hop and authority-bootstrap transports, independently provisioned unlisted entry bridges, and supervised Linux PT services. See [deployment and limits](docs/design/PLUGGABLE_TRANSPORT.md). This does not establish resistance to any particular censor or traffic-correlation attack.

The former multipath transport is retired. It lacked exit-side association and symmetric framing. This release provides single-path reliability; it does not transparently reconnect or replay application transactions after a failed exit. Onion services and browser fingerprint protection are outside the implemented protocol.

## Build and verify

Rust 1.88 or newer is required.

```sh
cargo build --locked --release
cargo test --locked --lib --bins --tests
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

Privileged namespace checks run separately in Linux CI. Ordinary tests do not establish host leak protection or real-network anonymity.

## Directory bootstrap

Operators publish Ed25519 authority keys through an authenticated channel. Clients must pin each endpoint explicitly. Example shape (replace placeholders):

```sh
anonguard-daemon --onion --listen 127.0.0.1:9050 \
  --authorities a@AUTHORITY_A:9000,b@AUTHORITY_B:9000,c@AUTHORITY_C:9000 \
  --authority-keys a:KEY_A_HEX,b:KEY_B_HEX,c:KEY_C_HEX \
  --quorum-threshold 3
```

Authorities use `--authority --authority-id ID --listen ADDRESS --identity-key-path FILE` and the same pinned peer configuration. Relays use `--relay`, a persistent identity key, and pinned authorities; exit relays additionally use `--is-exit`. Relay listen addresses must be reachable and advertised accurately. No unauthenticated bootstrap is provided for anonymity use.

The directory currently admits at most 512 relays; larger networks need a reviewed paginated directory design.

The CLI requires a quorum greater than two thirds of configured authorities. A single-authority test network provides no authority-compromise tolerance. Authorities freeze one snapshot per five-minute epoch; a conflicting view cannot be co-signed in that epoch. This is quorum-signed directory distribution, not a claim of a complete Byzantine consensus algorithm.

## Linux protected applications

`--enable-firewall-killswitch --strict-fail-closed --namespace-name anonguard` creates a fresh application namespace. It requires administrative namespace/nftables privileges and a numeric loopback listener. The host's firewall is not changed. The transport process remains outside the namespace.

For the FYP's supported headless applications, use the restricted
[application launcher](docs/LINUX_APP_CONTAINMENT.md), with a dedicated immutable
rootfs, unprivileged application identity and syscall restrictions. Configure
SOCKS5 with remote DNS at `127.0.0.1:9050` inside the namespace. Follow its explicit
administrative setup instructions; the packaged gateway service does not create
this privileged environment automatically.

A network namespace alone blocks external IP routes but does not contain host
pathname UNIX sockets, brokers or inherited descriptors. Launching an arbitrary
host application with `ip netns exec` is therefore not the full containment
profile. Applications elsewhere on the host are not protected. GUI/browser
containment and persistent application output are outside the current profile.

Namespace rules survive gateway exit or crash. Restart does not silently reuse a namespace or another daemon's socket. After stopping protected applications, administrative cleanup is explicit:

```sh
sudo ip netns delete anonguard
```

Windows and macOS support the application transport; they do not implement this kernel isolation. `--strict-fail-closed` refuses startup there.

## Migration and limits

Protocol v5 is incompatible with earlier plaintext relay links and directory transport. Upgrade clients, relays and authorities together. The TLS version boundary prevents fallback to the old protocol. Legacy address-only guard state must be deliberately reset when moving to identity-pinned guards; corrupt state fails startup.

A directory snapshot must be current and quorum signed. New circuits fail after directory expiry. Existing circuits are bounded to one hour and are not silently migrated. Protect persistent authority votes, directory rollback state, guard state and identity keys from modification. Clock rollback, stale directories, unreachable guards and conflicting authority views may stop service rather than lower security requirements.

For installation, acceptance evidence and the examiner walkthrough, start with
[practical FYP delivery](docs/FYP_DELIVERY.md).

See [protocol specification](docs/PROTOCOL_V3.md), [threat model](THREAT_MODEL.md), and [production readiness](docs/PRODUCTION_READINESS.md). Historical research documents and simulations are not evidence about the current protocol.

Licensed under MIT or Apache-2.0.

### Experimental padded sessions and native devices

Opt-in `--onion --padded-sessions --privacy-profile balanced` adds authenticated
profile negotiation, shared stream scheduling, independent bidirectional cover
and bounded idle tails. See [the session contract](docs/PADDED_SESSIONS.md).
The Debian package includes [native Client/Volunteer setup](docs/NATIVE_INSTALLATION.md);
VMs remain optional test fixtures. The new [measured-trace evaluator](eval/TRACE_EVALUATION.md)
is a defense-aware held-out baseline, not proof of AI resistance or production anonymity.
