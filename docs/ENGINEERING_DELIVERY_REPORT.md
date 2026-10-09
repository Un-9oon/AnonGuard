# AnonGuard padded-session and native-device engineering delivery

Verification date: 9 October 2026 (Asia/Karachi).

This delivery implements an opt-in, bounded traffic-shaping session layer and
native Linux Client/Volunteer installation. It is practical engineering work
with local end-to-end regression evidence. It does not certify production
anonymity, defeat every AI model, establish superiority to Tor or finish the
larger public-network/browser/post-quantum-authentication research agenda.

## Delivered changes

- Protocol v5: pinned TLS ALPN and handshake domains prevent silent old-protocol
  fallback. The selected exit acknowledges the exact encrypted privacy profile.
- Independent bidirectional cell scheduling with balanced/strict common
  fixed-rate profiles and bounded research RMT/Poisson options. Legacy custom
  morphing/chaffing flags cannot silently modify a selected session profile.
- Multiple logical TCP streams share one padded onion circuit. Round-robin
  scheduling, cumulative delivery acknowledgements, bounded queues/windows,
  monotonic stream IDs and per-session stream/control/rate limits constrain use.
- DATA warm-up, common duration buckets, idle tails and volume alignment continue
  cover after individual streams end. A hard 300-second lifetime bounds sessions.
  Connection failure closes streams without direct fallback or transaction replay.
- Local RFC1929 tuples provide opaque privacy-context labels; labels remain local
  and are cleared from credential buffers. No-auth clients share one default
  context. Labels are not account authentication or automatic per-site isolation.
- Native Linux role wizard, systemd units, dedicated accounts, default-deny
  nftables rules and a transparent TCP/remote DNS-over-TLS adapter. Client mode
  enables balanced sessions; Volunteer defaults to non-exit relay. VMs are optional.
- Native Firefox ESR launcher mode validates a protected client profile, active
  units and exact policy before disposable-profile launch. Existing optional VM
  mode remains available. This is not an audited Tor Browser replacement.
- Debian packaging installs helpers and public account definitions, preserves
  restrictions on removal, and derives ELF dependencies from the actual binary.
- Defense-aware, group-held-out trace evaluation baseline with training-only
  feature scaling, confusion matrix, precision/recall/FPR, available overhead/
  latency measurements, observation type and dataset SHA-256. No attack-result
  dataset is invented. Deep-learning and flow-correlation evaluation remain open.

## Bugs found and fixed during delivery

A refused stream initially caused expected worker cancellation to be treated as a
session panic. Cancellation now resets only the affected stream and regression
coverage verifies successful subsequent streams. The receive-flood test originally
relied on wall-clock processing speed; virtual time and explicit channel closure
make its failure boundary deterministic. Noncanonical session destinations refuse
before connecting. A legacy DNS-rebinding test depended on public nip.io DNS and
failed when resolution timed out; a controlled resolved-address fixture now runs
the same production validation/connect path and checks that no forbidden socket
is opened. Native public-profile/directory permissions no longer depend on the
administrator's umask; package account-definition directories are not group-writable.

## Executed verification

| Check | Result |
|---|---|
| `cargo test --offline --locked --all-targets --all-features` | 246 passed; 0 failed; 2 intentionally ignored |
| Debug Clippy, all targets/features, `-D warnings` | Passed |
| Release Clippy, all targets/features, `-D warnings` | Passed |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |
| Locked offline release build | Passed |
| Native helper tests | 11 passed; includes localhost mock SOCKS, DNS binding, permissions and read-only systemd dependency parsing |
| Browser policy/lifecycle contracts | 7 passed; no real browser launch |
| Trace evaluator contracts | 3 passed; synthetic fixtures validate mechanics only |
| Debian package build/content inspection | Passed; native helper executable modes and protected sysusers directory verified |
| Generated native Client/Volunteer CLI arguments | Accepted by daemon argument parser |

The two ignored Rust tests require privileged network namespaces and a real
obfs4proxy binary. Local non-ignored CLI tests run real pinned authorities,
relay links, hybrid circuit setup, SOCKS transfer, shared padded sessions and
relay-loss closure on loopback. These are not geographically distributed tests.
GitHub CI additionally contains privileged, transport, package lifecycle,
platform compilation and fuzz jobs; inspect the exact published commit's run,
not a prior green badge. Local build logs are retained in `verification-*.log`
in the working checkout and are ignored by Git.

The `.deb` is a local build artifact, not a signed production release. Its ELF
metadata requires libc6 >= 2.39 and libgcc-s1 >= 4.2. This is not evidence of a
successful installation on the user's actual device.

## Limits and deployment acceptance

The user's VM/live tests were deliberately deferred. No native firewall was
activated on the host; no service/account/network configuration was applied;
no actual browser policy-loading, leak/crash/boot/upgrade acceptance or multi-region
traffic-analysis campaign was performed. Native administrative restrictions trust
the host kernel, root, transport UID and privileged brokers. Root malware, host
IPC escapes, stolen login identity and compromised endpoints are outside the
network gateway's protection.

Session cover begins on demand rather than running permanently. Handshakes,
TLS/TCP packetization, congestion, CPU scheduling and session recreation remain
observable. Longer routes, RMT samples and Poisson jitter do not prove stronger
anonymity. ML-KEM hybrid key exchange is post-quantum key-establishment work;
Ed25519 authentication remains classical. No quantum hardware/QKD is used.

Before a public anonymity recommendation, finish independent protocol/crypto
review, sustained adversarial fuzzing, actual device containment acceptance,
operated diverse testnet/incident exercises and collected defense-aware deep
fingerprinting plus two-end flow-correlation experiments with a matched Tor
baseline. Onion/private services, a broader audited browser distribution and
Windows/macOS whole-device isolation are not delivered by this change.

See [PADDED_SESSIONS.md](PADDED_SESSIONS.md),
[NATIVE_INSTALLATION.md](NATIVE_INSTALLATION.md),
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) and
[the trace evaluation contract](../eval/TRACE_EVALUATION.md) for configuration,
costs, trust boundaries and acceptance steps.
