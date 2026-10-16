# Ubuntu VM validation — 16 October 2026

## Candidate and scope

Candidate: `21b4a93c68c5c3761db8775dfc02756040e02c98`.
Ubuntu 24.04.5 LTS, kernel 7.0.0-38-generic, two virtual CPUs, approximately
3.8 GiB RAM. The exact source, optimized daemon, Debian package and compiled
Rust test harnesses were transferred to the owned VM. Bundle SHA-256:
`2f6777272cd6683f6079334922098cc90a8503059e1f1a6667227f92ea5d260c`.
The VM runner verified the complete bundle digest before extraction/execution.

This is one-machine laboratory validation. Local authorities and relays are
real AnonGuard processes, but are not independent operators or separate networks.
No production anonymity, AI-undetectability or independent cryptographic review
is established by these checks.

## Observed results

All 61 completed unprivileged runner stages returned zero:

- 48 portable Rust test harnesses, run sequentially. Coverage includes hybrid
  handshake boundaries, post-quantum vectors, replay refusal, tracker ownership,
  directory admission, authority pinning, gossip convergence, network partitions,
  guards, padded sessions and actual telescopic circuits. Some harnesses have no
  selected tests or intentionally ignored tests; 48 is a harness count, not a
  claim that every compiled test ran.
- Ten Python stages: native setup/adapter, browser session/extension, app launcher,
  VM profile, release verification/version, latency measurement contracts, actual
  Firefox isolation and loaded Firefox enterprise policy.
- Explicit real-obfs4 Rust interoperability test, private-obfs4 CLI testnet, and
  actual Firefox through the real padded onion testnet.

Firefox 157.0.1 loaded owned parent/subresource pages through the actual CLI
onion gateway. Distinct origins received distinct gateway context credentials;
third-party resources retained their parent context. This was temporary addon
and disposable policy testing, not signed browser distribution acceptance.

Three privileged namespace fixtures passed:

1. Generated native firewall plus actual transparent adapter: TCP redirection,
   DNS failure refusal, UDP/IPv6 denial, connection closure after backend loss
   and firewall persistence after helper death. Its backend is a SOCKS fixture.
2. App containment: private filesystem, inherited descriptor/IPC restrictions,
   UID/capability/syscall boundaries, permitted proxy flow and helper-death refusal.
   The existing executable-specific AppArmor policy was preserved.
3. Protected native egress: provisioned PT endpoint allowed; other endpoint port
   denied; gateway direct external connection denied; gateway dynamic loopback
   PT connection allowed; ordinary UID denied access to that PT port. Production
   OUTPUT/NAT rules were used unchanged. Explicit fixture INPUT and established
   server-reply exceptions supported synthetic remote-address listeners on lo.
   This is not a complete installed-device/network test.

All four installed runner stages returned zero: protected namespace, temporary
unsigned lab package install, installed systemd PT lifecycle, and package purge.
Real obfs4 service restart preserved server identity. Private service credentials,
child-crash cleanup of readiness files, and dependent-service stop were verified.
The installed template PT service was tested; this does not certify the newly
generated native PT unit's complete boot/restart integration.

Separately, all three Python supervisor tests passed with real obfs4proxy.
The host firewall was never activated or replaced. No global AppArmor restriction
was disabled. The temporary package was purged after validation.

## Deliberate exclusions and pending evidence

Nine compiled harnesses embed build-host executable paths and were excluded from
the portable VM runner: CLI safety, proxy-file admission, research-tool CLI,
multihop CLI, identity initialization/rotation, CLI authority configuration,
revocation-policy CLI, and the separate live namespace harness. This VM result
must not be described as a complete all-targets/all-features runtime test pass.

Full package lifecycle acceptance was not run: its clean-VM prerequisite conflicts
with the existing AppArmor setup. Temporary installation, installed PT lifecycle
and purge passed instead. Boot/reboot, real network changes, existing host sockets,
and the fully composed generated native client/PT/firewall remain open.

Follow-up evidence retrieval and recovery verification completed in a later
session on the same VM. All 21 updated native contracts passed. The generated
service lifecycle fixture passed both initial and final runs; its synthetic
transport/backend and no-op firewall must not be represented as full native
real-relay acceptance. See [recovery hardening](NATIVE_RECOVERY_HARDENING.md).
The portable Rust baseline logs contain 247 passed tests and one ignored test;
explicit obfs4 interoperability was separately run with the ignored case enabled.

The initial delayed capture contained only the 24-byte pcap header and is not
usable evidence. A synchronized recapture reran actual Firefox/onion browsing
successfully and produced 13,279 packet records over 13.408 seconds, with
32,651,023 original captured frame bytes. Snapshot length was 256 bytes, truncating
4,128 records; this preserves timing/lengths but not complete payloads. Observed
IPv4 addresses were 127.0.0.1, 127.1.0.1, 127.2.0.1 and 127.3.0.1. The capture
mixes owned testnet and browser-control TCP on loopback: it is not a per-link
bandwidth, Internet leak, classifier-resistance or independent-network result.
Pcap SHA-256:
`ec7fdcc7f49e6ddce0037df9d79538cae949d4017be1c45c4d5e27555adf9145`.

Raw logs, result manifests and pcap were retrieved and the archive digest verified:
`1897b7ea6e48972a029f30766732b02d3334d7882ce7fb53a6cae6646331bc7b`.
This first retrieval includes the earlier lifecycle run and initial evaluator
failure; subsequent confirmation logs are retained separately. Private evidence
is not committed to the public repository. The initial approval-review usage
interruption was resolved when access became available; it no longer blocks
these retrieved results.

All six evaluator suites subsequently returned zero after installing Ubuntu's
`python3-sklearn` dependency. The initial missing-dependency failure remains in
the evidence. Evaluator tests validate analysis contracts, not real-world attack
resistance. Final evidence archive (including the final recovery run and all
post-dependency evaluator logs) was retrieved and hash-verified:
`ff5e85bb744c228d087831e80793507e6a44ba98ffbb3d595ae4185cd0bac01b`.
No temporary recovery units remained loaded, and SSH stayed active.

Next: finish composed native-service acceptance;
then test separate independently operated networks and evaluate representative
held-out traffic, false positives, correlation, latency and bandwidth. Independent
protocol review and authenticated release/browser delivery remain release gates.
