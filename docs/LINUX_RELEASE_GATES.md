# Linux release acceptance ledger

Target: Ubuntu 24.04 LTS, independent AnonGuard client/relay deployment.
This ledger tracks work against the public release contract in
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md). No completion percentage is
assigned: an open critical gate prevents public anonymity approval.

## Engineering work

| Boundary | Implemented control | Remaining acceptance |
| --- | --- | --- |
| Reverse node ownership | Tracker v2 requires canonical composite node ID and fresh command/challenge/TLS-exporter-bound Ed25519 AND ML-DSA proof before directory/nonce mutation | Exact release revision regression/VM acceptance; operator independence is not established by key ownership |
| Tracker admission | 512 total sockets, 16 concurrent handshakes, 16 concurrent registration proof exchanges, handshake burst32/refill16 per second; source 4 slots/burst 64/refill <=12 per second, bounded 4096 groups with idle expiry; 128 waiting registrations, three per node; deadlines and cancellation cleanup | Sustained churn, NAT behavior, weighted fairness and CPU/bandwidth budget measurement |
| Relay/client resource use | Existing global/per-IP connection limits, bounded circuit/window/document state and service CPU/RAM limits | Measured public flood/slow-peer admission, realistic cover-traffic cost and overload recovery |
| Linux native containment | Generated firewall, transparent TCP adapter, remote secure DNS with failure refusal, UDP/IPv6 blocking | Composed real-relay installed-device acceptance across boot/restart/reload/network change/pre-existing sockets |
| Native protected entry | Authenticated private config, exact authority coverage, dedicated obfs4 account/service, systemd credentials, provisioned endpoint egress and loopback-only gateway output; direct mode requires explicit lab opt-in | Installed nftables and actual PT crash/restart/boot acceptance; independent outer-transport evaluation |
| Headless app containment | Private rootfs, namespace, syscall/descriptor/UID restrictions | Privileged probe on the supported installed OS; no universal compromised-host protection |
| Browser | Privacy policy, session attribution extension, packaging and integration tests | Real signed addon distribution/activation, vendor-update maintenance and fingerprint consistency |
| Cryptographic protocol | Hybrid KEX, mandatory dual authentication, pinning, transcript binding and failure refusal | Independent protocol review, external vectors, key-compromise/migration exercises |
| Distribution | Version agreement, release-manifest verification, explicit operator minimum-tag/exact-artifact/revocation admission, and package lifecycle gates | Authenticated signing identities, reproducibility, signed release publication and update/rollback ceremony |

Latest scoped VM results: [16 October 2026 validation](VM_VALIDATION_2026_10_16.md).
Protected egress namespace, actual Firefox/onion testnet, and installed template
PT lifecycle checks passed; composed native boot/restart acceptance remains open.

Native recovery follow-up: [bounded shutdown and adapter restart propagation](NATIVE_RECOVERY_HARDENING.md).
Updated contracts and synthetic generated-unit restart/credential lifecycle pass
on Ubuntu. Actual native PT/client/firewall composition and boot/network-change
acceptance remain pending.

## Evidence that must exist for a public release

1. Record the exact commit, lockfile hashes, toolchains, full test/lint results,
   artifact digests and all required CI outcomes. A previous green commit cannot
   certify later edits. Unsigned laboratory artifacts remain laboratory builds.
2. Run privileged isolated regression fixtures, then the composed installed
   client with real relays. Preserve packet captures and service/journal results.
   Label controlled SOCKS fixtures explicitly; never relabel them as real relays.
3. Measure adaptive held-out fingerprinting, open-world false positives and
   end-to-end flow correlation on actual v6 captures. Include repeat runs,
   confidence intervals, latency, CPU/RAM, throughput and wire overhead. A
   simulated classifier or random graph cannot establish undetectability.
4. Exercise partitions, clock changes, guard/authority loss, sustained load,
   reconnect/recovery, key retirement and compromised-release rollback across
   independently operated networks.
5. Obtain independent cryptographic/protocol review and triage its findings.
   Developer review, fuzz smoke tests and algorithm interoperability are useful
   evidence but are not independent protocol certification.
6. Establish actual signing/browser accounts, authenticated bootstrap material,
   supported versions, an owner-approved security contact, incident response and
   exit-operator arrangements. Do not invent contacts or response commitments.

## Scope

Windows/macOS kernel isolation is outside this Linux release. Private onion-style
services and reverse onion-circuit transport are not implemented. A small private
deployment does not provide the public anonymity population of an established
network. No Tor-superiority, complete quantum protection or AI-undetectability
claim is an acceptance criterion that the current evidence can satisfy.
