# Production readiness

Status: experimental v3. Completion of this engineering redesign is not approval for public anonymity deployment and does not establish superiority to Tor.

## Implemented redesign

- Pinned TLS 1.3 relay links with mandatory v3 ALPN and no plaintext fallback.
- Per-link circuit identifiers, signed hybrid handshake transcripts and context-bound key derivation.
- Unambiguous signed relay descriptors, exact-snapshot quorum verification, durable authority votes and client rollback/equivocation rejection.
- Identity-pinned persistent guards and entry-only cooldowns.
- Shared private signing-key storage with exclusive publication under concurrent startup, bounded reads and Unix permission checks.
- Strict SOCKS5 method negotiation and destination parsing; bounded optional decoy operations.
- Bounded directional flow control, ACK validation, fair paced DATA/ACK scheduling, upload half-close and acknowledged response teardown.
- Exit DNS/address validation, shared connect deadlines and bounded connection/circuit lifetimes.
- Fresh Linux application namespaces, DROP rules installed before exposure, private bridge, helper identity checks and crash isolation.
- Bounded concurrent pinned directory retrieval, admission reconciliation against concurrent registrations, and deferred production votes until three relays including an exit are present.
- Gateway and namespace bridge workers scoped to their listeners; aborting a listener cancels its existing connections.
- Explicitly retired unsupported multipath gateway behavior and unsupported anonymity claims.

These changes require a coordinated v3 migration. No in-place replay or transparent reconnection of arbitrary TCP transactions is provided. Optional onion services and reviewed multipath sessions remain separate projects, not partially enabled production features.

## Verification and release gates

Locked tests and strict lint checks cover implemented contracts, including pinned identity rejection, three-hop telescoping, credit errors, directory conflicts/restart rollback and a 128 KiB half-closed request/response. A local CLI testnet also starts four authorities, three relays and a gateway, verifies a 128 KiB half-closed transfer, and checks connection closure after relay loss. This single-host test uses zero-cost PoW and explicitly permitted private exits; neither setting is a production recommendation. CI separately exercises privileged namespace isolation and cross-platform compilation. Passing normal tests alone is insufficient for deployment approval.

Required before a production release:

1. Independent cryptographic protocol and implementation review, with attention to layered cell framing, malicious relay behavior, transcript binding and secret lifetime.
2. Passing CI on the exact release commit, sustained fuzz campaigns and enforced coverage thresholds. Do not lower thresholds to hide failures.
3. Privileged Linux IPv4/IPv6/DNS leak and crash tests; install/upgrade/removal, state persistence, Windows key ACLs and recovery tests. Platform compilation does not prove kernel protection.
4. A multi-region testnet with independent operators, recorded circuit success, partitions, authority convergence, clock changes, load, guard outages and churn. Frozen divergent authority views can currently stall service until another epoch.
5. Resource-budget and scheduling evaluation. The current directory admits 512 relays and at most 16 authorities; scaling needs a reviewed paginated design. Fixed pacing has substantial bandwidth/throughput cost.
6. Authenticated bootstrap distribution, key rotation/revocation, signed reproducible releases, incident response, abuse management and explicit operator ownership.
7. Reproducible held-out traffic-analysis experiments with realistic passive/active adversaries and equivalent Tor configurations. Simulations and timing entropy do not establish anonymity.

## Packaging and operation

Release packaging now depends on the full reusable verification workflow and dependency audit at the release commit. Tagged releases remain explicitly marked as experimental prereleases. Distribution archives include a runtime argument example rather than an unsupported config.toml; the checksum manifest and binaries are signed by the release workflow. Passing these engineering gates does not substitute for independent review.

The Debian service uses a dynamic user and private persistent state. Configure `/etc/anonguard/runtime.env` with real endpoint-bound pins and a valid quorum; the daemon does not parse the former sample config.toml. Kernel isolation needs administrative namespace privileges and is a separate operational mode, not a privilege automatically granted by the packaged service.

Empty, expired, conflicting or insufficient directories fail new circuit construction. Preserve and protect identity keys, authority vote journals, guard state and accepted-directory state. Corrupt state fails startup. Existing Unix signing keys must deny group/other access (`chmod 600`). Key storage requires a filesystem supporting hard links; unsupported storage fails startup rather than replacing a concurrent identity. Windows ACL verification remains a release gate. Test migrations in an isolated testnet before upgrading all participants together.

The required first production release targets Linux, macOS and Windows with full application network isolation. Native macOS and Windows providers are not implemented; strict isolation refuses these platforms. Implementation and live IPv4/IPv6/DNS/UDP/crash validation on both platforms are release blockers. No deployed multi-region testnet or independent reviewer arrangement is recorded in this repository.

Windows and macOS currently support application transport only. Public network readiness, Tor compatibility, onion services and protection against global traffic correlation are not certified or implemented by this work.
