# Production readiness

Status: experimental v3. Completion of this engineering redesign is not approval for public anonymity deployment and does not establish superiority to Tor.

## Implemented redesign

- Pinned TLS 1.3 relay links with mandatory v3 ALPN and no plaintext fallback.
- Per-link circuit identifiers, signed hybrid handshake transcripts and context-bound key derivation.
- Unambiguous signed relay descriptors, exact-snapshot quorum verification, durable authority votes and client rollback/equivocation rejection.
- Identity-pinned persistent guards and entry-only cooldowns.
- PoW replay records retained through the inclusive acceptance boundary; registry exhaustion refuses new admissions instead of forgetting live proofs, with bounded identity sizes. Clock rollback behind a replay-cache purge refuses admission until time catches up.
- Shared private signing-key storage with exclusive publication under concurrent startup, bounded reads and Unix permission checks.
- Strict SOCKS5 method negotiation and destination parsing; bounded optional decoy operations.
- Explicit proxy files are read and validated completely before distinct endpoints are published; read and parse errors preserve the existing pool. Bad file or inline proxy configuration stops gateway startup without printing URL credentials.
- Bounded directional flow control, ACK validation, fair paced DATA/ACK scheduling, upload half-close and acknowledged response teardown.
- Exit DNS/address validation, shared connect deadlines and bounded connection/circuit lifetimes. Expired certified directories are excluded from every pool selection API.
- Fresh Linux application namespaces, DROP rules installed before exposure, private bridge, helper identity checks and crash isolation.
- Bounded concurrent pinned directory retrieval, admission reconciliation against concurrent registrations, and deferred production votes until three relays including an exit are present.
- Gateway, authority, tracker and namespace bridge workers scoped to their listeners; aborting a listener cancels its existing connections and queued reverse streams.
- Serialized kill-switch reset/trip state and cancellation notifications; raw tracker requests containing authentication tokens are not logged.
- Bounded research reassembly with progress at capacity, first-payload preservation and checked slicing/sequence exhaustion; this does not enable a multipath gateway.
- Research CLI tools identify synthetic assumptions, group duplicate fingerprint descriptors, honor the modeled population and propagate buffered dataset write failures.
- Explicitly retired unsupported multipath gateway behavior and unsupported anonymity claims.

These changes require a coordinated v3 migration. No in-place replay or transparent reconnection of arbitrary TCP transactions is provided. Optional onion services and reviewed multipath sessions remain separate projects, not partially enabled production features.

## Verification and release gates

Locked tests and strict lint checks cover implemented contracts, including pinned identity rejection, three-hop telescoping, credit errors, directory conflicts/restart rollback and a 128 KiB half-closed request/response. A local CLI testnet also starts four authorities, three relays and a gateway, verifies a 128 KiB half-closed transfer, and checks connection closure after relay loss. This single-host test uses zero-cost PoW and explicitly permitted private exits; neither setting is a production recommendation. CI separately exercises privileged namespace isolation and cross-platform compilation. Coverage aggregates the normal and privileged namespace runs without dropping uncovered source lines or counting duplicate classes twice. Passing normal tests alone is insufficient for deployment approval.

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

The current FYP delivery target is Linux (Ubuntu 24.04 LTS), with the restricted headless application profile. This narrows the deliverable; it does not satisfy the earlier universal-platform ambition. Native macOS and Windows providers are not implemented; strict isolation refuses these platforms. Full support for those platforms requires implementation and live IPv4/IPv6/DNS/UDP/crash validation. No deployed multi-region testnet or independent reviewer arrangement is recorded in this repository.

Linux network namespaces isolate IP networking and abstract UNIX sockets, not pathname UNIX sockets in a shared filesystem. The namespace-only backend does not contain host brokers or inherited descriptors. The experimental [headless launcher](LINUX_APP_CONTAINMENT.md) adds a dedicated rootfs, private process/IPC/user namespaces, host identity drop, descriptor sanitation and a native syscall policy. This restricted profile is not universal GUI/IPC containment or production certification. Require its privileged acceptance results on the release commit and live validation on the deployment kernel. Direct packet probes alone do not establish IPC containment. See [network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html).

Windows and macOS currently support application transport only. Public network readiness, Tor compatibility, onion services and protection against global traffic correlation are not certified or implemented by this work.
