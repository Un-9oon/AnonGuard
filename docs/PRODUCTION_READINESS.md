# Production readiness

Status: **experimental v6; not approved for public anonymity deployment**.
The coordinated post-quantum authentication and link-cover migration changes
wire formats, keys, cells and resource costs. Source implementation is not
independent security review, measured anonymity or release acceptance. No claim
of superiority to Tor or complete quantum protection is supported.

## Current engineering checkpoint

The current [v6 protocol specification](PROTOCOL_V3.md) describes the mandatory
network path. Its historical filename is retained; it supersedes v3/v5 details.

- Network identities require **both Ed25519 and ML-DSA-65** signatures. Composite
  pins bind both public components and encoding version. Descriptor admission,
  authority consensus/cross-checks, circuit handshakes, guards, private bindings
  and offline retirement use this composite identity meaning. Duplicate-component
  checks supplement composite-key uniqueness; different operators remain an
  external assumption.
- Directory transport `AGDIR004` combines ephemeral X25519 and ML-KEM-768,
  mandatory dual server authentication, transcript-bound directional HKDF and
  bidirectional encrypted confirmation. Missing pins and older transport versions
  are refused. Documents use authenticated bounded segmentation: six MiB maximum,
  at most six one-MiB chunks. Errors or cancelled partial operations poison sessions.
- Relay links require TLS 1.3 with `X25519MLKEM768` and `anonguard/6` ALPN.
  A certificate-carried composite identity is pinned while its classical Ed25519
  TLS signature remains verified. A mandatory challenge/TLS-exporter-bound dual
  identity proof authenticates the channel before onion traffic is exposed.
  This supplemental construction is custom and needs independent review.
- Onion cells are now **8192 bytes**, with enlarged authenticated handshake proofs.
  Mandatory hop-local 20-ms covered envelopes conceal idle-versus-data slots while
  links remain alive. Connection setup/lifetime, congestion and correlation remain
  observable. The calculated scheduling cost is about **409.8 kB/s per direction
  per link**, before TLS/TCP overhead; this is not measured performance.
- Bounded randomized 3..8-hop circuits (CLI default 3..5), persisted guards,
  non-exit middles, exit policy, bounded credit/ACK handling, half-close and failure
  refusal remain the routing contract. Multiplexed session profiles and tails are
  distinct from adjacent-link cover. RMT/Poisson/Lorenz are classical statistical
  research options, not quantum protection or proven anonymity improvement.
- Identity storage uses a protected, exclusive, durable **72-byte paired-seed
  bundle**. Existing Ed-only keys are rejected rather than overwritten. Guard,
  transport and accepted-snapshot versions prevent silently reinterpreting old
  pins. Offline retirement policy version 2 retains cumulative generation and
  quorum constraints; it requires authenticated operator distribution and restart.
- Exact-snapshot quorum, persistent authority votes, client rollback/equivocation
  rejection, bounded concurrent reconciliation, expiry and PoW replay protection
  remain fail-closed. Limits remain 512 relays and 16 authorities. Divergent frozen
  views/partitions can still stall service until a later epoch; this is not a
  complete Byzantine liveness protocol.
- Linux native Client/Volunteer tooling, transparent adapter and managed firewall
  remain experimental administrative profiles. VMs are test fixtures, not an
  installation requirement. Optional obfs4 bridges and protected authority
  bootstrap have no independently demonstrated censorship resistance.
- Firefox ESR privacy-policy/AutoConfig enforcement, temporary-addon circuit
  attribution and launcher packaging have local regression coverage. Normal
  distribution still needs a signed addon and actual installed-system acceptance;
  this is not an audited Tor Browser-equivalent distribution.
- `anonguard-setup --check-app-containment` provides an ordinary-user read-only
  Bubblewrap prerequisite probe and actionable Ubuntu AppArmor refusal. It never
  disables protections or installs host policy automatically. Headless rootfs,
  syscall, descriptor and namespace containment remain a separate narrow profile.

Upgrading all participants and operator artifacts together is mandatory. Preserve
keys, votes, guards, accepted snapshots and retirement journals; do not reset or
reinterpret security state to bypass migration refusal. There is no automatic
legacy trust-continuity ceremony, in-place stream replay or seamless TCP recovery.

## What existing evidence does and does not establish

Earlier local and Ubuntu 24.04.3 VM sessions exercised real authorities/relays,
browser-through-onion transfer, malformed handshake refusal, private-namespace
packet capture, native adapter crash/leak boundaries, documented AppArmor
prerequisites and Debian package lifecycle. See
[the original VM record](VM_VALIDATION_2026-10-10.md) and
[follow-up engineering/evaluation record](ENHANCEMENT_VALIDATION_2026-10-10.md).
Those records identify their tested revisions and laboratory assumptions.
They **do not validate the new v6 release**, its larger cells or new cover layer.
Do not carry old numerical performance or anonymity results forward as v6 results.

The prior owned-workload pilot identified strict-padded workloads at 66.7% 1-NN
and 50–83.3% small-MLP accuracy versus 33.3% balanced chance (three labels, twelve
held-out traces). It did not establish improved encrypted-link correlation
resistance. Later evaluation engineering improves evidence integrity, backpressure
and fixed-window analysis, but does not establish real-world undetectability.
Fresh defense-aware testing must measure v6 rather than relabel old captures.

Focused v6 transport regressions cover wrong composite pins, missing identity,
old versions, altered proofs, cross-handshake replay, low-order X25519,
noncanonical ML-KEM inputs, AEAD replay/tampering, cancelled partial streams and
segmented-document limits. The exact release-commit full suite, privileged tests,
CI and browser/VM acceptance must be recorded separately; this checkpoint makes
no unverified claim that every check has passed.

## Required release gates

1. **Independent protocol and implementation audit:** mandatory dual-auth composition,
   TLS exporter binding, malicious relays/authorities, canonical encodings,
   downgrade prevention, nonce/sequence use, secret lifetime and coordinated
   migration. External ACVP/KAT vectors and independent backend interoperability
   are needed alongside implementation tests; algorithm names are not validation.
2. **Exact-commit engineering verification:** full locked suite, strict lint, passing
   CI, privileged isolation regressions, sustained fuzzing of KEX/proofs/cells/
   documents/controls and honest coverage. Do not weaken gates to hide failures.
3. **Installed-system Linux acceptance:** boot ordering, IPv4/IPv6/DNS/UDP leaks,
   pre-existing sockets, IPC boundaries, crash/restart, suspend/resume, reload,
   network changes, install/upgrade/removal and persistent-state recovery.
   A fixture backend or packet-only probe does not certify the composed product.
4. **Real multi-network operation:** independent operators, public egress IP hiding,
   authority partitions/convergence, clock changes, guard outages/churn, prolonged
   load and recovery. Single-host tests with zero PoW/private exits are lab-only.
5. **Resource and anonymity measurements:** real v6 packet captures, adaptive
   held-out fingerprinting, open-world false positives, flow correlation and
   realistic protocol detection, with repeat runs/confidence intervals and fair
   Tor baselines. Measure latency, CPU/RAM, bandwidth and scaling simultaneously;
   mandatory cover and larger signatures/cells materially increase costs.
6. **Distribution and operations:** authenticated bootstrap/migration ceremonies,
   key rotation/retirement, signed reproducible releases and browser addon,
   persistent release rollback/revocation policy, incident response, abuse
   handling and explicit operator ownership.
7. **Browser delivery:** signed addon activation, combined installed client/browser
   packet acceptance, fingerprint consistency across supported devices and
   maintained vendor security updates. Login/cookies, compromised endpoints and
   external HTTPS/DNS PKI remain independent risks.

## Supported scope and operational boundaries

The FYP target is **Linux, initially Ubuntu 24.04 LTS**. Strict kernel isolation
on macOS/Windows is unimplemented and refused; cross-platform compilation is not
leak protection. Onion services, universal endpoint protection, a public anonymity
population and protection against a global observer are not established features.

The [release verifier](RELEASE_VERIFICATION.md) authenticates the release manifest
against its workflow/tag identity and stages verified artifacts. That establishes
origin/integrity, not anonymity or crypto certification. Tagged artifacts remain
experimental prereleases. Local unsigned lab builds are outside this release gate.

Packaged service roles do not automatically grant privileged namespace access.
Configure real authenticated authority pins and quorum. Key storage needs durable
administrator-controlled storage supporting its exclusive publication mechanism.
Unix permissions are checked; Windows ACL acceptance remains unresolved.

Network namespaces isolate IP networking and abstract UNIX sockets, not host
pathname sockets or inherited privileged descriptors. The
[restricted headless launcher](LINUX_APP_CONTAINMENT.md) adds an immutable rootfs,
private process/IPC/user namespaces, identity drop, descriptor sanitation and
seccomp. Native whole-device routing trusts the administrator, kernel, transport
UID and installed privileged services; it is not a compromised-root defense.
Neither mode automatically provides browser identity anonymity.

Post-quantum network identity/KEX improves a specified cryptographic boundary.
It does not upgrade destination web certificates, DoT PKI, Mozilla signing,
operating-system trust, traffic-analysis resistance or endpoint security. No
percentage of production readiness or complete quantum safety is inferred.

### In-progress v6 checkpoint (2026-10-10)

This checkpoint is published at the project owner’s request before remaining fixes. The real CLI daemon testnet currently fails: relay Tokio workers overflow their stacks during startup. The full regression run also found authority-error-message and legacy cell-size test failures; those two were edited but the complete suite has not been rerun after all changes. Do not deploy this checkpoint for production anonymity. Focused dual-signature, external ML-DSA vectors, guarded-link cancellation and session tests provide partial evidence only. Resume with the startup failure, then rerun formatting, strict Clippy, all targets and deployment-path checks before release.
