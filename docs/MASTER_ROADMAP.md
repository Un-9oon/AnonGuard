# AnonGuard Linux product and research roadmap

Date: 2026-10-15. Source baseline: local commit
`8236819` (parent ownership/admission commit `032fa80`). The working tree was
clean when planning began. Local commits and past green remote CI are different
evidence; publish/CI acceptance for the current revision remains open.

## Product target and meaning of better

We target an installable Ubuntu 24.04 Linux product with Client and Volunteer
roles, independent onion circuits, a maintained browsing bundle, explicit
fail-closed boundaries, hybrid post-quantum protocols and reproducible evaluation.
VMs are test fixtures. Ordinary clients do not need a VM; public reachability of
a volunteer still depends on NAT, firewall and transport conditions.

We cannot promise stronger anonymity, lower latency, lower bandwidth, more
availability and unlimited scale simultaneously against every adversary. We can
compete on measured dimensions under an explicit scope. The first release aims
for a defensible Linux browsing product; research profiles and private services
must not silently become required for that release. A new mix-network architecture
is outside the user's current chosen scope.

The engineering contract distinguishes:

- **Implemented:** source exists and the live path invokes it.
- **Verified:** named tests passed on the exact revision and environment.
- **Externally accepted:** independent reviewers/operators have supplied evidence.
- **Released:** artifacts, bootstrap, browser signatures and recovery are usable.

A feature is not complete just because its name exists in a module. Missing
features below are planned implementation, not claims that this roadmap adds them.

## Stronger resistance to detection and deanonymization

The [traffic-analysis hardening contract](TRAFFIC_ANALYSIS_HARDENING.md) adds
T1–T6 to W1/W2/W3/W5/W6/W7/W8/W9/W10: explicit transport-metadata/active-probe
assessment, jointly evaluated cover/session defenses, lifetime/volume controls,
path-control resistance, installed endpoint protection and independent adaptive
attacks. Protocol detection, website inference and end-to-end linkage have
separate observers, metrics and gates. "AI cannot analyze it" is not a supported
acceptance criterion. Direct custom ALPN/public relay metadata, nested handshake
patterns and a genuine normal-traffic reference must be included rather than
assuming random encrypted packets look ordinary.

## Quantifying optimization without invented percentages

For every candidate, record a pinned baseline and change one factor at a time.
Report p50/p95/p99 response/circuit-setup latency, successful throughput, failure
rate, CPU-seconds, peak/RSS memory, actual wire bytes, idle cost and attack outcomes.
Keep unsuccessful visits in denominators. Use an identical owned workload,
measurement window, device class, network conditions and stable protocol version.

Current link-cover arithmetic is `8196 / .020 = 409800` bytes/s per direction,
about 6.56 Mbit/s bidirectionally and 70.8 decimal GB/day for one continuously
active bidirectional link, before TLS/TCP/IP overhead. This is schedule arithmetic,
not measured consumption; backpressure, failure and lifetimes change real results.
It is a major optimization candidate, not evidence that cover may safely be removed.

Performance improvement is `(baseline - candidate) / baseline` for a metric where
lower is better. Compare privacy at matched bandwidth/latency budgets; compare
performance only when the required security properties and attack conditions match.
For attack success, report absolute differences, confidence intervals and base
rates, not a single combined 'anonymity percentage'. Predeclare a practically
meaningful gain after the pilot shows variance, before confirmation collection.
No universal 20%, 50% or 99% target is currently evidence-backed.

Security invariants have a different standard: a reproduced escape, authentication
bypass, downgrade, replay acceptance or direct fallback blocks release even if
aggregate performance is excellent. Zero observed failures is necessary evidence,
not proof that a failure is impossible.

## Work packages

### W0 — Reproducible baseline and acceptance inventory (P0)

**Current:** local source, tests, lab packages, CI workflows and release verifier
exist. Latest two local commits were not published; final process logs from an
interrupted build session were not all retained.

**Implement/finish:** pin source/lockfile/toolchain/browser/transport identities;
archive commands, outputs, test inventories, package/binary hashes and explicit
skips in a durable run directory. Run exact-commit CI after authorized publication.
Have a single release checklist link these artifacts rather than infer acceptance
from an older badge. Keep experimental artifacts clearly labelled.

**Acceptance:** clean checkout reproduction, no unexplained skipped required gate,
traceable binary/source provenance, independently retrievable results. Finish W0
before interpreting later measurements. Small integration work; external CI
availability and signing identities are dependencies, not code substitutes.

### W1 — Installed Linux client and leak/crash behavior (P0)

**Current:** native transparent TCP adapter, generated nftables policy, headless
rootfs/syscall/descriptor restrictions and isolated VM fixtures exist. The VM
required the documented executable-specific Bubblewrap AppArmor policy.

**Implement/finish:** compose the actual relay backend with native routing and
browsing. Exercise firewall-before-client startup, default-drop before bootstrap,
service failure/restart, adapter/DNS failure, pre-existing sockets, DNS-over-UDP/TCP,
IPv4/IPv6, IPC brokers, suspend/resume, interface/DHCP/network change, reload,
upgrade/removal and power interruption. Preserve authenticated remote DNS and
anti-SSRF destination resolution/connect binding. Explicitly define unsupported
UDP/QUIC/IPv6 behavior; refusing it is not implementing it.

Use isolated activation/rollback controls and console-based setup so an admin
does not accidentally rely on the connection being blocked. Verify ordinary-user,
rootless/capability and host-root boundaries separately; root/host compromise is
not solved by a user process firewall. Never disable AppArmor globally to pass.

**Acceptance:** no unauthorized test traffic emitted during the supported failure
matrix; healthy actual-relay traffic completes; configuration refusal is actionable;
recovery preserves identities, guards and signed directory history. Preserve
PCAPs, firewall counters and service ordering. Medium/large integration work.

### W2 — Browser product, fingerprint consistency and distribution (P0)

**Current:** Firefox privacy preferences, policy/AutoConfig, session attribution
extension, disposable profile launcher and tests exist. A signed normal addon and
full installed-browser acceptance remain open.

**Implement/finish:** one supported maintained Firefox ESR bundle/channel;
common language/font/window policy; consistent resistance/letterboxing;
first-party circuit and browser storage/cache/session isolation; WebRTC,
preconnect/prefetch, proxy failure and DNS handling tests. Test top-level pages,
iframes, redirects, service workers, WebSockets, downloads and popup/navigation
lifecycles. Prevent the normal release path from running without required active
protections. Verify headers and JavaScript-visible properties together; avoid
per-user spoofing knobs and arbitrary random User-Agents.

Use Mozilla's normal signing path for the extension, real operator-owned account
credentials outside the repository, pinned artifact identity and supported version
checks. Test actual release-browser installation, startup and update. Maintain
rapid vendor security updates; a permanent stale browser fork is not a shortcut.

**Acceptance:** installed signed addon is active, site identities remain separated,
network failures do not bypass the gateway, unrelated supported devices show no
new unintended fingerprint differences, browser updates preserve protections.
The fingerprint surface cannot be declared zero. Medium/large work plus external
signing/maintenance. Browser-only and whole-device modes must be distinct in UI.

### W3 — Fair admission, DoS and overload recovery (P0)

**Current:** tracker node ownership, 512 total sockets, 16 concurrent handshakes,
16 proof exchanges, 32-start burst/refill 16/s, 128 waiters/three per node; gateway
connection limits and service CPU/RAM budgets exist.

**Implement/optimize:** bounded per-source admission with IPv4-mapped/IPv6
normalization, deliberate IPv6-prefix policy and NAT-aware testing; post-auth
per-node fairness; weighted fair queues; TTL/size-bounded accounting maps; global
budgets that survive identifier churn; bounded handshake verification workers,
read/write/idle deadlines and queue backpressure on every external listener.
Measure limits before exposing tuning options. Never treat lots of self-created
keys as proof of independent clients/operators.

Test slow TLS/control peers, costly invalid proofs, partial frames, churn, full
queues, stream floods, directory reconciliation storms and stalled consumers.
Account for cover traffic on idle malicious links. Avoid unbounded label/IP logs
or metrics. Shed excess work before expensive cryptography wherever authenticated
protocol semantics permit, without creating a downgrade path.

**Acceptance:** measured CPU/RAM/file-descriptor/queue/wire ceilings, useful honest
client service under the declared attacker load, automatic recovery after load
ends, no leaked permits/tasks and no direct/unauthenticated fallback. Define and
publish supported capacity from results. Medium implementation plus load work;
distributed bandwidth exhaustion still needs deployment-level defenses.

### W4 — Cryptographic protocol assurance and key lifecycle (P0)

**Current:** X25519+ML-KEM-768, mandatory Ed25519 AND ML-DSA-65, pinned hybrid TLS,
exporter/transcript binding, paired key storage, retirement policy and negative
tests. Some independent-backend primitive interoperability was demonstrated.

**Implement/finish:** inventory every key, purpose, derivation, public pin,
cryptoperiod, signature boundary, stored version and erasure point. Add maintained
external known-answer/ACVP-compatible vectors where applicable and independent
protocol peer tests. Exercise low-order/noncanonical inputs, replay/downgrade,
truncated/cancelled messages, restart nonce/state continuity and secret redaction.
Review hybrid combiner assumptions and exporter/purpose separation explicitly.

Finish compromised relay/authority retirement, offline root recovery, staged key
rotation, authenticated bootstrap/migration and operator ceremonies. Persistent
state must survive power loss and upgrade. Do not replace established primitives
with invented quantum algorithms; QKD/hardware quantum networking is not required
for this design and is not provided by these libraries.

**Acceptance:** no untriaged critical/high findings, successful documented rotation
and compromise drills, external vector/interoperability evidence and independent
protocol/implementation review. Internal tests cannot close the independent-review
gate. Medium engineering plus specialist review with externally dependent timing.

### W5 — Timing, volume and lifetime protection (P1, after W0/W3)

**Current:** mandatory fixed-envelope links, balanced/strict sessions and research
RMT/Poisson profiles. Connection/lifetime/congestion metadata remain visible.

**Implement/compare:** keep one audited scheduler contract; expose separately
versioned research candidates for fixed-rate/padding tails, FRONT/RegulaTor-style
baselines and current ephemeral-defense generation after artifact/license and
integration review. Do not simply stack random jitter, chaos and padding. Specify
which observer sees hop padding versus end-to-end session behavior.

The current mandatory link carrier sends at 20 ms independently of the session
profile. Slowing the inner balanced session or adding another padding engine does
not by itself remove that carrier's idle-wire cost. A candidate must declare
whether it changes session behavior only or the outer link scheduler too; count
costs at both layers. Any carrier change needs coordinated versioning and fresh
attack evaluation rather than claiming free bandwidth savings.

For each candidate, model startup, idle, active, congestion, queue-full, tail and
shutdown states; bound bytes, buffering and maximum delay; prohibit silent
fallback to an unprotected mode. Use workload-independent windows and separately
measure long-lived session starts/stops. Forced lifetime buckets can reduce some
leakage while increasing costs; caps and exclusions must be disclosed.

**Acceptance:** held-out attack/performance frontier improves under a predeclared
budget without authentication/reliability regression. No global-observer immunity
is inferred. This is substantial research/engineering, with multiple iterations.
Changing the cell size/scheduler requires a coordinated wire-version migration.

### W6 — Adaptive attack/evaluation suite (P1, begins early)

**Current:** source-PCAP hashes, group-held-out baseline, validation-calibrated
open-world 1-NN, label/uncertainty checks and exploratory link correlation.
The owned three-size collector is a pilot, not a real-world anonymity dataset.

**Implement:** independent collection days/devices/networks and monitored plus
unseen background owned sites; matched Tor/AnonGuard conditions; stable context
lifetimes; recorded failures; synchronized paired client/exit/destination-side
captures where authorized. Separate protocol detection, website identification,
flow matching and identity linkage as different tasks.

Reproduce maintained established DF/Tik-Tok/RF and relevant newer multi-tab/few-shot
attacks under their actual feature/input requirements. Record artifact commit,
license, train/validation/test split, seeds, hardware and hyperparameters. Train
attackers on the defended profile; optimize only on validation; freeze a separate
confirmation dataset. Add calibrated precision/recall curves, FPR confidence bounds,
site imbalance/base rates, temporal drift and clustered uncertainty across actual
independent collections. Do not count model seeds as independent deployments.

**Acceptance:** reproducible code and real dataset provenance, no cross-split
capture reuse, enough background data to support the claimed FPR interval,
reported failed visits and credible strongest-attack results. Synthetic tests
validate mechanics only. Large experiment work; no fixed low-accuracy promise.

### W7 — Cell, queue and connection performance (P1, after measurement)

**Current:** 8192-byte cells and 20-ms link cover impose significant scheduled cost.

**Optimize:** profile allocations/copies, serializer/AEAD cost, queue occupancy,
scheduler wakeups, TLS record behavior and head-of-line blocking; reuse bounded
buffers and amortize work without nonce reuse or secret retention. Investigate
cell/envelope size and common pacing profiles jointly. Smaller cells need bounded,
authenticated handshake fragmentation/reassembly because PQ proofs exceed small
payloads; canonical framing, replay/order handling and memory ceilings require
review and a coordinated protocol version. Do not just shrink a constant.

Evaluate authenticated link reuse and stream fairness; never replay non-idempotent
application requests automatically after circuit loss. Revisit credit/ACK windows
from measured RTT and bandwidth while retaining hard queue bounds. Batch writes
only within the declared privacy/latency budget.

**Acceptance:** measurable p95 latency/throughput or idle-wire improvement on the
same workload at equivalent evaluated protection, with full regression and wire
cost evidence. A faster unpadded baseline is not an equivalent anonymity product.
Medium/large performance work, dependent on W5/W6 and profile requirements.

### W8 — Sybil admission, path bias and guard diversity (P1)

**Current:** signed directory, PoW/replay checks, key ownership, persistent guards,
role/subnet diversity and duplicate-component checks.

**Implement:** explicit operator/family declarations and policy, authenticated
independent-operator enrollment for the first network, relay reachability and
health probes, admission/revocation controls and privacy-preserving abuse handling.
Consider ASN/prefix diversity from authenticated maintained data with explicit
staleness/failure rules; /16 prefix checks alone are not BGP/ASN independence.

Adversarially test malicious exits/middles, many keys, distributed prefixes,
guard unavailability, induced failures and path-bias/rotation behavior. Retain
small persistent guard exposure rather than rotating entry nodes per request.
Default to the smallest hop policy meeting the evaluated model; extra random hops
increase latency and failure opportunities and need separate justification.

**Acceptance:** no unauthenticated enrollment/identity substitution, predictable
admission cost and capacity, bounded guard exposure under churn and explicit
operator-compromise assumptions. Permissionless Sybil resistance remains a hard
research/operations problem. Medium/large work; cannot be closed by PoW alone.

### W9 — Authority consistency, liveness and capacity (P1)

**Current:** >2/3 exact-snapshot acceptance, rollback/equivocation refusal and hard
512-relay/16-authority caps. Partitions/divergent snapshots can stall service.

**Implement/optimize:** document fault/quorum/clock assumptions, test partition,
join/leave, restart, stale view, concurrent registration and equivocation state
machines. Define reconciliation/epoch convergence and bounded retries. Never
serve an expired/unsigned directory merely to make a liveness test pass.

Measure signature verification, snapshot bytes, cache churn and bootstrap/recovery
latency. Consider authenticated incremental/cached directory representations only
after proving consistent snapshots and bounded validation; blindly raising caps
can exceed message/memory and bandwidth limits. Benchmark capacity tiers and
publish the supported tier rather than claim an Internet-scale mesh.

**Acceptance:** declared safety and conditional liveness properties survive fault
injection; resource costs are bounded at advertised capacity and security state
survives restart. Large work if changing the consensus protocol; an independent
protocol review is necessary for stronger BFT claims.

### W10 — Censorship transports and reachable volunteers (P1/P2)

**Current:** obfs4/private bridge support and pinned tracker bootstrap. Private
reverse SOCKS rendezvous is separate from onion circuit enrollment.

**Implement:** clean transport adapter contracts, maintained transport binaries,
identity pin continuity, managed restart/backoff, bounded bootstrap and distribution.
Assess additional established transports after threat/dependency review rather
than invent TLS impersonation. Test blocking, active probing, DNS/IP blocking,
NAT/CGNAT, bridge loss and transport crashes on owned networks.

Implement explicit reachability checks and operator instructions. If public reverse
onion relay support is required, design identity-bound relay forwarding, resource
and abuse controls as a separate protocol; do not silently use the current plain
SOCKS reverse path. Keep exit operation an explicit opt-in, not the Volunteer default.

**Acceptance:** reproducible reachability under named tested restrictions and
clean failure under unsupported networks; no promise to bypass every censor.
Medium/large work; diverse external networks are necessary evidence.

### W11 — Secure packages, updates and recovery (P0/P1)

**Current:** Debian packaging, lifecycle tests, release version agreement and
workflow-identity-bound artifact verification. No complete signed update service.

**Implement:** reproducible artifact build/provenance, SBOM/dependency audit,
maintained release keys/identities and normal browser signing. Integrate a maintained
TUF implementation with offline root/threshold/delegated roles, persisted versions,
expiry and rollback/freeze/mix-and-match refusal. Keep ordinary service accounts
unable to rewrite trust roots. Treat authenticated rollback for recovery as a
separate operator-authorized policy; never remove state to bypass monotonic checks.

Stage and validate updates before activation, preserve identities/guards/votes,
atomically switch, stop protected traffic on incompatibility and exercise power
loss, corrupt media, failed install and compromised signing-key recovery.

**Acceptance:** unsigned/tampered/stale/revoked/incompatible packages are refused,
recovery works without trust reset or privacy bypass, independently reproduced
artifacts and actual publication ceremony exist. Large integration/operations work;
accounts, domains and signing keys are operator dependencies.

### W12 — Private services and service-side IP hiding (separate P2 release)

**Current:** equivalent onion-service protocol is missing.

**Implement:** reviewable service identity/address format, authenticated expiring
descriptors, introduction/rendezvous roles, separate client/service circuits,
end-to-end service authentication, replay/abuse/admission limits and key rotation.
No service endpoint/DNS fallback may expose the host address. Do not claim .onion
compatibility or reuse the plain reverse tracker as a private-service substitute.
Use established crypto libraries and independently review the composed protocol.

**Acceptance:** service and client connect through independent devices/networks,
no direct service-IP fallback, spoof/replay/descriptor poisoning and rendezvous
DoS tests pass, rotation/revocation and recovery work. Very large protocol/product
work; additional review required. Keep it outside the first browsing release so
this work does not indefinitely block a narrower honest deliverable.

### W13 — Operations, population, privacy and user experience (P0 onward)

**Implement:** one installer and explicit Client/Volunteer choice; guided trusted
bootstrap and health diagnosis; a client cannot falsely display protected while
mandatory components are inactive. Volunteer default should be non-exit. Explain
browser-only versus supported OS protection and unsupported traffic clearly.

Publish owner-approved contact, support/version policy, incident/retirement runbooks,
privacy-preserving aggregate metrics and opt-in diagnostics without destinations,
credentials or identifiable flow logs. Audit public binds, firewalls, service users,
state permissions and dependency/browser update cadence. Arrange actual independent
operators across failure domains; multiple VMs or countries under one administrator
are not automatically independent. Recruit a genuine consenting population instead
of treating dummy traffic as additional independent users.

**Acceptance:** tested onboarding/upgrade/removal and incident drills, declared
operator responsibilities, observable aggregate health without sensitive telemetry,
a real staffed maintenance process and measured supported public deployment.
This requires continuing people/infrastructure, not a one-time code completion.

## Delivery order and dependencies

| Milestone | Required work | Honest deliverable |
| --- | --- | --- |
| M0 | W0 plus existing fixes | Reproducible experimental checkpoint; no public anonymity approval |
| M1 | W1/W2/W3/W4 engineering, W11 lab delivery | Supported Linux FYP/controlled pilot with explicit threat boundaries |
| M2 | W5/W6/W7, adversarial W8/W9, external review | Frozen evaluated candidate and narrowly stated measured results |
| M3 | Signed W2/W11, W10 reachability, W13 operators/population; all critical gates | Limited public beta with named assumptions, monitoring and recovery |
| M4 | Sustained multi-network evidence, independent review fixes, operated maintenance | Public release claim only for the accepted scope; never 'undefeatable' |
| Separate M5 | W12 and review | Private-service product extension |

Scheduling is risk-driven. With two people and 10–11 laptops, basic lab work and
measurements can run in parallel. External signing, reviews, independent operators,
realistic dataset collection and sustained reliability cannot be compressed into
three or four days by writing code faster. Budget in multi-week engineering and
multi-month validation/operations phases; estimates need a baseline pilot and actual
availability. This is planning guidance, not a promise of a completion date.

## Release/no-release rules

- Every critical authentication/leak/recovery defect blocks public release.
- A failed strong attack does not prove universal anonymity; report the attack,
  observations, thresholds, population, dataset and resource conditions.
- Anonymity-set size, timing protection, quantum cryptography and browser identity
  are different properties. No single pass percentage can replace their gates.
- Compare Tor network/protocol and Tor Browser in their corresponding scopes.
  Reproduce matched baselines rather than infer that Tor has no padding/PQ research.
- Add scope only when its independent acceptance can be maintained. Windows/macOS
  isolation and a new mix-network architecture are outside this Linux roadmap.

## Primary references and design inputs

The roadmap recommendations are engineering inferences for AnonGuard, not claims
that the following projects have validated it:

- [Tor guard selection](https://spec.torproject.org/guard-spec/) and
  [padding overview](https://spec.torproject.org/padding-spec/overview.html).
- [Tor disclosed attack limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/).
- [FRONT](https://www.usenix.org/conference/usenixsecurity20/presentation/gong),
  [RegulaTor](https://petsymposium.org/popets/2022/popets-2022-0049.php), and
  [2026 ephemeral defenses](https://www.petsymposium.org/popets/2026/popets-2026-0022.php).
- [Official reproducibility artifact for ephemeral defenses](https://github.com/maybenot-io/popets-2026.1-ephemeral-defs-paper-artifacts).
- [Real-world open-world evaluation](https://www.usenix.org/conference/usenixsecurity22/presentation/cherubin),
  [Robust Fingerprinting](https://www.usenix.org/system/files/usenixsecurity23-shen-meng.pdf), and
  [2026 multi-tab attack](https://www.usenix.org/conference/usenixsecurity26/presentation/liu-lin).
- [Browser fingerprinting protections](https://support.torproject.org/tor-browser/features/fingerprinting-protections/)
  and [Mozilla signing/distribution](https://www.extensionworkshop.com/documentation/publish/signing-and-distribution-overview/).
- [TUF specification](https://theupdateframework.github.io/specification/v1.0.36/).
- [ML-KEM standard](https://csrc.nist.gov/pubs/fips/203/final) and
  [ML-DSA standard](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).

Repository evidence: `docs/PRODUCTION_READINESS.md`, `docs/LINUX_RELEASE_GATES.md`,
`src/onion/{session,link_cover,flow}.rs`, `src/mesh/{tracker,guards,pool,authority,sybil}.rs`,
`scripts/{browser_session,native_adapter,device_setup,anonguard_run_app,verify_release}.py`,
`contrib/anonguard.service`, `eval/TRACE_EVALUATION.md` and CI workflows. Inspect
these again before implementing a work package against a later source revision.
