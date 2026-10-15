# Traffic-analysis hardening and acceptance contract

Date: 2026-10-15. Planning baseline: local `5e22738`. This extends W5/W6/W8/W10
of MASTER_ROADMAP.md. It changes the roadmap, not the live scheduler or transports.

## Objective and limits

We aim to make protocol identification, activity inference and flow linkage
materially harder for specified observers while preserving bounded resource use,
authentication and reliable delivery. We cannot promise that every AI will find
traffic normal or cannot analyze it. Encryption does not hide the existence of a
connection, all endpoint metadata, or every timing pattern.

"Normal" must mean an explicitly defined reference population (browser/version,
application mix, device/network conditions and observation window), not arbitrary
Internet traffic. A detector unable to distinguish one restricted dataset may
still identify known relay IPs, different TLS metadata, lifetime patterns or
unseen workloads. Protocol identification does not alone establish personal identity;
website identification and end-to-end correlation require separate evidence.

## Three distinct primary targets

| Task | Observer and examples of evidence | Required output |
| --- | --- | --- |
| AnonGuard protocol detection | Client-side network observer; public relay/bridge metadata, TLS/transport setup, packet lengths/directions, timing and lifetime | ROC/precision-recall, sensitivity at predeclared FPRs, confidence intervals, realistic prevalence and unseen conditions |
| Website/activity fingerprinting | Client-to-entry observer with defense-aware training; sizes, timing, burst structure, multi-tab context and session boundaries | Correct monitored identification, wrong monitored labels, background false alarms, open-world precision/recall and temporal/device/network generalization |
| End-to-end linkage | Attacker observing authorized client and exit/destination capture points; timing/volume, aligned activity and active interference | Paired versus unrelated-flow distributions, top-k/rank matching and binary linkage at realistic candidate counts/FPRs; disclose both capture locations |

A low score in one row does not close either other row. Protecting a service's
address is a separate private-service protocol requirement, not an exit-browser
claim. A compromised endpoint or a personal account can expose identity without
breaking the routing protocol.

## Ordered engineering changes

### T1 — Remove unnecessary public transport identifiers (W10)

Inventory actual wire-visible endpoints, DNS/bootstrap, TLS versions/groups,
ALPN, certificate behavior, record lengths, nested handshakes, connection reuse
and failures for each supported transport. Direct AnonGuard links use a custom
ALPN; a passively visible ClientHello can therefore identify the direct protocol.
Public relay addresses can reveal use even if packet shapes change. Direct mode
must not advertise protocol-indistinguishability.

Evaluate maintained established private bridge transports, including their own
passive fingerprints, active probing/replay behavior, server authenticity and
failure signals. Obfs4 is not ordinary HTTPS simply because it is encrypted.
Do not remove ALPN/pin/dual-signature authentication to make a packet trace look
less distinctive. Keep the inner authenticated protocol and evaluate the outer
transport separately. Use endpoints the operator owns or is authorized to use;
do not impersonate another service, intercept destination TLS, weaken certificate
validation or promise generic censorship bypass.

Acceptance: direct/bridge modes are labelled accurately; adversarial passive and
owned active-probe tests cover fresh sessions, repeated sessions and failures;
no authentication regression. An observed gain is scoped to the detector,
metadata visibility and reference traffic actually evaluated.

### T2 — Co-design outer cover and inner sessions (W5/W7)

Keep a common implementation/distribution of supported privacy profiles rather
than arbitrary per-device timing settings. Compare fixed-envelope pacing,
bounded volume/lifetime buckets and separately versioned FRONT/RegulaTor/ephemeral
candidates. A shared defense generator may randomize per connection; its security
must not rely on hiding the algorithm or preventing the attacker from training
on it. Do not combine independent randomizers without a model of the resulting
observable distribution and protocol semantics.

Specify startup, handshake, queue-full, congestion, idle, active, tail and closure
states. Bound padding bytes, delay and buffering. Measure nested handshake/burst
patterns and both directions. Current outer link pacing is 20 ms regardless of
inner profile: changing the inner profile alone does not remove outer idle cost.
Do not claim bandwidth savings until packet captures demonstrate them.

Acceptance: train adaptive attackers on every candidate and compare at matched
latency/wire budgets. Retain a candidate only when the strongest evaluated attack
and cost frontier support it. No silent fallback when the privacy budget cannot
be maintained; define explicit refusal/backpressure and disclose its visibility.

### T3 — Reduce duration/volume and session-linkability signals (W5/W2)

Collect request-independent observation windows plus complete session lifetimes,
including idle baselines and failures. Evaluate bounded tail/bucket policies,
context reuse and authenticated multiplexing across the declared application
scope. Do not merge first-party identities merely to hide handshake counts, and
do not mix personal account sessions into an anonymity context. Preserve reliable
half-close, flow control, maximum lifetime and cancellation behavior.

Acceptance: measure content-volume inference, start/stop inference, multi-tab
linkability and overhead separately. Report large/long requests excluded by a
policy and failed visits. End-of-capture artifacts must not become the classifier's
shortcut. Fixed windows are an experiment control, not proof of hidden lifetimes.

### T4 — Increase attacker's path-control difficulty (W8/W9/W3)

Preserve persistent guard exposure and authenticated directory/ownership policies.
Evaluate operator/family and maintained network-diversity information separately
from mere key or subnet counts. Test malicious relay participation, induced
connection failure, guard churn, partitioned authorities and resource-exhaustion
behavior on owned deployments. Add fair admission without unbounded identity/IP
accounting or destination-bearing logs. Do not rotate all guards per request or
assume extra random hops always improve anonymity.

Acceptance: explicit attacker relay/operator fractions and observation assumptions,
path-bias/churn outcomes, recovery and conditional quorum liveness. A small network
under one operator is a lab regardless of country count. These controls increase
cost under named assumptions; they cannot eliminate global observation.

### T5 — Close browser/device side channels first (W1/W2)

Complete installed real-relay browser/native acceptance, signed addon activation,
common fingerprint policy and site isolation. Include WebRTC, DNS, IPv6, existing
sockets, browser background activities, service workers, downloads, adapter/proxy
failure, reboot/reload and network changes. Retain explicit privileged OS setup
and fail-closed behavior. Routing cannot cure malware or an identified login.

Acceptance: a single reproduced unauthorized egress/authentication bypass blocks
release. A passing narrow fixture must not stand in for the composed product.

### T6 — Independent adaptive evaluation and model selection (W6)

Use the existing capture hash and train/validation/test contracts as the minimum.
Collect consensual owned normal-reference and AnonGuard workloads across different
collection runs, days, device types and networks. Keep entire sessions/related
flows in the same partition. Prevent labels from leaking through filename/time
ordering, target lab IPs, capture interface or device differences. Include slow
networks, retransmissions, realistic site/background mixtures, multiple tabs,
software upgrades and intentionally degraded conditions.

Use simple metadata/timing/volume baselines alongside established DF/Tik-Tok/RF
and appropriate newer multi-tab attacks. Separately validate a binary protocol
detector; do not relabel the website 1-NN evaluator as that detector. Compare full
metadata and content-shape-only threat variants, including a trivial known-relay
address baseline. Evaluate multi-observer attacks and owned active delay/drop
interference as different attacker classes. Record model/artifact identity,
hyperparameters, feature representation, compute budgets and untested classes.

Tune candidates and thresholds only on validation data. Freeze the defense before
independent confirmation collection. Report each attack, worst evaluated outcome,
prevalence assumptions and uncertainty across actual collection groups. Model
seeds do not create independent users or networks. If a new trained attack wins,
reopen the corresponding defense gate; do not retain only favorable classifiers.

## Statistical and operational acceptance

Predeclare the claimed detector/attack operating points and resource budget after
a pilot establishes variance, before the final comparison. For binary balanced
classification, chance accuracy is 50%; that does not make 50% a universal anonymity
target. Class imbalance requires base-rate-aware precision/recall and FPR reporting.
A detector that always predicts background can have high accuracy while being
useless; low detector success must be compared with appropriate trivial baselines.

Report confidence bounds. For example, supporting a below 0.1% FPR bound at 95%
confidence with zero observed false alarms needs about 2995 independent negative
observations under a binomial model (`1 - .05**(1/n)`). Correlated visits invalidate
that simple interpretation. This is sample-size planning, not a measured result
or sufficient product release criterion. Use separately justified clustered
methods for repeated sessions/devices/networks.

Choose the strongest tested defense that fits the predeclared latency, actual
wire/idle bandwidth, CPU/RAM, failure and recovery budgets. Publish a trade-off
frontier if no single candidate dominates. Cover bytes are not extra independent
users. Neither a classifier score near chance nor standardized encryption proves
that a global observer cannot link flows.

## Completion and non-completion

This roadmap update is complete when T1–T6 have named implementation/evaluation
work, prerequisites, scoped claims and acceptance checks. Runtime completion
requires source changes, exact-commit regressions, actual captures and independent
review; none is implied by writing this document. No live transport/scheduler
change or AI-resistance measurement was performed in this documentation batch.

## Primary sources and scope of inference

- [Tor disclosed correlation limits](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/).
- [Tor padding layers](https://spec.torproject.org/padding-spec/overview.html).
- [Fingerprinting obfuscated proxies with encapsulated TLS, USENIX 2024](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf): supports testing nested protocol metadata, not claiming TLS wrapping eliminates detection.
- [Probe-resistant proxy research](https://www.usenix.org/conference/foci20/presentation/frolov): useful transport-design evidence, not proof that AnonGuard is indistinguishable.
- [2026 ephemeral defenses](https://www.petsymposium.org/popets/2026/popets-2026-0022.php): candidate for comparative integration/evaluation, not inherited protection.
- [Real-world open-world WF evaluation](https://www.usenix.org/conference/usenixsecurity22/presentation/cherubin).
- [2026 multi-tab/few-shot WF](https://www.usenix.org/conference/usenixsecurity26/presentation/liu-lin).

Recommendations above are engineering inferences for this source baseline. A
finding on another system does not establish an AnonGuard measurement.
