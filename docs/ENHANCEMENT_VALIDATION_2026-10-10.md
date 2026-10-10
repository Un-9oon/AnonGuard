# Parallel engineering and owned-VM validation — 2026-10-10

Status: engineering improvements implemented; production anonymity and adaptive
AI-resistance are **not established**. This is a follow-up to
[the original VM pilot](VM_VALIDATION_2026-10-10.md), not its replacement.

## Changes

- Padded session scheduling now starts the next interval after the current write
  completes. A paused-clock regression fills a bounded socket, stalls it, then
  verifies that releasing backpressure does not generate an immediate catch-up
  cell. Identity authentication, cell size and privacy-profile rates are unchanged.
- Relay outgoing and accepted TCP connections enable `TCP_NODELAY`, avoiding
  Nagle batching on already paced cells. Congestion and TCP packetization remain.
- Packet collection preserves failures/partial progress, refuses evidence
  overwrite and rejects flow-observer failures, truncated captures and kernel
  drops. Per-window byte accounting explicitly includes other live contexts.
- Evaluation adds class-count baselines, seeded label-permutation controls,
  uncertainty/dependence caveats, feature ablations and correlation tie reporting.
  Incomplete captures cannot be presented as complete pilots.
- Optional fixed 5..120-second observation windows include post-response idle
  cover without stopping at each workload's response end. Exceeding the window
  invalidates the sample. Testnet deadlines account for the bounded 36-window run.
- Browser provisioning can emit one coherent policy/AutoConfig bundle with
  checksums. Isolation-XPI preflight rejects unsupported identities, permissions,
  extra code and unsafe archives; **Firefox still verifies the actual signature**.
- Linux setup can probe ordinary-user Bubblewrap namespace prerequisites without
  bootstrap or policy changes. It reports Ubuntu AppArmor restrictions and
  administrator prerequisites without disabling protections.

## Regression evidence

Full Rust `cargo test --offline --locked --all-targets` passed, including 93
library tests, actual local CLI testnets, handshake boundaries and multi-round
BFT convergence. The privileged namespace acceptance test remains explicitly
ignored in that suite; this result does not certify it. Clippy with all targets
and warnings denied, formatting and whitespace checks passed. The adjusted
testnet-deadline fixture was subsequently re-run: both testnets passed.

Focused Python suites passed: browser launcher 10, native helpers 13, owned
evaluation integrity 5 and general trace evaluator 3. Browser isolation JavaScript
suite: 6 passed. Browser/native helper suites also passed on the Ubuntu VM.

On Ubuntu 24.04.3, the prerequisite probe correctly refused Bubblewrap with
AppArmor userns restrictions active. Temporarily loading the documented profile
made the probe pass; the profile was then unloaded. Kernel restrictions remained
enabled. This checks basic namespace prerequisites, not full installed containment.
A browser bundle was emitted without modifying the installed browser; signing
and operator-installed browser acceptance remain external release gates.

## Fresh packet pilot: before and after

Two fresh runs used the same owned loopback workload/collector contract, each with
36 strict and 36 unpadded traces; 24 training and 12 held-out visits per profile.
Both builds passed actual transfer and relay-loss tests on the VM. Capture windows
span request completion plus one second. No real users or external destinations
were monitored. The VM is a memory-constrained live guest on the same host as
development; host/guest load was not experimentally controlled, including parallel
regression/build/archive work. This sequential comparison cannot isolate causality.

| Strict-mode measure | Before | After |
|---|---:|---:|
| 1-NN held-out correct | 10/12 | 7/12 |
| Small MLP accuracy, three seeds | 66.7%, 83.3%, 75% | 33.3%, 41.7%, 50% |
| Held-out p95 SOCKS + response latency | 12.17 s | 7.84 s |
| Captured payload-frame bytes / response bytes | 20.02 | 18.50 |
| Duration-only 1-NN accuracy | 66.7% | 83.3% |
| Counts/bytes-only 1-NN accuracy | 83.3% | 91.7% |
| Exploratory link-window matches | 9/12 | 8/12 |

Unpadded 1-NN was 12/12 before and 9/12 after; unpadded p95 latency moved
1.30 s to 2.83 s. That variability further prevents claiming a clean causal speed
or attack-resistance improvement. Captured byte ratios are **not per-request or
whole-network padding overhead**: other cached contexts, headers, retransmission
and partial tails affect them. See the documented nominal
[cover budgets](MULTIHOP_SCHEDULING.md).

Overall classifier reductions are encouraging pilot observations, while the
strong duration/volume classifiers and high correlation scores remain adverse
evidence. No anonymity threshold was achieved or established. Twelve dependent
test visits, three size classes and a small MLP are not an established adaptive
website-fingerprinting evaluation or a Tor comparison.

## Fixed-window experiment and interrupted-run history

A separate enhanced-build strict run with fixed 10-second windows reached 32/36
samples without recorded failure at the last verified snapshot. Subsequent SSH
access returned `No route to host`; its final status and remaining raw evidence
could not be retrieved. This experiment is **unverified/incomplete for reporting**,
not a passed test or an attack-resistance result. The user then confirmed a VM
shutdown. Reconnection showed a new SSH host key and an empty live-session
workspace: the original guest-only experiment was lost. Its available partial
progress is not substituted with a fabricated complete result.

The reviewed fixture was restored after screenshot-verified host authentication,
and a **separate fresh** strict run with fixed 10-second windows completed 36/36
samples. Transfer and relay-loss regression passed in 377.24 seconds. The complete
dataset, original log, all 36 PCAPs, evaluation outputs and SHA-256 inventory were
then archived locally outside the VM. Fixture daemons stopped and no VM firewall
tables were left by this capture test.

| Fresh fixed-window strict pilot measure | Result |
|---|---:|
| Held-out visits | 12 (24 training) |
| 1-NN correct | 6/12 (50%) |
| Small MLP accuracy, seeds 11/29/47 | 41.7%, 58.3%, 50% |
| Balanced label chance | 33.3% |
| 1-NN Wilson interval, conditional on independence | 25.4–74.6% |
| Duration-only 1-NN correct | 0/12 |
| Counts/bytes-only 1-NN correct | 6/12 |
| Early-sequence 1-NN correct | 3/12 |
| Held-out p95 request completion | 2.21 s |
| Captured payload-frame bytes / response bytes | 66.56 |
| Exploratory link-window matches | **12/12**, no tied top scores |

This changes the observation contract, not the routing/cryptographic policy.
The same-VM sequential samples are dependent; the interval is not a deployment
confidence guarantee. MLP label-permutation tail probabilities were approximately
0.362, 0.085 and 0.156, providing no robust small-sample claim of an effect in this
pilot. Zero duration-only matches does not prove duration is uninformative to
other classifiers or observers. Counts/bytes still support above-chance matches.

The high byte ratio includes ten seconds of link cover and other live contexts;
it is not request-exclusive overhead and must not be compared directly with the
request-completion-plus-one-second ratios. The lower latency occurred after a
fresh live-guest restart; a causal speed improvement is not isolated.

**The 12/12 link-matching result is adverse evidence.** The matcher compares
encrypted client/guard and last-relay/exit-link windows from the same loopback
capture, independently aligns their first payloads and searches up to 500 ms of
shift. It is not destination-side public-network deanonymization or identification
of a person. Nevertheless, fixed request windows did not defeat this observer,
and workload-classification results cannot justify a claim of correlation safety.
No matched Tor baseline, established adaptive model or open-world data was run.

Static inspection of `src/gateway/server.rs`'s intermediate-relay loop shows
received forward cells written to the downstream link and received backward
cells written upstream, with optional jitter rather than independent link cover.
Preservation of timing across those paths is a plausible contributor; this pilot
does not isolate its causal contribution. Endpoint session padding alone therefore
must not be advertised as removal of cross-link timing structure. A further
correlation-defense design needs explicit attacker assumptions, link-level
traffic-independent scheduling/cover or other evaluated mechanisms, resource
bounds and fresh held-out attacks; simply adding more random jitter is not an
evidence-backed fix. Deployment remains gated on that work.

All four GitHub workflows for implementation commit `9a908c1` completed
successfully: tests/lint, Firefox integration, dependency audit and combined CI
(including Linux/macOS/Windows compilation, headless containment and the short
fuzz campaign). Automated audit and short fuzzing are not independent crypto
review or sustained adversarial validation.

## AnonGuard versus Tor: defensible interpretation

For current public anonymous browsing, Tor Browser plus the Tor network is the
more defensible choice. This is a judgement about demonstrated deployment and
browser protections, not a matched empirical proof that Tor wins every metric.
AnonGuard is an independent experimental onion-routing implementation; no
equivalent Tor run was collected in this pilot.

| Concern | AnonGuard mechanism | What the evidence supports |
|---|---|---|
| Timing/volume analysis | Paced fixed-size cells, dummy cover, bounded idle tails | Mitigation attempt; residual classifier/correlation results prevent claiming the attack is solved |
| Browser tracking | Disposable ESR profiles, locked preferences and optional context isolation | Useful integration; signing/distribution and cross-device fingerprint acceptance remain open |
| Application network escape | Linux namespace containment and native firewall/adapter | Selected containment paths tested; not a compromised-host or universal endpoint solution |
| Quantum-era key exchange | X25519 + ML-KEM-768 hybrid circuit handshake | Concrete algorithm distinction; Ed25519 authentication remains classical and independent review is required |
| Cross-context linking | Optional browser context labels bound to cached sessions | Isolation boundary, not anonymity-population growth or protection from identifying logins |
| Malicious exits/plaintext | Authenticated relay links, destination policy, browser HTTPS controls | Neither onion system makes HTTP plaintext end-to-end confidential; HTTPS remains necessary |
| Anonymity population | Operator-provisioned authorities and relays | More hops do not substitute for independent operators and real user/traffic diversity |

Tor explicitly discloses [two-ended timing correlation limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/),
and also has [cover-traffic specifications](https://spec.torproject.org/padding-spec/).
Padding is therefore not uniquely absent from Tor, nor sufficient to claim
AnonGuard superiority. Tor Browser documents
[letterboxing, user-agent normalization and first-party defenses](https://support.torproject.org/tor-browser/features/fingerprinting-protections/),
while its [network metrics](https://metrics.torproject.org/networksize.html) record
its operational public relay/bridge network. Its published
[circuit handshake specification](https://spec.torproject.org/tor-spec/create-created-cells.html)
describes Curve25519-based ntor/ntor-v3; a different algorithm suite alone does
not establish stronger anonymity. Both require
[HTTPS for destination confidentiality](https://support.torproject.org/tor-browser/features/secure-connections/).

Predicting a workload/site from packets, detecting the routing protocol and
linking a user to a destination are distinct attacker tasks. This pilot does
not prove that any classifier identified a real person, nor that all those tasks
were defeated. A defensible FYP claim is implementation and evaluation of
post-quantum-hybrid exchange, padded sessions and Linux containment tradeoffs;
"solves all Tor flaws" is unsupported.

## Open gates

Independent cryptographic review, established defense-aware/open-world attacks,
independent days/devices/networks, complete-session bandwidth accounting,
destination-side correlation, signed browser distribution and installed native
browser/firewall crash/reboot acceptance remain required. Compromised-host
protection and fully post-quantum authentication are not implied by this batch.

Local raw evidence is retained outside Git in `vm-evidence/2026-10-10/`, including
separate before/after datasets, evaluator outputs, PCAP archive and original logs.
All 72 before-run PCAP hashes were matched to the local archive before removing
only redundant guest copies to avoid its RAM-backed disk exhaustion. Prior pilot
evidence is preserved. No private access keys or real browsing history are committed.
