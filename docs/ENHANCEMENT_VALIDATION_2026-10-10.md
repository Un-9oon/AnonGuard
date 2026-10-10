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

## Remaining release requirements

A separate enhanced-build strict run with fixed 10-second windows reached 32/36
samples without recorded failure at the last verified snapshot. Subsequent SSH
access returned `No route to host`; its final status and remaining raw evidence
could not be retrieved. This experiment is **unverified/incomplete for reporting**,
not a passed test or an attack-resistance result. Retrieve the complete document,
original log and PCAPs from `ag-traffic-fixed-enhanced` on the owned VM before
evaluating it. A live-session shutdown may lose guest-only evidence.

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
