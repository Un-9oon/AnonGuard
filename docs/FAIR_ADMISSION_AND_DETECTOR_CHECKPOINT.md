# Source admission and protocol-detection engineering checkpoint

Date: 2026-10-15. Base: local `d034504`. This records implemented boundaries and
verification scope, not public anonymity or AI-indistinguishability acceptance.

## Runtime change

Tracker handshakes now have a bounded source-group budget in addition to existing
global concurrency/start-rate budgets. Four concurrent handshakes per source,
64-start burst and at most 12 starts/s are engineering defaults. IPv4-mapped IPv6
addresses normalize to the same IPv4 group; ordinary IPv6 addresses share a /64.
The source permit spans TLS plus server authentication and is released before
waiting registration/tunnel lifetime. A rejected source does not consume global
rate credit; no admission wait tasks are created.

Accounting holds at most 4096 groups. Idle entries expire after 120 seconds and
are swept on admission or at 30-second periodic ticks; outstanding permits prevent
entry eviction and semaphore replacement. This avoids unbounded accounting and
preserves active concurrency counts. Source counters are not persisted or logged.
NAT/forwarder users share budgets. The policy is not complete weighted fairness,
operator independence or protection against distributed bandwidth exhaustion.

The existing rate bucket was moved to a shared internal module without weakening
its global 32-start burst/refill 16/s limit. Capability/ownership verification, PoW,
TLS/ALPN, directory publication and onion routing semantics are unchanged.

## Separate evaluation change

`eval/evaluate_protocol_detection.py` implements a binary packet-shape baseline
for explicit AnonGuard and reference classes. Each defense needs both classes in
training, validation and held-out groups. The normal reference population must be
named. Actual packet visits need retained source-PCAP hashes. Duplicate visits
or cross-split capture reuse refuse evaluation. A synthetic fixture is an explicit
test-only opt-in, never a measured protocol result.

Training-only feature scaling feeds a nearest-class distance ratio; it is not a
calibrated probability or an established deep detector. The threshold is selected
on validation data only under an empirical reference-FPR constraint. Held-out
outputs include sensitivity/FPR/precision, balanced accuracy, tie-aware AUROC,
Wilson intervals, assumed-prevalence projections and workload-overlap disclosure.
The output remains exclusive/private and bounded in pairwise work.

This detector excludes IP/ALPN/TLS metadata and active probing. A low shape score
cannot override a known relay address or custom direct ALPN. Website identification
and end-to-end correlation remain different tasks. No real reference capture
population or new AI-resistance result was produced in this batch. CI now invokes
the six synthetic integrity tests alongside the existing evaluator tests.

## Verification scope

- Source admission unit tests cover slots/release, IPv4 aliases, IPv6 address
  rotation, rate churn, accounting cap/expiry, live-entry preservation and cleanup
  without a new connecting source. Existing global rate-boundary tests remain.
- The socket regression fills one source's slots, confirms excess refusal, then
  completes authenticated TLS from another loopback source before the first source
  releases its slots. EOF then permits the original source to reconnect.
- Tracker regression covers all 128 waiting registrations, consumer capacity,
  mandatory ownership/capability proofs, malformed controls, cancellation/expiry,
  and the actual reverse gateway's four-transfer refill path. Fixture identities
  are precomputed before the short-lived capacity test begins, rather than spending
  its registration lifetime on unrelated key generation.
- The broad source-admission checkpoint passed 278 tests, zero failures and two
  explicit ignored privileged/transport tests. This run preceded the final periodic
  source-cleanup addition. Final cleanup/admission unit tests and the full 10 tracker
  regressions separately passed afterward; do not merge those counts into a claim
  of one final-revision full-suite run. Final all-target/all-feature strict Clippy,
  formatting and diff checks passed. The optimized build and
  optimized real-daemon tests passed (2/2). Release Clippy also passed.
- Protocol detector 6, open-world 8, generic trace 3, owned-evaluation 7 and timestamp-ordering 5 tests pass.
  Their inputs are synthetic or malformed fixtures, not successful privacy evidence.

Exact commands use locked Cargo dependencies and the documented test targets.
The task-local cache restored 310 root/fuzz crate versions from official archives,
verified against their lockfile SHA256. Matching Rust 1.95 formatting/lint tools
were extracted from checksum-verified distribution packages without host install.

## Fresh VM evidence and remaining gates

The initial probe did not return an SSH host key. A local read-only libvirt
inventory showed the already authorized Ubuntu VM was shut off. It was started,
its lease 192.168.122.128 and user-supplied fingerprint matched, and existing SSH
key access worked. The VM was left running. No unrelated VM was started.

On that VM the latest source-fairness/ownership tests 8/8, reverse gateway tests 2/2
and optimized real-daemon testnet tests 2/2 passed. The owned collector produced 72
complete fixed 5-second windows (36 strict, 36 unpadded) for three owned byte-size
workloads across three sequential blocks. All 72 source PCAP hashes were checked
on the VM; the 24 held-out PCAPs were retrieved and checked again by link analysis.
The run's input binary/script hashes and private raw capture/dataset logs are
retained outside the repository. "Unpadded" is still AnonGuard, not normal Internet.
No unrelated public/user browsing was captured.

### Captured-timestamp integrity correction

The strict raw dataset contained one 1-microsecond timestamp reversal. The strict
schema validator refused the initial combined dataset. Original datasets/PCAPs
were preserved. The new explicit timestamp tool generated a source-hash-linked
derivative, stable-sorting only clock backsteps within 2 microseconds. One trace
changed, and larger/cumulative backward jumps refuse. The complete derived schema
was validated before output creation. Subsequent reports identify the derivative
hash; they must not be described as an untouched raw-event sequence.

Future owned collection now records ordering metadata and validates the complete
dataset schema before publishing complete output. Link analysis uses the actual
declared 5-second window, verifies source-PCAP hashes and reports timestamp ordering;
it does not manufacture a 15-second zero tail. Independent first-payload alignment
still discards absolute timing lag, so this is not synchronized end-to-end
correlation or global-adversary validation.

### Small held-out pilot results

Training used the first two blocks and the last block was held out: 12 visits per
profile, three workload labels. These are dependent same-VM samples, not real
website/browser or multi-network populations. Multiple model seeds are not
independent collection runs. No Tor comparison or normal-reference detector run
was performed.

| Metric | Strict | Unpadded |
| --- | --- | --- |
| Byte-size 1-NN classification | 3/12 (25%) | 10/12 (83.3%) |
| Small MLP, three seeds | 16.7%, 25%, 41.7% | 83.3%, 83.3%, 91.7% |
| Counts/bytes feature ablation | 50% | 66.7% |
| Held-out p95 request completion | 1659 ms | 870 ms |
| Observed whole guard-link bytes across held-out windows | 70,135,255 | 6,372,192 |
| Exploratory paired-link top-1 match | 3/12 | 2/12 |

Balanced three-label chance is 33.3%; link-window random candidate chance is 1/12.
The strict 1-NN Wilson interval is approximately 8.9–53.2%, assuming independent
visits; actual repeated visits do not justify that independence. Other feature
views still expose signal. Strict observed about 11 times as many whole-link bytes
in these windows and higher p95 completion. Bytes include existing contexts,
handshakes, headers/retransmissions and idle cover; this is not request-attributed
overhead. The link matcher does not support a claim of correlation immunity.

### Still open

Actual adaptive attack/transport comparison, independent real normal-reference
collection, profile optimization at matched budgets, established deep attacks,
composed installed-browser/native leak acceptance, signed delivery, independent
review and independently operated public population remain open. See
MASTER_ROADMAP.md, TRAFFIC_ANALYSIS_HARDENING.md and LINUX_RELEASE_GATES.md.
