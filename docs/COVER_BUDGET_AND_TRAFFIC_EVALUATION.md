# Cover budget and traffic evaluation — 16 October 2026

Status: experimental Linux implementation; public production anonymity and AI
undetectability are NOT established. No Tor superiority claim is supported.

## Delivered controls

- Default 20-ms covered links remain unchanged. Opt-in `--link-cover-profile
  economy` authenticates a separate exact ALPN and schedules at 40 ms. Mismatches
  fail; there is no fallback. All hops require coordinated configuration.
- `--privacy-profile balanced-longtail` uses 60-second closure buckets and a
  20-second minimum idle tail (balanced: 30/10), retaining 64-cell boundaries and
  the hard session lifetime. It costs additional idle bandwidth and does not
  hide arbitrary session duration. Older peers refuse it.
- Same-stream packing consumes already queued byte chunks within the existing
  cell slot. Work, queues and overflow storage are bounded. Streams and browser
  contexts remain separate; no additional timer or emission slot is introduced.
- Defense-aware random-forest and RBF-SVM baselines use disjoint collection
  groups and train-only scaling. Protocol thresholds use validation data only;
  Wilson bounds explicitly prevent tiny data from establishing low FPR.
  These are custom baselines, not published DF/Tik-Tok attack replications.

## Final-code owned-VM measurements

Ubuntu VM, all nodes under one operator, three owned byte-size workloads, three
sequential blocks per arm, 36 visits per arm, five-second packet windows. Inner
session profile balanced; outer link interval is the controlled difference.
PCAP hashes verified independently: 72/72. Group 2 held out, 12 visits/arm.
Packet counters include headers, retransmission, idle cover and other live
contexts on the selected link: they are NOT request-exclusive overhead.

| Held-out measure | 20 ms | 40 ms |
| --- | ---: | ---: |
| Captured link bytes | 68,677,271 | 37,479,743 |
| p95 request latency | 1,737 ms | 2,094 ms |
| 1-NN workload classification | 5/12 | 3/12 |
| Small MLP, seeds 11/29/47 | 2/3/6 correct of 12 | 5/5/4 correct of 12 |
| Random forest, seeds 11/29/47 | 3/3/2 correct of 12 | 2/1/1 correct of 12 |
| RBF-SVM | 6/12 | 4/12 |

Thus this pilot shows 45.43% fewer captured bytes and 20.56% higher p95 latency.
Attack outcomes are mixed, confidence intervals wide, with only three size
classes (chance 1/3). No default change or general anonymity conclusion follows.
RF/SVM train on block 0 with validation block 1; 1-NN/MLP train on blocks 0+1,
so raw scores do not establish relative attack strength. Collection order and
single-VM topology are confounders. No matched Tor benchmark was run.

Final VM functional tests: 2/2; private obfs4 bootstrap/transfer tests: 2/2.
Final actual Firefox test: owned root/iframe/script and origin-context separation
passed; Example Domain loaded in 2.929 s and Wikipedia in 3.873 s. Navigation
checks inspected document URI and body. This is two bounded visits, not a
browser-fingerprinting, installed containment or reliability evaluation.

## Earlier checkpoints retained separately

Before packing, the same cover comparison showed 47.14% fewer link bytes and
17.61% higher p95 latency. Those figures do not describe the final binary.
An earlier Firefox Wikipedia visit timed out at 20 seconds; its log is retained.
The final retry succeeded, but a single retry cannot prove packing was the sole
cause or establish a navigation success rate.

Pre-packing real lifetime checks, one 8-KiB fetch each with economy links:
balanced closed after 35.90 s / 14,019,455 captured bytes; longtail after
64.53 s / 25,716,463 bytes. Both PCAP ordering checks passed. These mechanism
checks predate packing; final-code timer/closure tests pass in the Rust suite.
Longer tails cost bandwidth: their cost cannot be combined with fixed-window
savings to claim overall total traffic is halved.

The first parallel full-suite run encountered the existing 40-second multihop
deadline while release compilation competed for CPU. The unchanged isolated
case and later complete suite passed. Adding profile ID 5 also required updating
the former unknown-profile test to ID 6; explicit downgrade refusal remains.
Neither initial failure has been represented as a passing first run.

## Validation and reproducibility

Final local validation: 287 Rust tests passed, all-target/all-feature Clippy
with warnings denied passed, 33 Python evaluation tests passed, optimized binary
build passed. Socket tests ran with explicit sandbox permission. Benchmark smoke
runs completed; these are not performance comparisons.

Private evidence root (not published to Git):
`vm-evidence/2026-10-15/cover-economy/packed-final/` contains original inventories,
merged provenance, owned analysis and adaptive reports. Final source PCAPs and
browser logs remain under the VM validation directories. The merged inventory
preserves source trace IDs and hashes; only defense arm labels/IDs are prefixed.
Source merged SHA256:
`2d48c2f64ce9904ca9485ae3550c0dc1e80e3d7696648fba4d3db7547cd9a44e`.

## Remaining acceptance gates

Duration/start-stop correlation, both-end observers, multi-tab and adaptive deep
attacks, unseen sites/devices/networks and realistic congestion remain open.
Direct ALPN identification remains observable without protected transport.
Independent cryptographic review, signed browser/release/update delivery,
installed Linux restart/leak checks, sustained fuzz/load testing and independent
operators/users are still required. Code does not manufacture an anonymity set.

Research context: [FRONT/GLUE](https://www.usenix.org/conference/usenixsecurity20/presentation/gong)
and [RegulaTor](https://petsymposium.org/popets/2022/popets-2022-0049.php)
motivate measured privacy/bandwidth/latency tradeoffs. Neither defense is claimed
as implemented or evaluated by name here; their published results are not
AnonGuard results.
