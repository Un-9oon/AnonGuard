# AnonGuard Ubuntu VM validation — 2026-10-10

## Verdict
Functional integration and Linux containment/package regressions passed. AnonGuard is **not established as production-ready or AI-resistant** by this session. Real captured traffic remains classifiable in this small controlled pilot. This is a laboratory VM on a real Ubuntu kernel, not a geographically distributed anonymity deployment or an independent cryptographic audit.

## Environment and scope
Ubuntu 24.04.3 LTS live session, approximately 3.8 GiB RAM, no swap, 2 GiB writable overlay. The guest kernel ran the daemons and firewall tests. Firefox ESR 140.17.0 and temporary development addon were used. SSH host identity was confirmed by the operator before access. Source baseline: `4a7b1172611aa187ffdb5ccc71a0e0f3c38e2b0d`; opt-in capture fixtures were added during the session. Stripped Rust binaries and a static C probe were built on the controller and executed on Ubuntu; this was not an Ubuntu source-build verification.

Four pinned authorities, three relays and a gateway ran as genuine processes. Private exit permission and PoW zero were explicit fixture settings only; they are not production settings. No public relays, third-party users, Tor baseline or uncontrolled browsing dataset was monitored. All packet captures concern owned loopback fixture links, with TCP source-port attribution from the gateway PID. Snap/package and browser setup activity occurred during an early run; a later 72-trace run was completed without concurrent browser/package setup.

## Checks and outcomes
- Padded and unpadded real CLI bootstrap, 128 KiB transfer and relay-loss connection closure: passed.
- Four malformed/invalid-pin/zero-DH handshake boundary tests: passed. These exercise the existing hybrid protocol; they do not independently validate its mathematical security or establish full quantum-safe authentication.
- Eight SOCKS boundary tests, three guarded-I/O/kill-switch tests, and ten existing external-network validation tests: passed.
- Eight browser launcher/generator and eleven native-helper tests: passed.
- Actual Firefox policy loading and preference locks, ordinary and isolated profiles: both passed.
- Actual Firefox addon nested resources, origin/tab separation and missing-addon/proxy-loss refusal: passed.
- Firefox through the real padded relay chain, followed by the existing transfer/crash regression: passed (approximately 70 seconds on this VM).
- Real native adapter and generated nftables rules in a private namespace, with tcpdump: transparent TCP passed; failed DoT returned DNS SERVFAIL; direct UDP/IPv6 denied; backend loss closed streams; firewall table survived service deaths. Backend for this component test was a controlled SOCKS fixture, separate from the real relay test.
- Application containment using the existing static probe: private filesystem/descriptors, UID/caps, syscall restrictions, proxy flow and helper-death checks passed after the documented executable-specific AppArmor prerequisite was temporarily loaded. The profile was then unloaded. The unconfigured Ubuntu setup correctly refused execution.
- Debian package install, reinstall, preserved configuration, removal, recovery and purge: passed. The test package was purged afterward; this is not an installed production client.

## Captured traffic / classifier pilot
Three owned HTTP response workloads: 8, 32 and 64 KiB, emitted in 4 KiB chunks with a 15 ms server interval. Responses were carried through actual onion circuits. The observer sees client-to-guard TCP payload frames, not plaintext HTTP, local SOCKS frames or synthetic onion-cell logs. TCP segmentation, retransmissions and header bytes are included; payload-only frames exclude ACK-only frames. Capture window spans connection/request completion plus one second, not the complete lifetime of all continuing cover sessions. Cached padded sessions from earlier requests can contribute cover traffic within those observer windows.

Each profile has 36 traces: 24 from collection blocks 0/1 for training, 12 from block 2 held out. Labels were balanced; chance is 33.3%. Collection order was shuffled with a recorded deterministic seed. Feature scaling uses training samples only. Held-out blocks are sequential within the same VM/session, not independent days/devices/networks. Neural seeds reuse the same 12 test traces and do not enlarge the test sample.

| Measurement | Unpadded | Strict padded |
|---|---:|---:|
| 1-nearest-neighbor accuracy | 100% (12/12) | 66.7% (8/12) |
| Small MLP accuracy, seed 11 | 100% | 50% |
| Small MLP accuracy, seed 29 | 100% | 75% |
| Small MLP accuracy, seed 47 | 100% | 83.3% |
| Held-out p95 SOCKS + request completion | 6.56 s | 16.84 s |
| Observed payload-frame wire bytes / response bytes | 4.36 | 25.32 |

The wire ratio is **not** total network bandwidth overhead or a direct policy-cost estimate: it includes both directions, protocol/handshake traffic, TCP header/segmentation effects and continuing cover in the specified windows; it excludes ACK-only traffic and later tails. Timing is noisy on a memory-constrained live guest. Do not use these values as a production performance benchmark.

Exploratory 1-NN feature ablations on the same test block: strict duration-only 75%; counts/bytes 83.3%; early 64-event sequence 25%. These indicate remaining observable information in duration/volume in this pilot, not a proven sole cause or independently validated attack. Adding more random jitter cannot be assumed to remove it.

The earlier strict dataset gave 75% 1-NN and 25–41.7% MLP, illustrating sensitivity to a tiny dataset/conditions. An initial unpadded collector incorrectly requested session-context SOCKS auth rather than its supported NOAUTH; the fixture was corrected. A subsequent unpadded run timed out on a read during concurrent setup/browser activity. The failed logs were preserved, no failure was silently replaced by a successful fabricated trace, and both modes later completed an uncontended rerun. Causation of that timeout has not been isolated.

### Exploratory link correlation
A separate post-collection Pearson baseline matches client-to-guard versus last-relay-to-exit-link windows in the same PCAPs: 50 ms bins, first 20 seconds, maximum alignment shift 500 ms. Among 12 held-out windows per profile, correct top-one matches were unpadded 3/12 (25%) and strict 6/12 (50%); random candidate selection is 1/12 (8.3%). Repeated workloads, multiple continuing sessions and limited attribution make this an exploratory window-matching diagnostic. It is **not destination-side end-to-end correlation validation**, and the worse strict result prevents claiming universally improved traffic-analysis protection. No external attack implementation or independent multi-network evaluation was performed.

## Limitations / release gates
- No established Deep Fingerprinting model, open-world website dataset, protocol-detection classifier or equivalent Tor experiment.
- No geographically independent network, operator diversity or public-IP-hiding proof across different egress addresses.
- No independent crypto audit, exhaustive fuzzing, malicious-relay campaign or compromised-host proof.
- No signed-addon distribution, operator-installed combined browser/native acceptance or standardized cross-device fingerprint evaluation.
- No root/boot/reboot-wide kill-switch acceptance: the live session was not rebooted, and the main SSH connection was deliberately preserved.

## Next engineering priorities from the evidence
1. Treat duration/volume leakage and high observed cover cost as unresolved findings; investigate them with larger, stable runs before tuning the policy.
2. Add established adaptive attack implementations, held-out days/devices and open-world samples; retain success/failure denominators and confidence intervals.
3. Separately evaluate destination-side correlation and protocol detectability. Website/workload classification, network detection and flow linking are different tasks.
4. Validate the actual installed signed browser + gateway + native firewall composition before releasing to users.

## Reproduce
Run the existing Rust testnet with `ANONGUARD_TRAFFIC_EVAL=/absolute/owned/output`, using `--test-threads=1 --nocapture`. Requires trusted tcpdump, ss, Python, and noninteractive sudo in a designated owned test environment. The capture helper creates only owned loopback HTTP servers and captures fixture relay ports. Lab-only subprocesses receive private-exit/PoW settings from the existing test fixture. Partial JSON remains explicitly incomplete after failure.

Merge strict.json and unpadded.json traces into a schema-v1 packet dataset, then run:

```sh
python3 eval/evaluate_owned_capture.py DATASET.json --output NEW_REPORT.json
python3 eval/evaluate_link_correlation.py DATASET.json PCAP_DIRECTORY --output NEW_LINK_REPORT.json
```

Classifier evaluation requires NumPy. This pilot uses the repository's small MLP, not an established deep-fingerprinting attack. Raw captures, dataset hashes, JSON results and original success/failure logs were preserved outside Git in the controller workspace. No private keys were placed in the repository.
