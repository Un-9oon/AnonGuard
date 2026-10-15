# Owned Linux VM validation — 15 October 2026

This is a controlled functional and exploratory traffic-analysis checkpoint, not a public-production anonymity certification. It does not establish superiority to Tor or resistance to arbitrary AI classifiers.

## Environment and boundaries

- User-authorized Ubuntu VM, two virtual CPUs, retained AnonGuard v6 optimized daemon and runtime tests from the `3113c4a` implementation. Published source tree at the beginning of this run: `b0e6074` (tree `56c4c26aa42f21acc41a4a05c86e7c7f4441f7a4`). Subsequent changes in this checkpoint concern fixture permissions and documentation, not the production daemon.
- CLI fixture: four pinned authorities, three relay roles and a client gateway. The private-bridge variant also provisions an unlisted entry and spare relay. These are local processes on one VM, not independent operators or a geographically diverse anonymity population.
- Fixture authorities use deliberately cheap admission and relays allow private test destinations with explicit insecure-lab flags. These settings must not be copied into a public deployment.
- Reverse tracker tests exercise volunteer registration, ownership authentication and pairing/forwarding. No people were recruited and no public volunteer infrastructure was deployed.
- Public traffic was bounded HTTPS GETs to `example.com` and `www.wikipedia.org`, with no account logins. Python/OpenSSL certificate verification remained enabled. Firefox used a fresh automation profile and a temporary development add-on.
- Raw captures and detailed logs remain private evidence outside Git. Test namespaces do not replace the host firewall. Global AppArmor restrictions were not disabled. The VM was provisioned with browser/evaluation tools and obfs4proxy; the Selenium package also pulled distribution-recommended browser dependencies.
- This was a shared VM with package provisioning during the early run. Timing figures are exploratory; they are not a dedicated performance benchmark.

## Functional checks

| Check | Outcome |
| --- | --- |
| Tracker authentication/resource admission | 8 tests passed |
| Reverse volunteer registration/pairing | 2 tests passed |
| Ordinary CLI network, transfer and relay-loss closure | 2 tests passed in a separate capture-free run |
| Private obfs4 bridge variant | 2 tests passed; this is transport functionality, not censorship or indistinguishability proof |
| Native namespace firewall/adapter | Passed: transparent TCP, fail-closed DNS, UDP/IPv6 refusal, backend-crash stream closure; backend is a SOCKS fixture |
| Application containment | Initial fixture permission failure; corrected fixture passed under `umask 077`, covering private filesystem, inherited descriptors, UID/caps, syscall policy, proxy flow and helper death |
| Actual Firefox through the real CLI testnet | Firefox 157.0.1 loaded owned page, iframe and script; root-origin credentials shared correctly and distinct origins separated; relay-loss closure passed |
| CPU-pinned capture rerun | Both CLI tests passed; 36 strict + 36 unpadded visits completed, 72/72 source-PCAP hashes independently verified |
| Focused VM security/core tests | 112 core unit tests, 7 handshake-boundary tests, 3 directory-admission tests, 1 multi-authority-pinning test and 2 zeroization tests passed (125 total) |
| Local launcher/seccomp contracts | 5 tests passed with normal socket permissions; the initial restricted-tool sandbox attempt blocked otherwise permitted sockets |

### Containment fixture correction

The evidence runner intentionally uses `umask 077`. The fixture previously inherited that mask for its `/app` directory and statically compiled probe. The unprivileged probe UID consequently could not traverse/execute them (`bwrap: execvp /app/probe: Permission denied`). The fixture now explicitly grants those two test artifacts mode `0755`; private host sentinel files and broker resources stay private. The corrected privileged fixture passed with the original restrictive umask and without relaxing kernel policy.

### Capture refusal retained

The first strict-profile collection completed 28 visits before rejecting a later PCAP whose selected timestamps exceeded the declared two-microsecond ordering tolerance. Examination of the unmodified failed PCAP found an approximately four-microsecond backward timestamp step. The incomplete strict inventory was not passed off as a complete accuracy experiment. The unpadded half completed. A separate CPU-pinned rerun completed all 72 visits and both CLI tests under the unchanged ordering policy. All 72 source hashes were independently verified. This is a distinct experiment, not a repair of the original raw evidence; it does not fix or guarantee timestamp ordering on arbitrary capture systems.

## Public HTTPS packet pilot

All **24** Python HTTPS visits completed with `200 OK`: 12 through AnonGuard and 12 direct. Every source-PCAP hash was independently rechecked against the dataset: **24/24 matched**.

The two routes used the same Python TLS stack, request form and sites, interleaved in three collection blocks. AnonGuard features observe its gateway-to-guard link on loopback; direct features observe the selected outgoing HTTPS connection on the VM interface. Each capture uses a ten-second observation period, with events extracted only for selected flows. Interface, persistent covered-context state, same-VM dependence and the two-site population remain confounds. This is not representative ordinary browser traffic.

### Protocol identification

Eight visits trained the shape-distance detector, eight calibrated its threshold, and eight were held out (four AnonGuard, four direct). Threshold selection used validation data only, at a nominal empirical validation false-positive budget of 1%.

- At that frozen threshold, held-out sensitivity was **1/4 (25%)**, with **0/4** direct false positives; balanced accuracy **62.5%**.
- Held-out ranking AUROC was **1.0** on those eight observations. Ranking separation and one calibrated operating point measure different things; a weak frozen threshold is not evidence that the classes are indistinguishable.
- The 95% Wilson interval for sensitivity is approximately **4.6–69.9%**; for false positives it is **0–49.0%**. Four negatives cannot establish a real 1% false-positive guarantee. Dependence between visits adds uncertainty beyond these intervals.
- A small 32-unit MLP, with fixed hyperparameters and seeds 11/29/47, also detected 1/4 positives at its validation-calibrated thresholds. Its held-out AUROCs were 0.50/0.25/0.25. This is a tiny generalization/calibration diagnostic, not an established adaptive deep detector evaluation. Seeds are not independent populations.

The protocol is therefore **not established as AI-undetectable**.

### Activity inference

A separate two-site nearest-neighbor pilot used only the AnonGuard visits: eight training visits and four held out. It identified **3/4 (75%)** held-out site labels; balanced two-site chance is 50%. The sample is far too small for a broad website-fingerprinting claim, but it does not support treating activity leakage as solved.

### Direct passive protocol marker

TShark decoded TLS ClientHello messages from 24 previously retained held-out PCAPs. `anonguard/6` ALPN was visible in 13 files (one strict file and all twelve unpadded files). These files may contain multiple relay links. A capture without a ClientHello is not a negative classification of the protocol.

This proves a direct TLS protocol marker is observable where that ClientHello is captured; AI is unnecessary for that identification. It does **not** imply the same marker is visible inside a correctly applied obfs4 wrapper. Removing authenticated ALPN checks is not an appropriate shortcut: transport concealment needs separate client-to-bridge capture and adversarial evaluation.

### Browser observations

The first actual Firefox run loaded Wikipedia with expected document content. Example.com had the expected title and HTTPS document URI but failed the fixture's visible-text success predicate, so that first flag was retained as inconclusive. The diagnostic rerun retained DOM text and a screenshot; both public pages then met the document-URI/content checks and the full browser/relay-loss test passed. Example.com's current page uses changed visible content, which made the original exact visible-text predicate unsuitable. The original false flag remains in the first log. Temporary add-on installation is not normal signed browser distribution or fingerprinting certification.

## Fresh owned-workload shaping rerun

This separate CPU-pinned experiment used the existing three owned byte-size workloads, 36 visits per profile and the final 12 visits per profile held out. It does not measure public browsing or compare against Tor.

| Metric | Strict | Unpadded |
| --- | --- | --- |
| Nearest-neighbor workload accuracy | 5/12 (41.7%) | 7/12 (58.3%) |
| Small MLP accuracy, seeds 11/29/47 | 25.0%, 25.0%, 41.7% | 58.3%, 66.7%, 83.3% |
| Held-out p95 completion | 1,767 ms | 855 ms |
| Held-out captured gateway-link bytes | 70,822,827 | 6,397,044 |
| Exploratory same-VM client/guard versus last-relay/exit window matching | 1/12 | 2/12 |

Three-class chance is 33.3%; the nearest-neighbor uncertainty intervals are wide and overlap. The link matcher has 12 candidate windows (random top-1 chance 1/12), independently aligns the first payload on each link and discards absolute lag. Its result does not measure a destination-side/global observer or show correlation resistance.

Strict mode cost approximately **11.1× captured link bytes** and **2.1× p95 completion time** in this rerun. Captured bytes include headers, retransmissions, other live contexts and idle cover; they are **not request-attributed overhead**. The pinned single-CPU condition is a measurement constraint, not a production tuning recommendation. These data show a cost/defense tradeoff needing further work, not a completed anonymity solution.

## Remaining acceptance gates

- Independent client/entry/exit networks and destination-side observations; client and exit on one VM cannot demonstrate distinct public IPs or operator independence.
- Representative normal browsing population, adequate sample size, genuinely independent splits, multi-tab/unseen-site/device/network evaluation, established adaptive attacks and traffic-correlation experiments.
- Composed installed-system boot/restart/network-change leak tests with real relays, beyond namespace fixtures.
- Sustained overload/distributed-source fairness, sustained fuzzing, independent cryptographic/protocol review, signed browser/release distribution and complete secure-update/key-recovery acceptance.
- Private onion-service equivalents remain outside the implemented feature set.

Functional successes here do not close these gates. Public anonymity and universal traffic-analysis resistance remain unestablished.
