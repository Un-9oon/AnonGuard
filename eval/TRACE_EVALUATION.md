# Measured-trace evaluation contract

`evaluate_traces.py` consumes pre-collected defended traces; it neither generates
traffic nor simulates successful anonymity. JSON schema:

```json
{"version":1,"observation":"packet","traces":[
  {"id":"opaque-1","label":"owned-page-a","group":"day1-device1-network1",
   "defense":"balanced","events":[[0.0,1,2048],[0.04,-1,2048]],
   "application_bytes":1000,"latency_ms":500}
]}
```

At least two traces are required, with disjoint training/test groups and training
samples for every tested defense. `observation` is `packet`, `onion-cell` or
`synthetic`; never label simulated or cell-layer output as real packet captures.
Events are nondecreasing seconds, direction +/-1 and observed bytes. Labels/IDs
are pseudonyms: omit credentials, payloads, real browsing history and endpoints.
Groups must represent independent collection days/devices/networks. Capture
metadata leakage is sensitive; keep raw captures locally and obtain participant
consent. Client/exit captures for correlation need synchronized clocks and paired
flow identifiers, which this baseline does not evaluate.

```sh
python3 eval/evaluate_traces.py traces.json \
  --test-group day2-device2-network2 --output result.json
```

Every defense trains its own 1-nearest-neighbor classifier on defended training
samples. Feature scaling is fitted on training data only. Features include sizes,
directions, duration and interarrival summaries. Results include confusion matrix,
precision/recall/false-positive rate, unseen test labels, available wire/application
ratio, p95 measured latency, split groups and input SHA-256. Output is exclusive
and mode 0600. Duplicate IDs, non-finite measurements and malformed events refuse.

This is a reproducible baseline, not a deep-learning evaluation. Deep Fingerprinting,
more recent defense-aware attacks, open-world datasets, correlated repeated visits,
adaptive adversaries and flow correlation remain required experiments. Train/test
near-duplicate visits must be separated by the collector; unique IDs alone do not
detect duplicate content. No accuracy result for AnonGuard or Tor is supplied.
Synthetic unit-test accuracy proves only evaluator mechanics. Compare profiles
at matched latency/bandwidth budgets; report confidence intervals across independent
collection runs and tune exclusively on separate validation groups.

## Owned-capture pilot limitations and integrity controls

`capture_owned_testnet.py` records partial progress before collection and preserves
failure metadata plus available capture logs/PCAPs. Use a fresh output directory:
existing complete or partial evidence is not overwritten. Flow-observer failures,
truncated capture records and kernel capture loss refuse a sample. Failed visits
must remain in the report denominator; a successful rerun does not erase failures.

Capture accounting separates bytes before the request, during its measured lifetime,
and during the one-second post-request window. These are **whole gateway-link
bytes**, including headers, retransmissions and cover from earlier still-active
contexts. They are not request-attributed bandwidth overhead. In particular, strict
mode reuses one context per collection block, so background contexts may accumulate.
A fair per-request overhead experiment requires matched context lifetimes plus
separate idle baseline windows; subtracting a guessed baseline is not acceptable.

For a request-independent observation experiment, set
`ANONGUARD_CAPTURE_WINDOW_SECONDS=5` (bounded to 5..120 seconds) alongside
`ANONGUARD_TRAFFIC_EVAL`. Each capture continues for that duration after request
start, including idle cover after completion. A request exceeding the window
invalidates the sample instead of changing its observation duration. Keep the
same window for every compared build/profile. This avoids deliberately stopping
capture at each response's end, but does not remove observable session starts,
congestion, accumulated contexts or later session termination. It is an evaluation
control, not a new anonymity guarantee. Record failures and longer-workload exclusions.

`evaluate_owned_capture.py` adds seeded held-out-label permutation diagnostics and
majority-class/count baselines. Permutation preserves test class counts and never
changes the trained model. This is a pipeline sanity check, not an anonymity proof.
Wilson intervals assume independent visits: same-VM sequential samples and multiple
model seeds do not provide independent deployments. Hyperparameters must be fixed
before collecting a separate confirmation dataset.

The exploratory link matcher reports tied maxima and events omitted by the fixed
20-second window. It independently aligns both links to their first payload, losing
absolute timing lag. Repeated sessions and workloads invalidate interpreting its
same-VM top-1 rate as global-adversary resistance. Destination-side, multi-network,
open-world and established defense-aware attacks remain unevaluated.

## Open-world baseline with a separate validation partition

`evaluate_open_world.py` adds an explicit monitored-site/background experiment.
It uses the same observed-trace schema, plus `complete: true`. Packet traces must
include `capture_sha256`, the lowercase SHA-256 of their source PCAP. The owned
collector now records this digest; older captures must have it derived from the
preserved original PCAP, never invented from an ID. Cross-partition PCAP reuse
refuses evaluation; duplicate source PCAPs within a profile also refuse rather
than inflating the number of supposedly independent visits. Event-identical shapes are disclosed separately: fixed-size
padding can legitimately make shapes identical, so matching shapes alone do not
prove that a capture was copied. Digests identify files, not honest collection.

```sh
python3 eval/evaluate_open_world.py traces.json \
  --monitored-label owned-site-a --monitored-label owned-site-b \
  --train-group collection-day1 \
  --validation-group collection-day2 \
  --test-group collection-day3 \
  --validation-max-fpr 0.01 --output open-world-result.json
```

All groups must be explicitly assigned exactly once to disjoint train, validation
and test partitions. Each profile's training labels must equal the monitored set.
Both later partitions need every monitored label and background visits; background
site labels must differ between validation and test. Defense-aware feature scaling
is fitted on training only. The squared-distance rejection threshold maximizes
correct monitored identification subject to the empirical validation FPR limit.
Held-out data cannot influence scaling or this threshold. Equidistant different
monitored labels cause abstention. A reject-all operating point is labelled, not
reported as proof of a successful defense. The baseline refuses more than one
million pairwise distances per profile; use a separately validated scalable attack
for larger experiments rather than silently subsampling observations.

Outputs distinguish correct monitored identification, wrong monitored labels and
background false alarms. They include Wilson intervals and precision projections
at explicitly assumed monitored-visit priors (50%, 1%, 0.1%). Zero false alarms in
a small background sample still has a nonzero uncertainty bound. Projected precision
uses point estimates, not a guarantee about deployment prevalence. Output creation
is exclusive and mode 0600. Incomplete captures refuse; synthetic data requires an
explicit test-only opt-in. No measured attack result is supplied with unit tests.

This implements one open-world baseline, not Deep Fingerprinting, Robust
Fingerprinting, a global-observer evaluation, statistically independent collection,
or resistance to adaptive attackers. Group names do not establish independence.
Use separately collected devices/networks/days, larger background populations,
failed-visit accounting and a frozen confirmation dataset. Published research
motivates realistic open-world evaluation: [Cherubin et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/cherubin).

## Separate protocol-detection baseline

`evaluate_protocol_detection.py` evaluates AnonGuard-versus-reference packet-shape
classification, not visited-site inference. It uses the same trace schema with
`complete: true`, explicit `reference_population` and a per-trace `protocol_label`
of `anonguard` or `reference`. `label` remains the opaque workload label; class
names must not replace independent collection grouping. Every compared defense
needs both protocol classes in all three group partitions. Record what the normal
reference actually represents: browser/application mix, device/network, collection
period and observation window. The tool cannot establish that it represents the
Internet generally.

```sh
python3 eval/evaluate_protocol_detection.py protocol-traces.json \
  --train-group collection-day1 --validation-group collection-day2 \
  --test-group collection-day3 --validation-max-fpr 0.01 \
  --output protocol-result.json
```

Feature scaling uses training data only. The nearest-class distance-ratio score
is not a calibrated probability. Validation selects the threshold maximizing
sensitivity under the requested empirical reference FPR constraint, moving tied
scores together. An explicit reject-all point remains labelled. The held-out
report includes sensitivity/FPR/precision, balanced accuracy, Wilson intervals,
tie-aware AUROC, assumed-prevalence precision and workload overlap. Held-out AUROC
is reporting only, never a threshold-selection input. The same one-million
pairwise-distance ceiling, source-PCAP hashes, duplicate/split integrity checks,
exclusive private output and explicit synthetic opt-in apply.

This is a simple **shape-only** baseline. It does not inspect IP reputation,
TLS/ALPN/certificate metadata or active probing, and is not an established deep
protocol detector. A low shape score does not hide a public relay address or a
visible custom ALPN. No real AnonGuard detection result is supplied by synthetic
regression tests. The three-workload owned collector still needs a separately
collected, honestly labelled reference population before this experiment exists.

For paired link-window matching, the evaluator now uses a declared fixed capture
window instead of extending a shorter observation to 20 seconds of artificial zeros.
Legacy variable-duration input retains a disclosed 20-second cap. Supplied source
PCAP hashes are checked before extracting exit-link events, and omitted events are
counted for both sides. Each side is still independently aligned to its first
payload: clock lag is discarded and this remains an exploratory same-VM baseline,
not a destination-side/global-observer experiment. Choose the observation contract
before confirmation collection; this integrity correction does not establish
traffic-analysis resistance.

The opt-in Rust testnet fixture accepts `ANONGUARD_TEST_SOURCE_ROOT` for locating
the exact collector/browser fixture sources when running prebuilt test executables
on a separate test VM. Omit it to retain the compile-time repository root. Record
the executed source/binary hashes; this variable is for trusted lab fixtures, not
a production service configuration or authority bootstrap mechanism.

## Bounded timestamp ordering and preserved raw evidence

Kernel/capture timestamp order can differ from packet-file order by a small
amount. The owned collector now applies a documented stable chronological order
only when backward displacement from the running maximum is at most 2 microseconds.
It records count/largest backstep; larger jumps, cumulative drift beyond the bound
and nonfinite timestamps refuse. Packet-file order and original PCAP bytes remain
unchanged. Timestamp ordering is not clock synchronization or TCP reassembly.
The collector validates the final dataset against the shared schema before marking
its complete output ready for evaluation.

For an already retained raw dataset, use an explicit derivative instead of editing
it or weakening the schema validator:

```sh
python3 eval/event_order.py raw-traces.json --output timestamp-ordered.json
```

The tool records the raw dataset SHA256, changed traces, tolerance and policy;
validates the entire derived schema before publishing; and creates exclusive 0600
output. Source-PCAP hashes remain attached but this timestamp-only tool does not
independently verify the files. Link analysis verifies provided source-PCAP hashes
and includes exit timestamp-order metadata. Preserve the original failed analysis
and raw dataset as part of the evidence trail. This bounded mechanical repair
must not be represented as an anonymity improvement or used to hide clock jumps.


## Defense-aware RF/SVM baselines

Install NumPy and scikit-learn in the evaluation environment (Ubuntu CI uses
`python3-sklearn`). Run `python3 eval/test_adaptive.py` for validation checks.
Example, with all groups assigned exactly once:

```sh
python3 eval/evaluate_adaptive.py captured.json --task website \
  --train-group block-0 --validation-group block-1 --test-group block-2 \
  --feature-window 5 --output adaptive.json
```

`website` is closed-world activity classification; it also accepts owned size
workload labels, which must not be described as actual websites. `protocol`
requires the protocol-label dataset contract and uses validation-only threshold
calibration. Both tasks reject overlapping groups, duplicate source-PCAP hashes
and incomplete inventories. Features include aggregate/sequence, signed bursts
and a fixed common time window. Models/hyperparameters are fixed; held-out data
is not used for tuning. RF seeds are sensitivity checks, not independent samples.
These custom baselines exclude TLS metadata and active probing and do not replace
established adaptive deep attacks. Tiny datasets cannot establish undetectability
or operational low-FPR performance. See the cover-budget checkpoint for results.
