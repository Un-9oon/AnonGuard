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
