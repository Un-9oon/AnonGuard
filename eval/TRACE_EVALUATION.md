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
