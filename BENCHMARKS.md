# AnonGuard performance evaluation

Protocol v3 has no validated production performance baseline or measured
superiority over Tor. Earlier microsecond, circuit-latency and hundreds-of-Mbps
figures lacked reproducible measurements and have been removed. Correctness tests
do not establish network throughput.

## Measurement contract

Record the exact commit, configuration, OS/kernel, hardware, link capacity,
relay locations, operator ownership, workload and capture points. Preserve raw
measurements and commands. Report sample counts, median and tail latency,
failures and uncertainty; include failed and timed-out requests.

Measure circuit establishment separately from steady-state transfer. Include
useful application bytes, total wire bytes in both directions, idle cover traffic,
CPU/RAM consumption and connection failure behavior. Cell encryption benchmarks
measure cryptographic operations, not application throughput. Current cells are
2048 bytes; framing, onion layers and pacing impose additional limits. Read the
active scheduler configuration when calculating capacity, and label estimates
as models rather than measured results.

## Comparison with Tor

Use equivalent three-hop topology, workload, hardware and observation models.
Record padding and transport settings. Private laboratory Tor and public Tor
answer different questions; report them separately. Report padding's bandwidth
and latency costs alongside any classifier results.

Website fingerprinting and end-to-end timing correlation are separate attacks.
Split real captures by collection session/day and workload identity before model
fitting; fit normalization on training data alone. Keep variants of the same
source trace out of opposing splits. Include multiple seeds, baselines and
held-out environments. Low accuracy for one classifier does not establish
anonymity against other observers or attacks.

Scripts in `eval/` include historical synthetic emulations. Their `tor` and
`quantum` labels describe simulations, not executions of Tor or current AnonGuard.
Results cannot substantiate production, quantum-security or Tor-superiority
claims. Real-network testing is a separate gate, currently deferred by the
operator. See [production readiness](docs/PRODUCTION_READINESS.md) and
[FYP acceptance record](docs/FYP_ACCEPTANCE_RECORD.md).
