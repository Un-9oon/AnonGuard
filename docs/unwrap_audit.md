# Panic, unwrap and expect review status

The former nine-instance inventory was historical and referenced retired code.
It is not a current exhaustive audit or a proof that every panic is unreachable.
Do not use old line numbers or counts as release assurance.

Current reviews must distinguish test-only assertions from reachable production
paths, inspect input/state/concurrency assumptions, and record the exact commit.
Strict Clippy, regression tests and fuzzing contribute evidence but do not prove
panic freedom. Dependency code and platform failures require their own review.
See [robustness evidence](../ROBUSTNESS.md), [threat model](../THREAT_MODEL.md) and
[release gates](PRODUCTION_READINESS.md). Historical notes remain in Git history
and the clearly labeled [report archive](reports/README.md).
