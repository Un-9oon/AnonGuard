# Deployment acceptance record

Copy this template into the private evaluation folder. Fill observations after
running each case; an empty entry is not a pass. Follow [delivery procedures](FYP_DELIVERY.md).

- Source commit:
- Build toolchain and package SHA-256:
- Artifact signature status and verification evidence:
- Test date/time and timezone:
- Operator and independent reproducer:
- Host inventory, distribution and kernel versions:
- Topology and actual failure domains:
- Explicit lab exceptions:
- Tested application, immutable rootfs provenance and configuration:
- Gateway and application cgroup limits:

| Case | Procedure/evidence file | Expected | Observed | PASS / FAIL / NOT RUN |
|---|---|---|---|---|
| Clean installation | | | | NOT RUN |
| Fresh quorum and authenticated startup | | | | NOT RUN |
| Complete three-hop transfer | | | | NOT RUN |
| Upload half-close and response | | | | NOT RUN |
| Incorrect authority/relay identity | | | | NOT RUN |
| Insufficient/expired directory | | | | NOT RUN |
| Relay loss with no direct fallback | | | | NOT RUN |
| Restart preserves state | | | | NOT RUN |
| Quorum retirement and policy rollback refusal | | | | NOT RUN |
| Retired relay/bridge and local identity refused | | | | NOT RUN |
| Authority replacement preserves quorum and old-journal refusal | | | | NOT RUN |
| Direct IPv4/IPv6 blocked | | | | NOT RUN |
| Direct DNS/UDP blocked | | | | NOT RUN |
| Host IPC and inherited descriptors contained | | | | NOT RUN |
| Helper crash containment | | | | NOT RUN |
| Two-VM adapter topology and no direct application route | | | | NOT RUN |
| Two-VM SOCKS flow, DNS/UDP/IPv6 and other-port refusal | | | | NOT RUN |
| Two-VM daemon/proxy/firewall failure and reboot containment | | | | NOT RUN |
| Package upgrade and recovery | | | | NOT RUN |
| Resource limits and overload recovery | | | | NOT RUN |
| Independent clean-machine reproduction | | | | NOT RUN |

## Performance evidence

Use the same synthetic owned workload, concurrency and run duration. Identify
warm-up, sample count, failed requests and percentile calculation. Do not omit
failed trials or treat transport measurements as an anonymity proof.

| Configuration | Trials / failures | Latency p50 / p95 / p99 | Useful throughput | Total bytes | Peak CPU / RSS |
|---|---|---|---|---|---|
| Direct baseline | | | | | |
| AnonGuard | | | | | |
| Optional comparable Tor baseline | | | | | |

## Handoff decision

- Unresolved failures and their impact:
- Supported tested configuration:
- Unsupported configurations:
- Reproduction instructions and presentation fallback:
- Independent reviewer/reproducer observations:
- Acceptance decision, date and responsible person:

The initial status is NOT ACCEPTED. Change it only after reviewing the recorded
results. Lab acceptance is separate from the public-release gates in
[production readiness](PRODUCTION_READINESS.md).
