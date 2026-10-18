# AnonGuard: engineering research overview

## Abstract

AnonGuard is an independent Rust implementation in the onion-routing family. It
combines authenticated variable-length paths, hybrid post-quantum key exchange
and authentication, bounded cover scheduling, Linux containment tooling and a
managed Firefox ESR workflow. These are implemented mechanisms whose anonymity
benefits require empirical and independent assessment. Tor superiority, zero
leakage, AI immunity and complete quantum protection have not been established.

## Problem and contribution

Encrypted low-latency routing still exposes timing, volume and endpoint/browser
metadata. This project explores the engineering trade-offs of explicit cover
profiles, bounded stream multiplexing, composite relay identities and device
integration. The aim is a reproducible research platform and practical lab
artifact, not an assertion that onion routing's known attacks are solved.

## Implemented scope

- Protocol v6: 3–8-hop paths (CLI default 3–5), 8192-byte cells, mandatory pinned
  TLS, hybrid X25519/ML-KEM-768 exchange and Ed25519 + ML-DSA-65 identity proofs.
- Directory acceptance requires distinct signatures over the same snapshot from
  a quorum greater than two thirds of configured authorities. These are composite
  signatures collected into a quorum, not a threshold-signature scheme or proof
  of complete Byzantine consensus liveness.
- Proof of work and prefix diversity constrain admission/path choice but do not
  establish independent ownership, ASN diversity or Sybil immunity.
- Hop-local cover and optional padded sessions provide bounded timing/volume
  shaping. RMT, Poisson and Lorenz options are classical research samplers;
  simulation results do not establish real-traffic classifier resistance.
- Linux setup, restricted headless containment and managed browser controls have
  explicit prerequisites and separate installed-system acceptance gates.

## Evidence and limitations

Dated checkpoints record exact tests and configurations. Unit tests verify the
behaviors they exercise; simulation accuracy and mutual-information estimates
are not proofs of real-world anonymity. Adaptive attacks trained on defended
traffic, held-out networks/devices, fair bandwidth/latency comparisons, signed
browser delivery and independent cryptographic review remain necessary.

The earlier draft's zero-bit-leakage, negligible-overhead and guaranteed
classifier-immunity claims are withdrawn as current results. Earlier prose is
recoverable in Git history and historical reports; it is not a validated paper.

Use [the maintained protocol](docs/PROTOCOL_V3.md),
[architecture](docs/architecture.md), [threat model](THREAT_MODEL.md),
[measurement contract](BENCHMARKS.md) and [readiness gates](docs/PRODUCTION_READINESS.md)
for technical and FYP claims. A publication-quality literature review and novel
comparative research result must be supported by cited studies and reproducible
experiments; this overview does not claim to supply either.
