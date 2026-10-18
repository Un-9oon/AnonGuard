# Documentation reconciliation — 19 October 2026

## Which documents to use

Use [README](../README.md) for navigation and prerequisites,
[the v6 specification](PROTOCOL_V3.md) for the wire contract,
[architecture](architecture.md) for an overview and
[production readiness](PRODUCTION_READINESS.md) for open gates.
`PROTOCOL_V3.md` retains its old filename to preserve links; its contents specify
v6. Dated reports/checkpoints record their own commit and environment and are
not automatic acceptance of later source changes.

The source crate remains `0.2.0`. Wire version v6 and Debian package revision
`0.2.0-0lab.20261019.1` describe different things. The published 19 October lab
package contains source `e870f28`; this later documentation reconciliation does
not rewrite its immutable build information or claim a new binary build.

## Corrections made

- Removed stale v3/v5 descriptions from maintained navigation, relay, handshake
  and scheduling guides. The supported route is bounded 3–8 hops, default 3–5;
  a three-hop test fixture remains a valid baseline.
- Corrected old 1024/2048-byte descriptions to 8192-byte cells where describing
  the current protocol. Updated session budgets to 204.8/409.6 kB/s per direction
  for 40/20 ms, and separated nested session bytes from strict link envelopes
  (409.8 kB/s per direction before TLS/TCP).
- Documented existing authenticated flow credit, bounded streams, phase-preserving
  pacing and fixed-window completion. Removed incorrect claims that cell flow
  control is future work or that 32-bit counters imply a universal safe byte budget.
- Updated the root research overview: unsupported zero-bit leakage,
  negligible-overhead, threshold-signature and classifier-immunity conclusions
  are not current findings. An old nine-instance panic inventory is not a current
  exhaustive audit.
- Linked the actual unsigned lab download and clarified operator/browser/addon
  prerequisites. Signed-workflow instructions do not imply lab signatures exist.
- Marked the earlier engineering snapshot and [report archive](reports/README.md)
  as historical. Old sample TOML is neither installed nor consumed by the daemon.

## Review scope and limits

The reconciliation searched tracked Markdown and deployment/sample material,
checked local Markdown destinations, and cross-checked key protocol/rate/profile
claims against source. No tracked build targets, `.deb` archives, Python bytecode
or transient logs were found in the inspected repository file inventory. JSON
fixtures and dated audit evidence are intentional tracked inputs/evidence.

Historical reports deliberately retain obsolete prose and unvalidated hypotheses
under explicit warnings; they are not synchronized implementation contracts.
Retired test/path names and historical version strings in compatibility-rejection
tests are not automatically mistakes and have not been blindly renamed. This
editorial check is not an exhaustive security audit, proof that every sentence is
correct or a fresh production-readiness certification.
