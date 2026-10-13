# Linux v6 regression validation — 2026-10-13

This follow-up starts from `21f2f6d` and records the accompanying fixes. It is
engineering acceptance for the listed laboratory paths, not public-anonymity
certification or an independent cryptographic audit.

## Fixed behavior

An ordinary TCP readiness probe previously aborted a real relay with a Tokio
worker stack overflow before TLS authentication. A debugger traced the failure
through the nested connection/relay poll frames into certificate identity-key
cloning. Boxing the inner relay future reduces the enclosing async frame's
stack pressure without increasing worker-stack limits or disabling checks.
The existing real CLI testnet exercises this readiness probe and then requires
successful authenticated circuits, 128-KiB application transfer and closure
after relay loss.

The strict EXTEND decoder also refused legitimate gateway frames because the
gateway's mandatory 32-byte next-hop identity pin was passed as extra bytes to
the canonical body decoder. The gateway now separates that pin before decoding;
exact body and complete frame lengths remain enforced. Randomized-depth and
maximum-depth circuit tests passed in the full suite.

New live TLS regressions reject classical-only key exchange, old ALPN, either
corrupted signature component, wrong challenge binding and proof replay across
distinct exporter channels. They include a valid-channel control. The real
obfs4 interoperability test now exchanges a complete 8192-byte v6 cell and
flushes/gracefully shuts down the response; an obsolete 18-byte stream probe
could not progress through the complete-cell cover layer.

## Verification

Host: Linux x86-64; Rust/Cargo 1.95.0. Cargo.lock was unchanged. Missing caches
were restored from checksum-verified locked crates; no vendored dependencies or
machine-specific Cargo configuration were added to the repository.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check`, `git diff --check` | Pass |
| `cargo clippy --locked --all-targets -- -D warnings` | Pass |
| `cargo test --locked --all-targets --no-fail-fast` | 57 target summaries, 267 passed, 0 failed, 2 ignored |
| `cargo build --release --locked` | Pass |
| Daemon testnet using the optimized release binary | 2/2 passed |
| Real obfs4 pinned v6 TLS/cell interoperability | 1/1 passed |
| Full private-bridge CLI testnet through real obfs4 | 2/2 passed |
| Native-device setup contracts | 13/13 passed |
| Restricted application launcher contracts | 5/5 passed |
| Browser-session contracts | 13/13 passed |
| Browser-extension packaging contracts | 2/2 passed |
| HTTP latency/failed-proxy contracts | 2/2 passed |
| Signed-release admission contracts | 8/8 passed |
| Offline VM-profile contracts | 7/7 passed |
| Trace-evaluation contracts | 3/3 passed |
| JavaScript browser isolation tests | 6/6 passed |

The two ignored Rust tests are the privileged namespace acceptance and optional
real-obfs4 test. The latter was separately executed as listed above. Browser
unit contracts do not mean installed signed-addon acceptance. The ML-DSA external
vector test in the full suite exercises 210 Wycheproof vectors; the Rust test
summary counts this as one test, not 210 separate tests.

To repeat optimized deployment verification:

```sh
cargo build --release --locked
ANONGUARD_TEST_DAEMON="$PWD/target/release/anonguard-daemon" \
  cargo test --locked --test test_daemon_testnet -- --test-threads=1
ANONGUARD_OBFS4PROXY=/absolute/path/to/obfs4proxy \
  cargo test --locked --test test_pluggable_transport -- --ignored
ANONGUARD_OBFS4PROXY=/absolute/path/to/obfs4proxy \
  ANONGUARD_TEST_PRIVATE_BRIDGES=1 \
  cargo test --locked --test test_daemon_testnet -- --test-threads=1
```

CI now includes the optimized daemon check. These are local results; a subsequent
GitHub Actions run must be inspected separately before claiming green remote CI.

## Dependency advisory evidence

The complete RustSec snapshot at revision
`6aed84668c23d7f535077a9fe918bf1fa0f6a5bc` was downloaded after initial
network failures. Every extracted file matched its upstream Git blob SHA-1
in the complete, non-truncated 2296-entry recursive tree. Cargo-audit 0.22.2
loaded all 1310 advisories and scanned 309 lockfile packages with no ignored
advisories and `--deny warnings`: zero vulnerabilities and zero warnings.

[Full snapshot provenance](evidence/2026-10-13/rustsec-full-snapshot.json) records
the revision, archive hash and verification count;
[the audit JSON](evidence/2026-10-13/cargo-audit.json) records the full result.
Its Git metadata fields are null because the archive is not a Git checkout.
The earlier 96-advisory relevant-package check and hash manifest are retained
as separate evidence. This is a snapshot check of published dependency
advisories, not evidence that custom protocol composition is secure.

## Outstanding acceptance

The previously supplied VM address `192.168.122.128` returned no route to host.
No fresh privileged VM leak/crash, installed signed-browser, packet-capture
classifier/correlation or multi-region acceptance was performed here. Earlier
v5 captures do not validate v6. Cover traffic still has a calculated cost of
409.8 kB/s per direction per active link before TLS/TCP overhead; stronger
anonymity, efficiency or Tor superiority is not established by passing tests.

Independent protocol review, sustained fuzzing and the remaining deployment
gates in [production readiness](PRODUCTION_READINESS.md) remain release blockers.
