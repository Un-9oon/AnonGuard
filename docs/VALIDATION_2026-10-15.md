# Tracker, fuzz and distribution verification — 2026-10-15

This record accompanies the working-tree changes based on `5e10f7865c20`.
It records Linux engineering verification, not production-anonymity approval,
Tor superiority, independent cryptographic review or complete quantum protection.

## Corrected behavior

The optional reverse tracker previously accepted bearer capabilities on plaintext
TCP and retained disconnected queued sockets together with their connection
permits. The revised shared boundary requires pinned hybrid TLS and a separate
`anonguard-tracker/1` ALPN, with the existing exporter-bound dual Ed25519/ML-DSA-65
proof. Legacy plaintext is rejected. Controls are bounded length-prefixed UTF-8;
no buffered application data is discarded at handoff.

Waiting registrations monitor closure and early data, expire after 60 seconds,
and release their slot and permit. At most three wait per node and 128 globally
within a 512-connection budget. Consumer handoff retains ownership of the relay
socket and permit; active tunnel lifetime is at most one hour. Cancellation drops
the listener's owned tasks and closes active tunnels. A 32-KiB control limit fits
all 128 maximum-length node IDs without disclosing their capabilities.

Tracker CLI identities persist across restart. Client/volunteer callers require
an explicit tracker pin; volunteers read a private, bounded capability file.
Discovery IDs never automatically become authorized proxies. The former normal
relay heartbeat that immediately dropped its registration was removed. Reverse
relay PoW workers now use independent starting nonces and run outside async I/O
workers, preventing pooled/refill requests from reusing deterministic proofs.
Workers terminating unexpectedly propagate failure. SOCKS success is sent only
after destination admission and connection.

This remains a private rendezvous feature. Registration labels are not
independently certified volunteer identities; first-registration racing and
broader distributed denial of service remain limitations. The tracker observes
participants. Reverse onion circuit transport is explicitly unsupported. See
[the operational contract](REVERSE_TRACKER.md).

## Verification

Linux x86-64, Rust/Cargo 1.95.0, matching 1.95 Clippy/rustfmt. Temporary tooling
was extracted without installing host packages. A disposable vendor cache was
restored from 310 root/fuzz locked crate archives, each checked against its
Cargo.lock SHA-256. Repository Cargo.lock was not changed.

| Check | Result |
| --- | --- |
| Final locked all-target/all-feature suite | 271 passed, 0 failed, 2 ignored; 57 target summaries |
| Final tracker auth/integration tests | 8 passed, including plaintext refusal and real four-visit transfer/refill |
| CLI safety and optimized daemon testnet | Passed; optimized daemon tests 2/2 |
| Debug and release all-target/all-feature strict Clippy | Passed |
| Formatting and diff whitespace | Passed |
| Optimized release build | Passed |
| All 13 fuzz harnesses: locked compilation and strict Clippy | Passed |
| Release version/admission tests | 2 + 9 passed |
| Native setup / restricted app launcher / HTTP measurement contracts | 13 / 5 / 2 passed |
| Browser session / extension / JavaScript isolation contracts | 13 / 2 / 6 passed |
| Trace / owned-evaluation integrity contracts | 3 / 5 passed |
| Debian package build and v0.2.0 metadata admission | Passed; unsigned local artifact |
| Workflow YAML parsing and shell syntax | Passed |

The ignored Rust tests are privileged namespace acceptance and optional real
obfs4 interoperability. Neither was rerun as a live acceptance test in this
session. Socket-based tests initially refused inside the filesystem sandbox;
the same tests passed with authorized local socket access. This is not a product
failure or a reason to weaken isolation checks.

Reproduce the main checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --release --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features --no-fail-fast
cargo build --locked --release
ANONGUARD_TEST_DAEMON="$PWD/target/release/anonguard-daemon" \
  cargo test --locked --test test_cli_safety --test test_daemon_testnet \
  --test test_tracker_auth --test test_tracker_integration -- --test-threads=1
cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets
cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
```

## Instrumented fuzz smoke results

All 13 targets completed a 20-second budget (about 21 seconds each) with seed
731, maximum input 16384 bytes, per-input timeout 10 seconds and 2048-MiB RSS
limit. They exited zero, loaded sanitizer coverage counters, and reported no
AddressSanitizer or LeakSanitizer error. Across targets libFuzzer reported
**5,336,915 executions**; these are mutations, not independent security trials.
The slow hybrid-identity target completed 277 executions and the peel target 350;
raw aggregate throughput must not obscure these smaller cryptographic samples.

The lab used Rust 1.95 / LLVM 21.1.8 and matching Clang 21 ASAN runtime, with
unstable compiler flags enabled only in a disposable fuzz build. Rust dependency
artifacts were ASAN-instrumented; core and harness compilation additionally used
`-C passes=sancov-module`, inline 8-bit counters, PC tables and comparison tracing.
Coverage pertains to those compiled paths; standard-library/native-crypto
instrumentation and complete branch coverage are not established. The supported
nightly cargo-fuzz path remains the recommended CI command in `fuzz/README.md`.

The first local attempt lacked registered coverage counters and failed in
LeakSanitizer under the restricted sandbox. It is excluded from passing results.
The corrected build was run with authorized sanitizer/process access and leak
checking retained. No check was disabled to count the failed run as a pass.

These are short, empty-corpus smoke campaigns. Some targets retained flat
coverage; valid protocol seeds, broader corpora, independent repeated seeds,
long campaigns and coverage review remain necessary. No sustained-fuzzing gate,
cryptographic security property or anonymity guarantee follows from this run.

## Release behavior

CI includes all 13 fuzz targets and the release-version unit tests. Release
publishing also requires browser integration and agreement between Cargo version,
tag and Debian metadata. Linux archives include native/browser setup sources.
The Debian package requires Python 3.11 for the verifier/version tooling and
checks both installed binaries' dynamic dependencies. Disposable package tests
now exercise distinct upgrade/downgrade fixtures and persistent-state hashes.
Privileged package installation was not performed on this host.

## Same-day dependency advisory follow-up

The first remote push (`637a4a8`) passed browser integration, tests/lint and
Linux/macOS/Windows compilation, but the fresh dependency audit found four
Rustls advisories published on 2026-10-14: RUSTSEC-2026-0346, 0347, 0348 and 0349.
Each upstream advisory specifies Rustls >=0.23.46. Cargo.toml now requires that
patch floor, and Cargo regenerated both lockfiles at 0.23.46. The downloaded
archive matched crates.io SHA-256
`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`.

The patched-dependency full suite again passed 271 tests with zero failures and
two opt-in skips. Strict Clippy, optimized build and all fuzz-harness compilation
were rechecked. The earlier ASAN mutation totals above belong to checkpoint
`637a4a8` before this Rustls patch; they are not relabelled as a new TLS fuzz run.

The fresh upstream RustSec database at
`edb58f5974b83eb8302332821cb6d389777aa351` contains 1329 advisories. Cargo-audit
0.22.2 with `--deny warnings` reported zero vulnerabilities/warnings in both
root (309 packages) and fuzz (275 packages) lockfiles. All 310 distinct locked
registry package versions also matched current authenticated index checksums
and had non-yanked status. No advisory was ignored.

The initial vendor-only cache caused yanked lookups to emit error diagnostics
even though cargo-audit returned zero. Those incomplete results were rejected.
After populating an isolated sparse cache from the verified HTTPS index
responses, both audits completed without diagnostic errors. CI now explicitly
rejects these soft errors, empty inventories, findings and warnings; four new
admission regression tests pass. Both root and fuzz lockfiles are audited.

The existing relay configuration already disables resumption, only offers the
hybrid KEX group, and does not enable ECH or Brotli certificate decompression.
These facts limit particular advisory conditions; they do not substitute for
updating the dependency. See the official
[RustSec advisory records](https://github.com/RustSec/advisory-db/tree/edb58f5974b83eb8302332821cb6d389777aa351/crates/rustls).

A separate OpenSSL 3.6.4 interoperability probe also passed seven message sizes
in each Rust-to-OpenSSL ML-DSA-65 and Ed25519 verification path, an OpenSSL-to-Rust
composite proof, and altered-message/signature refusal. It exercises the actual
domain-separated identity transcript with test-only keys. This validates a
signature backend boundary, not the complete protocol or external audit gate.

## Assurance still required

Independent protocol/composition review, sustained fuzz campaigns, installed
signed-addon/browser acceptance, privileged v6 leak/crash acceptance, independent
operators, multi-network load/partition tests and current v6 traffic-analysis
measurements remain gates. Algorithm names and passing tests do not establish
AI undetectability, browser fingerprint uniformity or global-observer resistance.
No percentage of production readiness is assigned. See
[the release gates](PRODUCTION_READINESS.md).
