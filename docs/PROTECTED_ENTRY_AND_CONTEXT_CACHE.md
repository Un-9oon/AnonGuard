# Protected entry and independent privacy-context initialization

This checkpoint addresses two engineering boundaries found after the owned-VM evaluation. It does not establish public anonymity, traffic indistinguishability or a reduction in the measured padding bandwidth cost.

## Protected-entry policy

The daemon now exposes `--protected-entry`. This opt-in client policy requires all of:

- `--onion --padded-sessions`;
- `--bridge-transports` with provisioned, pinned entry transport bindings;
- `--authority-transports` covering the pinned directory authority set, with the existing authenticated authority configuration.

Missing dependencies fail at CLI validation before key creation or networking. Existing binding validation, entry selection, TLS identity/proof checks and authority transport coverage checks remain mandatory. Existing transport connection code has no direct or local-DNS fallback. The policy may use provisioned listed entries; `--private-bridges` additionally selects the independently provisioned unlisted-entry mode.

Client mode without this opt-in emits a warning that direct/partially protected TLS metadata can identify AnonGuard. Direct mode remains available for authorized labs and deployments that do not claim transport concealment. At this historical checkpoint the policy was a daemon CLI contract. The subsequent [native installer integration](NATIVE_INSTALLATION.md) now provisions authenticated operator-supplied bindings, a dedicated PT service, systemd credentials and restricted egress. Actual installed acceptance remains open.

ALPN validation was not removed and relay authentication was not weakened. A required wrapper prevents sending the client-facing protocol directly when correctly provisioned, but neither the flag nor a successful obfs4 connection proves resistance to adaptive classifiers, active probing or a network-wide observer. The outer transport needs its own capture/evaluation.

## Independent context setup

Previously the padded gateway held the shared cache mutex while establishing a circuit, potentially for the full setup timeout. A slow context could therefore block unrelated contexts.

The cache now reserves a bounded slot under a short map lock, then initializes the session through a per-context `OnceCell` outside that lock:

- different contexts can establish independently;
- concurrent requests for one context share one setup/session;
- pending reservations count toward the existing eight-context limit;
- finished/failed sessions and abandoned cancelled reservations can be reclaimed;
- a live waiter retains a pending reservation; unrelated contexts are never merged or evicted to make room;
- session tasks retain abort-on-drop ownership and the existing 30-second setup deadline.

The first debug end-to-end run exposed a stack overflow from nesting the large cryptographic setup future under the new initialization machinery. Boxing that future corrected the regression; the padded CLI transfer/relay-loss test subsequently passed without increasing thread stacks or weakening deadlines.

This removes an artificial cross-context setup dependency. It does not change the 20-ms covered-link interval, cell sizes, cover tails, stream isolation, traffic budgets or wire protocol. No numerical production latency improvement is claimed without a matched benchmark. The previously observed roughly 11x captured-link byte cost remains an open optimization concern.

## Verification scope

Three concurrency tests cover independent progress/capacity accounting, single initialization/shared ownership, failure reclamation and cancelled-initializer recovery. CLI refusal tests cover missing protected-entry requirements. The private padded testnet now explicitly enables the new policy. The ordinary CLI network passed both tests on the VM with the candidate debug daemon. The optimized candidate release daemon passed both real-obfs4 private-bridge tests, including padded protected-entry mode (8.59 seconds total). An early VM debug private-bridge run failed the existing 20-second authority bootstrap deadline before reaching gateway/session initialization; that failure is retained rather than counted as a passing run. The test deadline was not increased. Strict all-target/all-feature Clippy, formatting and the release build passed. The full all-target/all-feature Rust suite completed with **283 passed, zero failed and two ignored**, plus passing benchmark smoke checks. The unsigned local Debian package was rebuilt from the optimized daemon. No fresh traffic-analysis resistance improvement is claimed from these functional checks.

## Still open

Representative outer-transport detection measurements, adaptive site/activity inference and correlation evaluation, matched bandwidth/latency defense selection, native protected-transport provisioning, signed normal browser/release delivery, secure update/key recovery acceptance, independent protocol review, sustained fuzz/load tests and independently operated networks/users remain required. These changes do not close those acceptance gates.
