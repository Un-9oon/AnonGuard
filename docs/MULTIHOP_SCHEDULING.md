# Bounded multi-hop circuits and experimental scheduling

AnonGuard v5 supports 3 through 8 onion hops. The CLI defaults to a randomly
chosen length in 3..=5; configure `--min-hops 3 --max-hops 8` to expand the range.
Selection uses the authenticated directory, keeps a persistent entry guard,
chooses non-exit middle relays and ends at an exit relay. A private bridge can be
followed by a variable number of certified middle relays and a certified exit.
Not every relay is included. Unique endpoints and configured subnet diversity
remain selection constraints. Prefix diversity does not prove operator independence.

The upper bound uses available role-compatible, healthy relays and the selected
path's diversity constraints. Extra exits do not count as available middle hops.
A compatible exit is reserved before filling the middle path. Uniform sampling
then chooses a length within the configured minimum and available path length.
If that minimum cannot be met, selection fails; it does not downgrade to a
one/two-hop path or bypass authentication. Greedy selection is bounded and may
refuse a snapshot even when another guard/exit combination could form a path.
Existing guard pins are preserved rather than rotating until a path works.

This is a protocol migration: ALPN is `anonguard/5`, handshake transcript domains
are v5, and backward sequence numbers have a three-bit origin hop plus a 29-bit
counter. Sequence exhaustion fails closed. Upgrade clients and relays together;
v3 clients/relays cannot share circuit links with v5. Directory authority
transport is otherwise unchanged. Preserve identities, guards and rollback state.

## Timing behavior

Padded sessions wait a fresh profile interval after completing each socket write.
Backpressure therefore cannot produce immediate catch-up cells from an expired
timer. Relay TCP links disable Nagle batching so the kernel does not deliberately
add another small-write delay. Congestion, TCP segmentation and host scheduling
still affect wire timing; these settings are not a traffic-analysis proof.

### Cover budget and deployment tradeoff

The strict session interval is 20 ms: nominally 100 KiB/s of 2048-byte cells per
direction, or 200 KiB/s across both directions of each circuit link, even while
idle. Balanced uses 40 ms, nominally 50 KiB/s per direction. These are scheduling
budgets before TLS/TCP overhead, segmentation, retransmission and backpressure,
not measured throughput. Each hop carries that traffic; multiple isolated
contexts multiply it. The gateway bounds cached contexts to eight, streams to
sixteen per session and session lifetime to 300 seconds. Normal idle completion
also obeys the existing minimum-age/idle and 64-cell volume boundaries.

Native setup keeps balanced mode as its default. Use strict only with an explicit
cover budget; it does not promise stronger measured anonymity on every workload.
Reducing cover when application bytes stop can expose activity, while lengthening
tails consumes bandwidth. Do not tune these policies using the same held-out
attack samples used to claim success. Measure complete session lifetimes and
independent idle windows before reporting per-request or deployment-wide cost.

Default scheduling uses a 20 ms continuous timer and emits DATA, ACK or DUMMY
cells. `--rmt-morphing --rmt-ensemble goe` or `gue` selects experimental
Wigner-surmise intervals. GOE uses inverse-transform sampling; GUE uses a scaled
three-dimensional Gaussian radius. There is no GAN, quantum hardware, or learned
adversarial optimization in these samplers. RMT is classical statistics.

`--jitter` selects Poisson intervals and `--chaos` selects deterministic Lorenz
intervals. When several flags are enabled the existing precedence is RMT, then
Lorenz, then Poisson. Onion intervals are clamped to 5..=100 ms to bound rate and
stall costs, so their observed distribution is a truncated/clamped research
profile, not an exact unbounded Wigner distribution.

The client upload and exit response use their locally configured engines. Configure
participating exit relays as well as clients to enable statistical scheduling in
both directions: profile negotiation is not implemented. Intermediate relays
retain their configured forwarding jitter. Read events do not reset continuous
stream timers; real cells, ACKs and cover cells share their scheduling opportunities.
Cells remain 2048 bytes regardless of engine; RMT chunk-size research helpers do
not change the onion wire-cell size. TCP/TLS segmentation is outside that guarantee.

Longer paths add latency, handshakes and failure exposure. Random lengths may
also identify this network's traffic. RMT patterns may be learnable; artificial
randomness is not an anonymity proof. Real held-out attacker evaluation and fair
Tor benchmarks remain release gates. No source-only claim of stronger anonymity,
throughput, endpoint protection or production readiness follows from this change.
