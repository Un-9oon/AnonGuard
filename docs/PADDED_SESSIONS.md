# Padded onion sessions (experimental protocol v6)

The target is reduced website-fingerprinting leakage to a local passive observer
of the client link. This is not an undetectability promise, a global correlation
proof or a defense against a compromised client/exit. RMT describes a classical
statistical sampler; it does not use quantum hardware or create quantum secrecy.

Start an already provisioned client with the existing authority, pin and quorum
arguments plus:

```sh
anonguard-daemon --onion --padded-sessions --privacy-profile balanced \
  --listen 127.0.0.1:9050 [existing authenticated bootstrap arguments]
```

The bracketed text above describes required arguments; it is not a shell command
to copy verbatim. All relays and clients need protocol v6 and matching authenticated link-cover
ALPN (`anonguard/6` for strict; `anonguard/6-cover40` for economy). No fallback to older protocols or unpadded streams
occurs when profile negotiation fails. Legacy `--jitter`, `--chaos`, `--rmt-morphing` and `--chaffing` flags cannot be combined with session profiles. Authorities require the v6 deployment
identity/directory migration described in [the protocol](PROTOCOL_V3.md). Legacy single-stream mode remains available when
`--padded-sessions` is omitted; it does not get session tails or multiplexing.

## Implemented contract

The selected exit authenticates an exact version/profile acknowledgement inside
the onion circuit. Intermediate relays forward encrypted session controls. Only
an exit at hop index 2 or later accepts sessions. Profiles are common presets:

| Profile | Scheduled interval per direction | Intended role |
|---|---|---|
| balanced | 40 ms | Fixed-rate baseline |
| balanced-longtail | 40 ms | Longer idle/duration buckets |
| fixed-window | 20 ms | Minimum 120 s; 6000-cell finish boundaries; strict link cover |
| strict | 20 ms | Higher-bandwidth fixed-rate baseline |
| research-rmt | GOE-derived, bounded 5–100 ms | Experimental comparison |
| research-poisson | Poisson-derived, bounded 5–100 ms | Experimental comparison |

A dedicated actor schedules both directions independently of application reads.
At a scheduled opportunity it emits one 8192-byte onion cell: queued control,
ACK, application data or encrypted dummy. ACKs and data use round-robin fairness
across streams. DATA waits for a one-second warm-up. Circuits remain alive after
individual TCP streams finish. For balanced/strict/research profiles, once empty,
an idle tail lasts at least ten
seconds, the duration reaches a common 30-second bucket and each direction's
final scheduled cell count aligns to 64. A finish handshake ends the session.
`balanced-longtail` instead uses at least 20 seconds idle and a 60-second age
bucket, retaining 64-cell alignment. `fixed-window` ignores last-activity time
for finish eligibility: minimum session age is 120 seconds and final scheduled
cell count aligns to 6000. Drain conditions and the finish exchange remain
mandatory. Older peers refuse its profile bytes `[1,6]`; there is no fallback.
Concurrent arrivals can extend it. The hard lifetime is 300 seconds and closes
active streams without transaction replay. Idle contexts are recreated on a
later request, with a new circuit; a request racing a retiring session may fail.

Schedules are cell-layer targets, not exact IP packet timing: TLS/TCP framing,
congestion, CPU scheduling and relay jitter change observations. Slow writes
cause backpressure and bounded failure rather than catch-up flooding. Opening
handshakes and initial circuit creation remain observable outside scheduled
cells. A shared session is created on demand; it is not permanent background
cover across the device's entire online lifetime.

Per session limits: 16 concurrent streams, 1024 monotonic stream identifiers,
32 unacknowledged data cells per stream per direction, bounded queues, at most
64 pending controls, a 512-cell receive burst followed by 250 cells/second,
30-second I/O deadlines and a 300-second total lifetime. Writes earn cumulative
credit only after destination/application delivery. Unknown controls, replay,
invalid credit and cryptographic errors fail closed. Destination refusal or
local stream failure resets that stream; no direct connection fallback exists.

## Privacy contexts and resource costs

SOCKS RFC1929 username/password tuples, when supplied, are length-framed and
hashed locally as opaque context labels. They are **not password authentication**
and never go to relays. Same label shares one run-scoped session; different
labels use different circuits. At most eight active contexts are cached. No-auth
clients share the daemon's default context. Therefore this does not automatically
provide per-site or per-account isolation. Use dedicated daemon instances/ports
for unrelated browser identities when the application cannot supply labels.
Cache lifetime ends with the listener; cached actor tasks are aborted on drop.

The native adapter uses an ephemeral process label distinct from the default
browser context. OS applications routed through that adapter share its context.
Neither labels nor padding prevent login/cookie identity disclosure.

At 40 ms, each active context schedules about 204.8 kB/s of session cells per direction; at 20 ms,
about 409.6 kB/s, before TLS/TCP overhead and retransmission. Eight contexts
multiply costs. Mandatory strict hop-local cover uses an 8196-byte envelope every
20 ms (409.8 kB/s per direction) independently of session activity. Session cells
are payload inside those envelopes, not a second wire-byte total to add. Tail
traffic and multiple hops add further costs. These are
calculated scheduling costs, not measured throughput or anonymity improvements.

## Evidence and acceptance

Local tests cover genuine pinned TLS/hybrid three-hop transfer, two multiplexed
half-closed streams, refusal isolation, CLI transfer and closure after relay
loss, exact profile negotiation, context framing, replay/unknown controls,
receive-rate limits and virtual-time idle-tail/volume boundaries. These tests
are correctness evidence, not attack-resistance measurements.

Before recommending use for personal safety, collect owned multi-user traffic
under held-out days/devices/networks; retrain attack models on each defended
profile; evaluate deep website fingerprinting and two-end flow correlation
separately; compare latency, bandwidth and anonymity under a matched Tor
baseline. A novel timing distribution can itself be a fingerprint. Fixed-rate
profiles are the engineering baseline; statistical modes are research options.
