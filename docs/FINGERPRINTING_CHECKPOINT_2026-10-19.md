# Fingerprinting defense checkpoint — 19 October 2026

These source changes are not evidence of Tor superiority, undetectability or
public production anonymity. Website inference and protocol identification
remain separate evaluation targets.

## Scheduling and session length

Covered-link and padded-session writers now retain their scheduling phase when
writes finish within a slot. Resetting after each write previously accumulated
write time into the cadence. Expired opportunities are skipped instead of repaid
as a catch-up burst. TCP congestion, OS scheduling and retransmissions still
affect observable packet timing; application cells are not IP packets.

The optional `fixed-window` padded-session profile removes last-activity time
from normal finish eligibility. Its 20 ms schedule requires at least 120 seconds
of session age and a 6,000-cell boundary before finishing. Existing drain
conditions and peer finish exchange remain mandatory. Busy sessions wait for a
later boundary; the 300-second lifetime limit remains. Setup, errors, congestion,
crashes and long transfers still expose information. This is not a promise of
an exact 120-second connection duration.

Strict link cover and upgraded participating relays are required. Older peers
reject the new profile identifier without silent fallback. Balanced remains the
default. Select `--privacy-profile fixed-window` in onboarding/device tooling,
or `--padded-sessions --privacy-profile fixed-window` on the daemon.

This experimental choice has a high cost: 6,000 8,192-byte session cells represent
49,152,000 bytes per direction before link framing/TLS/TCP. Strict link cover has
its own continuously scheduled envelopes; nested payload counts must not be
added as independent wire bytes. Measure captured wire bytes, useful throughput
and attack success at matched budgets before choosing a default.

## Browser consistency and acceptance

Browser configuration locks shared English language/locale values, clears
resist-fingerprinting domain exemptions, disables DNS prefetch from HTTPS pages
and supplies UTC in the browser environment. These supplement existing Mozilla
resist-fingerprinting, letterboxing, proxy and isolation settings. They are
standardization controls, not a new browser engine or unique invention. Hardware,
browser-version and rendering differences still need evaluation.

Managed browser policy also blocks new camera, microphone, location and
notification permission grants and locks those defaults. Typed search suggestions
and address/payment autofill are disabled to reduce accidental personal-data
disclosure. Capture/location-dependent sites lose that functionality. These are
endpoint privacy controls, not traffic-correlation defenses. The controls use
[Mozilla's supported permission policies](https://firefox-admin-docs.mozilla.org/reference/policies/permissions/).

Installed-browser acceptance and disposable policy tests compare every actual
protected preference value as well as its lock and policy state. Locked but
incorrect values are refused. Existing installed AutoConfig files are validated
exactly and never silently overwritten: operators must review and migrate older
policy installations before acceptance with the new configuration. Browser
updates, signatures and sandbox protections remain enabled.

## Evidence and limits

Checkpoint verification passed: 122 Rust library tests, strict all-target Clippy,
Rust formatting, 68 Python browser/onboarding/device/addon/distribution tests,
and three disposable Firefox ESR 140.16.0 live policy/browsing tests. Socket tests
were run outside the restricted sandbox; no host firewall or package installation
was performed. The published 18 October lab package predates these source
changes and must not be presented as containing them.

Regression coverage checks variable write costs, late-slot skipping, profile
encoding/rejection, activity-independent finish eligibility, actual encrypted
session completion, generated device configuration and weakened browser values.
Disposable Firefox tests exercise policy loading, page-visible language,
remote-domain SOCKS requests, nested resources and refusal paths. Temporary-addon
fixtures do not establish signed installed-browser delivery.
The real covered writer is additionally exercised with alternating 1/12 ms
flush costs under virtual time: data and dummy envelopes retain 20 ms write
spacing. This deterministic transport fixture does not model an Internet path.

These tests establish specific implementation behavior, not adaptive attack
accuracy, end-to-end correlation resistance, cross-device fingerprint entropy or
public-network resilience. Real traces, attacks trained on defended traffic,
held-out sites/devices/networks and matched latency/bandwidth comparisons remain
necessary. Signed-browser acceptance, independent protocol review and diverse
deployment evidence remain release gates.
