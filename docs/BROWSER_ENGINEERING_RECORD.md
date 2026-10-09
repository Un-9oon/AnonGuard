# Browser engineering record — 2026-10-10

This iteration delivers the native Firefox integration implementation and a
repeatable development test, not universal anonymity or a production release.

## Concrete defect fixed

The original document-ID isolation draft passed mocked tests but blocked real
Firefox ESR 140 subresources: the browser supplies frameAncestors/documentUrl at
these events. A real disposable headless repro loaded only the main page.
The corrected addon derives the top-level origin from browser-supplied frame
ancestry, keeps third-party resources within their owner context, and refuses
missing attribution. It does not read server-controlled Referer headers or guess
from the current tab URL. Same-origin reloads share a context, different origins,
tabs, containers and private windows do not. Navigation is not a universal
identity reset; close the disposable session for fresh browser state/labels.

## Delivered

- Version 0.1.1 addon sources and bounded local context management.
- Existing native opt-in policy with blocked default proxy and one managed addon.
- Deterministic unsigned signing input builder; production signature enforcement
  remains enabled. No signing account is needed for temporary development tests.
- AnonGuard Browser desktop entry for the provisioned native client; requires
  protected configuration and the signed addon for normal installed use.
- A Selenium/headless Firefox test using real addon APIs and local SOCKS/HTTP
  fixtures, with no connection to actual destination servers or the user's VM.
- Separate Firefox Browser Integration CI against maintained ESR with pinned
  browser/driver setup action commits.
- Debian packaging of launcher/desktop entry/reviewable addon sources and Python
  dependency, plus package-lifecycle file assertions.

## Observed checks

Firefox ESR **140.16.0** with a temporary addon passed the integration test twice
following the attribution fix. The final run verifies the page-visible RFP timezone `Atlantic/Reykjavik`
(year-round UTC offset). This value is read from page-executed JavaScript, not
WebDriver's privileged script context, which exposed the host timezone in an
initial incorrect test assertion.
It verifies nested third-party scripts/frames, parent-context credentials,
different site/tab labels, SOCKS domain targets rather than local destination
resolution, unavailable WebRTC API, no loopback target bypass, missing-addon
refusal and proxy-loss refusal against a direct-connection canary.

Seven browser launcher tests, two package/policy tests and six JavaScript tests
pass. Debian package rebuild and whitespace checks pass. Native-helper tests
previously passed outside sandbox restrictions. Rust protocol code did not change
in this iteration; its earlier test results are not a browser acceptance result.

The test deliberately permits fixture HTTP while normal browser policy remains
HTTPS-only. It does not demonstrate signed-addon installation, enterprise policy
locking/loading, all Firefox-internal channels, DNS/IPv6/QUIC packet-capture leak
absence, TLS handshake fingerprint normalization, uniform fonts/graphics across
machines, AI attack resistance, browser update safety or multi-region anonymity.

## Next acceptance stage

Run the provided test locally, then test the real AnonGuard client/relay network
with owned test destinations and packet captures. Record policy loading, cookie/
connection isolation, failure/leak behavior and fingerprint consistency on the
supported machines. Mozilla signing is needed for normal distribution, not these
development fixtures. Independent crypto review, traffic-analysis experiments,
operator diversity and broader platform work remain separate release gates.

## Follow-up: actual onion testnet and enforced privacy locks

On 2026-10-10, real Firefox ESR 140.16.0 also passed the CLI onion-testnet path:
four pinned authorities, three relay processes and the real padded gateway.
Owned HTTP pages and iframe resources loaded through the actual daemon chain.
A local SOCKS tap observes distinct origin credentials and forwards gateway
responses unchanged, with no synthesized success or direct destination fallback.
The existing 128 KiB transfer and relay-loss test still completes afterward.

A new real-browser policy test exposed another engineering defect: Firefox's
enterprise Preferences policy rejects the RFP/first-party privacy keys, so JSON
presence did not mean those preferences were locked. Those keys are now removed
from enterprise Preferences and locked using protected standard Firefox
AutoConfig. The launcher requires the exact protected loader/config and rejects
conflicting loaders. Operators must migrate previously generated policy files.
Eight launcher/generator tests now pass.

Both ordinary and isolated policies passed actual Firefox loading/preference-lock
checks inside private executable layouts. The test never writes installed host
policy or disables Firefox's AutoConfig sandbox. The Firefox CI now repeats both
these checks and the real CLI testnet browser path.

This strengthens local integration evidence. It still does not supply an
operator-installed client acceptance record, packet-capture DNS/IPv6/QUIC leak
proof, standardized font/graphics distribution, Mozilla-signed addon or an
independent anonymity/cryptographic assessment.


## Follow-up: generated native rules exercised in kernel

An isolated user/network-namespace test found that `redirect` was invalid as the
unquoted chain name. The generator now uses `nat_output`. After fixing it, the
real generated firewall and native adapter passed transparent TCP, DNS refusal
on authenticated-DoT failure, UDP/IPv6 drop, active-stream closure on backend
crash and bounded refusal of new streams. tcpdump observed only these owned
fixture flows; denial counters and table persistence were checked. No host
firewall, host account or user's VM was changed. The SOCKS backend here is a
fixture, with the actual relay/browser test performed separately.
The separate Firefox CI now runs this namespace/capture regression as well.
Operator-installed combined browser/client acceptance and broader adversarial
traffic-analysis evaluation are still not established by these tests.
