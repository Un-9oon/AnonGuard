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
