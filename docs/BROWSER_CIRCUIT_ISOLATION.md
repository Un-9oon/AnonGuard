# Browser circuit-isolation engineering and release gates

Status: experimental source, offline contracts and a real headless Firefox local
fixture test implemented and passing on ESR 140.16.0. **Not yet a signed or
production-accepted feature.** The ordinary browser profile
still uses the daemon's shared default context. This document does not certify
Tor Browser equivalence or production anonymity.

## Implemented boundary

`browser/isolation` is a persistent Firefox extension using Mozilla's documented
`proxy.onRequest`, SOCKS username/password, remote DNS and connection isolation
key APIs. It targets the native Linux client at 127.0.0.1:9050 with padded sessions.
It does not change cryptographic algorithms or route through Tor.

Each browser-provided top-level origin gets random 256-bit local credentials,
scoped additionally to tab, cookie store and private mode. Same-origin reloads
keep their context; a different origin, tab or container gets another. Closing a
tab removes its labels, and browser restart creates fresh labels.
Subframes and resources inherit their owning top-level origin, including nested
third-party destinations. Firefox ESR 140 supplies `frameAncestors` and
`documentUrl`, not the optional document IDs assumed by the original draft.
The initial implementation consequently loaded a root page but blocked scripts;
a real browser repro confirmed this, and the integration now uses browser-supplied
frame ancestry. Missing or ambiguous attribution refuses instead of guessing from
a destination, Referer header or mutable tab URL. Old-document requests keep their
own source context during navigation.

The daemon hashes length-framed SOCKS labels into its context key. Different
labels cannot use the same cached session; existing 8-context/16-stream bounds
remain. Busy contexts can be refused, not merged. These labels are local circuit
selectors, not access-control credentials and not website account anonymization.
No browsing records are saved to disk. Memory is bounded to 512 origin contexts and cleaned on tab closure. A full table requires closing tabs or a new
browser session. Expected compatibility risks include background requests,
service workers without frame attribution, long-lived tabs and special browser channels.

The extension returns no direct proxy and terminates every fallback list. A
second blocking request listener cancels missing attribution. Proxy API errors
latch refusal until browser restart. The isolation policy sets the **default**
proxy to unavailable loopback port 9, so missing/disabled/failed extension does
not silently send traffic into the shared NOAUTH circuit. It allows only the
managed isolation extension. Existing native firewall containment is also needed.
The loopback endpoint must remain unavailable; validate this during acceptance.

## Packaging and deployment boundary

Build an unsigned, deterministic signing input (does not install anything):

```sh
python3 scripts/build_browser_extension.py --output /tmp/anonguard-isolation-unsigned.xpi
```

Have Mozilla sign the exact reviewed package for normal maintained Firefox ESR.
Do not turn off signature enforcement, browser sandboxing or security updates.
The Debian package ships **source for review**, never an active unsigned addon.
A signing account and signed artifact have not been supplied or created.

After authenticating the signed release, an administrator on the dedicated
client installs it root-owned/non-writable at
`/usr/share/anonguard/browser/isolation-signed.xpi`. Generate the opt-in policy:

```sh
anonguard-browser --emit-policy /tmp/isolation-policy.json --native-client --circuit-isolation
```

Inspect and install that policy at Firefox's actual supported policy path. Start
with `--check --native-client --circuit-isolation`, then
`--launch --native-client --circuit-isolation`. The launcher refuses a missing or
untrusted artifact. It **does not validate Mozilla signatures**; Firefox must
validate them and show the extension enabled under the active force-install
policy. File presence is not evidence the extension runs. Native role setup does
not automatically activate this experimental policy. The ordinary profile stays
available while this profile awaits acceptance.

## Required acceptance before treating this as delivered browser protection

1. Sign the package, run actual maintained ESR, confirm policy and addon loading.
2. Record real SOCKS credentials/circuit IDs for two sites, nested third-party
   frames, same-site reload, redirect, two tabs, containers and private windows.
   Verify attribution event ordering on that exact build, including old-document
   requests during navigation. All unknown attribution must refuse.
3. Disable/remove/break the addon and crash the proxy/relay: capture no direct
   DNS, IPv4, IPv6, WebRTC or QUIC. Verify no connection to the default NOAUTH
   context. Keep tests inside disposable fixtures, not sensitive browsing.
4. Evaluate storage and HTTP connection reuse, popup/worker behavior, font/canvas/
   WebGL/timezone/window fingerprints across machines and version upgrades.
5. Benchmark availability and padding overhead under the daemon's context caps.
   Independent review and defended-training/flow-correlation evaluation remain.

Offline tests cover parent-resource inheritance, site/tab/container/private-mode
separation, redirect-origin separation, attribution failure, bounds and listener wiring;
Python tests cover deterministic packages and policy fallback boundaries. A real Firefox test also verifies nested frame loading, shared third-party
credentials within a site, separate site/tab labels, remote-domain SOCKS targets,
WebRTC API disablement, loopback bypass refusal, missing-addon refusal and
proxy-loss refusal. This uses a disposable profile and temporary addon, with a
fixture-only HTTP exception. It is not a full DNS/IPv6/QUIC packet-capture audit
or signed-policy acceptance. Universal endpoint protection, a standardized
font/graphics distribution and an independently audited browser remain open.

Primary API references:
[Mozilla proxy event](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/onRequest),
[SOCKS and connection isolation fields](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/ProxyInfo),
[request attribution fields](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/RequestDetails).


## Local testing without a signing account

Install Selenium, Firefox ESR and geckodriver in a controlled test environment.
Run `python3 scripts/test_browser_live.py`; it loads the actual addon temporarily,
starts only loopback fixture servers, and deletes its browser profile on exit.
The native proxy port 9050 must be free: the test refuses an occupied port and
never stops another service. It does not use the user's VM or resolve/connect
real destination servers. A direct-connection canary checks failure boundaries.
GitHub's separate Firefox Browser Integration workflow repeats this against
maintained ESR. Signing is not needed for these development tests.

The Debian package now installs an **AnonGuard Browser** desktop entry. It starts
the native isolated profile and refuses missing protected configuration or a
missing signed addon. This is a launcher for maintained Firefox, not a new engine.
The entry remains unusable for normal deployment until the signed addon and
native client have been provisioned; local tests use temporary installation.


## Verified real testnet and privacy locks

`ANONGUARD_BROWSER_TESTNET=1 cargo test --locked --test test_daemon_testnet
padded_cli_testnet_transfers_and_closes_after_relay_loss -- --exact --nocapture`
now also runs real headless Firefox through four pinned authorities, three actual
relay daemons and the padded gateway to owned HTTP fixtures. A local SOCKS tap
observes local labels and forwards the real gateway response/data unchanged; it
never fabricates CONNECT success, resolves a destination or provides a direct
fallback. Sites and iframe resources load through the actual onion testnet.
Lab-only private-exit/zero-PoW settings do not escape temporary processes.

`python3 scripts/test_browser_policy_live.py` verifies the generated policy and
privacy preference locks inside actual Firefox using a private executable
layout. Follow the [AutoConfig migration](BROWSER_SESSIONS.md) before normal
launcher use. Enterprise-policy JSON alone did not enforce these privacy locks.
These checks are now part of the browser CI; full packet-capture and installed
client acceptance remain distinct tasks.
