# Browser circuit-isolation engineering and release gates

Status: experimental source and offline contracts implemented. **Not yet a
signed, installed or browser-accepted feature.** The ordinary browser profile
still uses the daemon's shared default context. This document does not certify
Tor Browser equivalence or production anonymity.

## Implemented boundary

`browser/isolation` is a persistent Firefox extension using Mozilla's documented
`proxy.onRequest`, SOCKS username/password, remote DNS and connection isolation
key APIs. It targets the native Linux client at 127.0.0.1:9050 with padded sessions.
It does not change cryptographic algorithms or route through Tor.

Each top-level navigation receives fresh random 256-bit local credentials.
Credentials are scoped to tab, cookie store, private mode, request identity and
hostname. Redirecting to a different hostname receives a different context.
Subframes and resources inherit the originating document's context, including
third-party destinations. Opaque document IDs bind parent/child attribution;
missing IDs are refused rather than inferred from a referrer or destination.
An ESR build that does not expose these IDs at the necessary events is **not
supported by this integration**, even if it passes the launcher's version floor.

The daemon hashes length-framed SOCKS labels into its context key. Different
labels cannot use the same cached session; existing 8-context/16-stream bounds
remain. Busy contexts can be refused, not merged. These labels are local circuit
selectors, not access-control credentials and not website account anonymization.
No browsing records are saved to disk. Memory is bounded to 2048 pending/document
entries and cleaned on tab closure. A full table requires closing tabs or a new
browser session. Expected compatibility risks include background requests,
service workers without document attribution, long-lived tabs and redirect IDs.

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

Offline tests cover parent-resource inheritance, tab/container/navigation
separation, redirect rejection, attribution failure, bounds and listener wiring;
Python tests cover deterministic packages and policy fallback boundaries. They
are not real Firefox leak tests. Universal endpoint protection, a standardized
font/graphics distribution and an independently audited browser remain open.

Primary API references:
[Mozilla proxy event](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/onRequest),
[SOCKS and connection isolation fields](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/ProxyInfo),
[request document identities](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/RequestDetails).
