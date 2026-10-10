# Experimental Firefox ESR session integration

`anonguard-browser` is an operator-configured Firefox ESR integration for the
[SOCKS-only application VM](VM_SEPARATION.md). It is not a new browser engine,
Tor Browser replacement or fingerprint-indistinguishability certification.
It requires maintained native Linux Firefox ESR 140 or later; install current
security updates from a trusted vendor. A minimum version check is not a check
that all known vulnerabilities are patched. Snap/Flatpak layouts are outside this
initial native-file profile.

## Provisioning

First prepare both VMs and their networking/firewall boundary. Create a dedicated
non-administrator application user without personal browser state or host
integrations. Firefox and its dependencies must be administrator-installed and
not writable by that account. Do not disable the browser sandbox to make it run.

Generate the browser policy offline, with the same gateway/port as the VM profile:

```sh
python3 scripts/browser_session.py --emit-policy /tmp/anonguard-browser-policy.json \
  --proxy-host 10.77.0.1 --proxy-port 9050
```

The destination must not exist. Inspect the policy before copying it to the
application VM. On that guest only, an administrator installs root-owned,
non-writable inputs:

```sh
sudo install -d -m 755 /etc/firefox/policies /etc/anonguard
sudo install -m 644 anonguard-browser-policy.json /etc/firefox/policies/policies.json
sudo install -m 644 profile.json /etc/anonguard/vm-profile.json
```

`profile.json` must be the reviewed two-VM generator output for this deployment.
The policy is system-wide and changes Firefox for every user of this dedicated
VM. Resolve existing enterprise policy conflicts first; the launcher refuses
additional/weakened settings rather than silently merging them. For distributions
using a different policy directory, install to the actual vendor-supported path
and pass that absolute path with `--policy-path`. Confirm which file Firefox
loads; merely passing a filename to the launcher does not tell Firefox to use it.

The generated policy locks SOCKS5 and remote DNS, clears bypass exceptions,
disables proxy direct failover, DoH, WebRTC and HTTP/3, reduces prefetch/speculative
connections, enables HTTPS-only mode, resistance-to-fingerprinting and letterboxing
preferences, and applies first-party/network-state isolation preferences. It
blocks additional extensions and disables account sync, telemetry and stored
login/form features. It does **not** disable security updates, safe browsing,
certificate validation, the browser sandbox or remote security-setting updates.

## Check and run

As the ordinary application user inside the VM:

```sh
anonguard-browser --check --proxy-host 10.77.0.1 --proxy-port 9050
anonguard-browser --launch --proxy-host 10.77.0.1 --proxy-port 9050
```

From a source checkout, use `python3 scripts/browser_session.py` in place of the
installed command. `--check` reads protected configuration, inspects actual guest
addresses/routes and obtains the browser version; it does not open a browser or
external connection. Root execution, writable/symlinked policy inputs, endpoint
mismatch, extra non-loopback interfaces, unexpected addresses/IPv6 and default or
foreign routes are refused. These observations do not attest the hypervisor or
active firewall; require their separate acceptance results.

Each launch gets a new private temporary profile, fresh session home/cache and
temporary download directory. Existing profiles are never imported or reused.
Arbitrary browser options, extensions and startup URLs cannot be passed through.
Inherited preload/proxy and browser sandbox-override variables are discarded.
Normal shutdown and handled termination stop the browser process group and delete
the temporary directory. SIGKILL, host crash and storage snapshots can retain
data: this is not forensic erasure or a live OS. Use disposable encrypted VM
storage if required, and keep downloads within the VM. Do not open downloaded
files through host applications or shared folders.

## Browser acceptance still required

Before browsing real sensitive traffic, open `about:policies` inside the launched
browser. Record the active generated policies and absence of errors. Check that
the relevant preferences are locked and effective on the exact ESR build. The
launcher's `configuration_present` result intentionally keeps `browser_accepted`
false and reports policy loading **NOT VERIFIED**. File/schema validation cannot
prove preference enforcement or networking behavior.

Use owned test pages and captures to verify remote DNS, no direct IPv4/IPv6,
WebRTC/QUIC behavior, gateway-loss refusal, cookie/storage separation after restart,
letterboxing and observable fingerprint consistency across supported machines.
Test version upgrades as well as current installation. Fresh profiles do not
provide per-site SOCKS identity/circuit isolation. The separate experimental
[native isolation extension](BROWSER_CIRCUIT_ISOLATION.md) adds source and policy
contracts, but still needs signing and real-browser acceptance. A personal login still identifies its user. Fonts, graphics, locale, browser
version, custom features and small population can still distinguish sessions.
This integration does not reproduce Tor Browser's complete patch set or establish
equivalent anonymity. No browser integration live acceptance is recorded yet.

References: [Mozilla policy configuration](https://firefox-admin-docs.mozilla.org/guides/policies-configuration/),
[locked SOCKS/remote-DNS policy](https://firefox-admin-docs.mozilla.org/reference/policies/proxy/),
[preference policies](https://firefox-admin-docs.mozilla.org/reference/policies/preferences/).


## Required privacy AutoConfig migration

Real Firefox ESR testing found that enterprise `Preferences` accepts network
preferences but rejects the RFP/first-party privacy preferences used here. These
privacy locks now use Firefox's standard AutoConfig `lockPref`, with its sandbox
left enabled. The launcher requires exact protected AutoConfig files and refuses
conflicting loaders. Regenerate old policies, which contained ineffective locks.

Generate files offline:

```sh
anonguard-browser --emit-autoconfig /tmp/anonguard-privacy-config
```

On the dedicated client only, an administrator reviews and installs
`anonguard.cfg` in the actual Firefox executable directory and `anonguard.js` in
its `defaults/pref` directory, both root-owned mode 644. Resolve existing
AutoConfig first; do not overwrite an organization's configuration. For a native
Debian ESR layout, those paths are `/usr/lib/firefox-esr/anonguard.cfg` and
`/usr/lib/firefox-esr/defaults/pref/anonguard.js`. Other layouts need their actual
vendor executable directory. The launcher checks that directory based on the
resolved executable, not a guessed system-wide path. Firefox/vendor updates must
preserve/revalidate these inputs; missing/changed inputs refuse launch.

The local policy test uses a private executable layout with read-only vendor
resources and an actual `distribution/policies.json`. It verifies policy loading
and all relevant preference locks in ordinary and isolated profiles, without
changing the installed Firefox. It does not establish the operator's installed
client configuration, addon signature acceptance or all fingerprint surfaces.

### Coherent provisioning bundle

Generate all three configuration inputs together instead of mixing an old policy
with new privacy locks:

```bash
python3 scripts/browser_session.py --native-client --circuit-isolation \
  --emit-bundle ./browser-provisioning
```

The destination must not exist. It contains `policies.json`, `anonguard.cfg`,
`anonguard.js`, and a SHA-256 inventory in `bundle.json`; files are private to the
creator. Generation changes neither Firefox nor host services. The inventory is
for consistency checking, not a signature or an authenticity proof.

For an administrator-managed Firefox ESR installation, install the reviewed
policy at `/etc/firefox/policies/policies.json`, the cfg beside the resolved vendor
Firefox executable, and the loader at that directory's
`defaults/pref/anonguard.js`. Use root-owned files mode 0644 and protected,
non-symlink ancestor directories. Refuse conflicting AutoConfig loaders rather
than overwriting another administrator's setup. This policy affects that Firefox
installation, including other users; provision a dedicated installation when
shared-browser behavior must be preserved. Do not copy files into a vendor
resource tree through symlinked directories.

Circuit isolation additionally requires the genuine Mozilla-signed XPI at
`/usr/share/anonguard/browser/isolation-signed.xpi`. The launcher now rejects
unsigned archives, wrong extension identities, unexpected executable members,
duplicate members, archive traversal, and oversized decompressed contents.
Signature-member presence is only a structural preflight: Firefox must verify
the actual signature and accept the managed extension. Never rename the unsigned
source package to make it appear signed, or disable signature verification.
A non-isolated bundle deliberately uses the shared default circuit and must not
be described as providing per-origin circuit isolation.

After protected installation, run `anonguard-browser --native-client
--circuit-isolation --check` as the ordinary client user. This verifies files and
service prerequisites; its output still states that browser policy loading has
not been verified. Acceptance must include actual policy locks, managed addon
loading, distinct SOCKS origin credentials, and failure refusal in the installed
browser. The automation tests use temporary addon installation and are not a
substitute for the signed distribution acceptance test.

Validate a saved bundle before privileged provisioning:

```bash
python3 scripts/browser_session.py --native-client --circuit-isolation \
  --validate-bundle ./browser-provisioning
```

Validation compares bounded regular-file contents against the supported generator,
not merely the editable hash inventory. It rejects missing/extra members, symlinked
members and rehashed weakening of the default refusal endpoint.

### Installed signed-browser offline acceptance

After the operator installs the protected policy, AutoConfig and genuinely signed
addon, an ordinary user can run the following with Firefox ESR, Selenium and
geckodriver available, **and the SOCKS client already stopped**:

```bash
python3 scripts/check_installed_browser.py
```

This helper changes no host configuration and does not install a temporary addon.
It uses a fresh automation profile of the actual installed browser to inspect
loaded policies/locks and Firefox's signed, active managed-addon state. It then
tries an owned loopback canary with SOCKS unavailable and refuses acceptance if
any direct connection arrives. Automation system access is enabled only for
observing policy/addon state; signature checks and privacy policies remain intact.
A force-installed addon may need up to 30 seconds to load; absent signing artifacts
or incorrect protected configuration produce failure rather than a skipped pass.

This is a negative integration acceptance check, not a general leak audit. Host
firewall restrictions can independently prevent the canary connection, and native
firewalls may also block WebDriver's ephemeral local control ports. Report such
failures rather than weakening production rules to obtain a pass. A later positive
installed-browser test must exercise the live client, signed extension, origin
credentials and actual relay destination; packet captures, IPv6/DNS leak tests,
and cross-device fingerprint measurements remain separate requirements.

The installed offline checker now requires the exact complete preference-lock
set and enabled Firefox signature enforcement. Its canary observer must first
pass an owned-loopback positive readiness probe, remain alive, and encounter no
observer errors. A successful negative result additionally requires Firefox's
`proxyConnectFailure` error page to identify the exact unique requested canary
URL. HTTPS-only interstitials, generic connection errors, stale error pages,
missing locks and WebDriver failures are refused rather than counted as passes.
The browser diagnostic establishing that refusal format used a disposable profile,
not an installed signed-browser acceptance run.
