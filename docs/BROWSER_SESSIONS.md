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
provide per-site SOCKS identity/circuit isolation; that remains separate gateway
work. A personal login still identifies its user. Fonts, graphics, locale, browser
version, custom features and small population can still distinguish sessions.
This integration does not reproduce Tor Browser's complete patch set or establish
equivalent anonymity. No browser integration live acceptance is recorded yet.

References: [Mozilla policy configuration](https://firefox-admin-docs.mozilla.org/guides/policies-configuration/),
[locked SOCKS/remote-DNS policy](https://firefox-admin-docs.mozilla.org/reference/policies/proxy/),
[preference policies](https://firefox-admin-docs.mozilla.org/reference/policies/preferences/).
