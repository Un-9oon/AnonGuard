# Joined Linux onboarding

For copying the package to another computer with an installer and plain-English
guide, see [Portable Linux distribution](PORTABLE_DISTRIBUTION.md).

## What this automates

For a fresh dedicated Debian/Ubuntu-style systemd Linux installation:

1. `apt` installs the native package and required networking/service dependencies.
2. Open **AnonGuard Browser** (or run `anonguard-onboard --start`) as the ordinary
   desktop user. On first use it opens the same sudo/terminal setup wizard, offering
   Client or non-exit Volunteer. **AnonGuard Setup** and
   `sudo anonguard-onboard --apply` remain explicit console-only alternatives.
3. Supply independently authenticated network bootstrap inputs. Clients also
   supply private obfs4 provisioning and an approved signed addon, or use an
   already coherently installed addon. The wizard checks all these before applying.
4. Client onboarding provisions coherent managed Firefox policy/AutoConfig and
   addon delivery, then calls the existing native setup for dedicated accounts,
   firewall-before-service activation and protected PT/gateway/adapter startup.
5. The wizard checks service activity and writes a non-secret root-controlled
   completion receipt. The ordinary desktop user opens **AnonGuard Browser**;
   its new launcher uses the exact Firefox executable selected in onboarding.

No VM is required for installation. No browser runs as root. The wizard does not
invent network operators, trust downloaded keys automatically, create signing
accounts, disable signature/AppArmor enforcement or open an exit by default.

## Install and start setup

Authenticate the package/signatures/operator policy before installation. Local
unsigned lab packages require their own explicitly recorded test-build procedure.
From the directory containing the actual package:

```sh
sudo apt install ./anonguard_0.2.0-0lab.20261019.1_amd64.deb
anonguard-onboard --start
```

`apt`, unlike bare `dpkg -i`, resolves the declared dependencies: Python, systemd,
iproute2, nftables, obfs4proxy, procps and sudo, plus detected ELF libraries.
Firefox ESR is recommended when available from the configured OS repositories.
Ubuntu repositories may not provide it; a maintained root-installed Firefox ESR
must then be independently provisioned. The wizard accepts its actual executable
path and refuses unsupported stable/Snap browsers or non-ESR version output;
it does not add an unknown third-party repository or download/execute a browser.
Bubblewrap/libseccomp remain optional dependencies for the separate headless-app
containment profile. Ordinary native onboarding is not that rootfs profile.

A genuine approved Mozilla-signed isolation XPI is an external prerequisite.
The wizard can install it using an independently authenticated digest/version;
Firefox must still authenticate the signature and activate the addon. Missing
ESR, addon, bootstrap or protected-entry material blocks client setup. Thus a
package alone still cannot promise immediate public anonymous browsing.

## Noninteractive administration and read-only planning

Example client plan (replace placeholders with real independently authenticated
operator inputs; placeholders intentionally cannot pass):

```sh
anonguard-onboard --plan --role client \
  --bootstrap /operator/bootstrap.json --bootstrap-sha256 TRUSTED_BOOTSTRAP_SHA256 \
  --transport-config /operator/pt.json --transport-config-sha256 TRUSTED_TRANSPORT_SHA256 \
  --browser /opt/dedicated-firefox/firefox \
  --extension /operator/isolation-signed.xpi --extension-sha256 TRUSTED_XPI_SHA256 \
  --extension-version 0.1.1
```

`--plan` validates input/prerequisite and browser-target contracts without changing
configuration or services. It may read operator files and execute the trusted
browser's `--version`; it is not a live connectivity/anonymity acceptance test.
It can run over SSH. To apply the same inputs, use `--apply` as root **at the
local console**; An interactive local TTY is required. SSH environment and process-ancestry checks
refuse detected SSH application even when sudo resets environment variables, because firewall
activation can disconnect remote administration. The desktop Setup entry opens
this same sudo/terminal flow, rather than creating a separate GUI implementation.

Volunteer setup needs only the authenticated bootstrap and a reachable advertised
IPv4:port. NAT forwarding/reachability is separately configured by the operator;
there is no automatic UPnP or promise that restrictive networks permit relays.
A volunteer does not get a client firewall/browser profile.

## Preservation and failure behavior

Native configuration/state is never overwritten to reinitialize an existing
installation. Its preflight runs before browser files are published. Existing
browser files must be root-controlled and exactly match the supported generator;
conflicting policy/AutoConfig refuses before publication. Use a dedicated
root-installed ESR layout if another administrator already manages the vendor
installation. This policy affects that Firefox installation, including other users.

Console detection is an operational safeguard, not attestation of physical access
or protection against a malicious administrator. A private nonblocking `/run` lock
refuses overlapping onboarding operations.
Successful completion writes `/etc/anonguard/onboarding.json`, recording role and
browser path with `configuration_complete: true`, `browser_accepted: false` and
`deployment_accepted: false`. Service activity is not proof of directory quorum,
usable circuits, addon signature acceptance or anonymity. The normal browser
launcher repeats its native/policy/receipt preflights before launch.

Failure may leave partial configuration or installed addon/browser policy. The
wizard does not delete keys/configuration or remove firewall rules to recover.
Missing completion receipt blocks the joined browser launcher. Preserve state
and diagnose from the console using the documented upgrade/recovery process;
this is a fresh-install flow, not automatic repair or role switching. Vendor
browser updates and upgrades require renewed acceptance; a changed/missing pinned
executable can deliberately refuse launch. Keep protected applications stopped
until installation and real-network acceptance complete.

## Verification scope

Source tests cover role selection contracts, authenticated input refusal,
protected-entry wiring, prerequisite refusal, browser target inspection, apply
ordering, no-overwrite preflight, failure-without-firewall-removal and ordinary-user
launch with the selected browser. They mock privileged application and do not
activate a host firewall. Package tests check helper installation and extensionless
module loading. A full console-run new-device client with actual signed addon,
trusted operators and native real PT/client/firewall composition remains required.

### Current verification record

Seventeen new onboarding contracts passed locally, plus 21 native, 13 browser
session, seven addon-install, 21 release-verifier and two release-version tests:
81 checks total. Native loopback/systemd-parser tests ran outside socket sandbox
restrictions; none activated host routing services or firewall. The new cases cover
first desktop start, configured subsequent start, Volunteer no-browser behavior,
SSH ancestry after sudo environment reset, local-console requirements and read-only
browser-layout refusal. Root application is mocked in orchestration tests.

VM transfer was attempted but 192.168.122.128 returned `No route to host`.
There is no current VM full-apply result for this flow. Package extraction/helper
CLI checks are separate from a console-run actual signed-ESR/client deployment.
