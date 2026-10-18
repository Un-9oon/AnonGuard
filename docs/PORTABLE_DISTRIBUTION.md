# Portable Linux distribution

The distribution combines a real `.deb` with an ordinary-user installer and a
plain-English guide. It targets a dedicated Ubuntu 24.04 LTS x86-64 lab device.
The current local package is unsigned and is not a production release.

## Operator build

Build the package with `scripts/build_deb.sh` (or its explicitly documented
`--prebuilt` option when optimized binary provenance is already established), then:

```sh
python3 scripts/build_distribution.py \
  --deb dist/anonguard_0.2.0_amd64.deb \
  --output dist/AnonGuard-Linux-0.2.0-lab
```

The output directory must not exist. The builder also creates a sibling `.tar.gz`.
The builder snapshots and checks package metadata, checks matching provenance if
present, preserves the installer executable bit and records the package revision
separately from the distribution builder revision/dirty state. It never installs
the package or starts services. SHA256SUMS covers the package, installer, guide and
build information. These checksums do not independently authenticate the publisher.

## Recipient flow

Extract the archive, open a terminal in its folder, and run `./install.sh --check`.
This validates the checksums, package identity, host architecture and Python baseline,
then runs apt's dependency simulation. It does not run the onboarding wizard or
modify host firewall/service configuration.

Run `./install.sh` as an ordinary desktop user at the target device console. It
repeats preflight, requires a running systemd host, asks before installation, runs
sudo/apt with the local package and invokes the existing first-run launcher. The
wizard offers Client or non-exit Volunteer. Subsequent browsing uses the application
menu entry. `apt` needs configured OS repositories/internet; dependency `.deb` files
are not bundled for offline use.

## Remaining operator provisioning

This bundle does not create a public relay network or invent trust roots. A novice
still needs operator-prepared authentic bootstrap/checksum and, for clients,
protected-entry credentials, maintained root-installed Firefox ESR, an approved
Mozilla-signed addon and its authenticated version/digest. The existing wizard
currently prompts for these inputs; this is not a fully provisioned one-click
anonymous browser. No root keys or private bridge credentials are copied into the
distribution. Standard Ubuntu Firefox Snap is not automatically converted to ESR.

Firewall activation remains console-only. Package removal intentionally preserves
firewall restrictions/security state. There is no automatic networking reset or
unreviewed migration over an existing installation. Explain this to recipients
before configuring their regular desktop.

## Verification boundaries

`python3 scripts/test_distribution.py` exercises archive integrity, payload retention,
tamper/architecture refusal, non-overwrite and provenance mismatch. These fixtures
never install packages. A local apt simulation is not a fresh Ubuntu installation,
signed-addon acceptance, boot/recovery test or anonymity measurement. Those existing
release gates still apply to each intended installed target.
