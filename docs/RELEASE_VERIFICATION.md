# Verify a release before installation

Use a tagged experimental release and select its exact tag through an authenticated
operator channel. A SHA-256 checksum alone does not authenticate the publisher.
The signed SHA256SUMS manifest binds artifact bytes to the release workflow and tag.
Verification does not certify anonymity, review quality or deployment readiness.

Obtain the verifier from an independently trusted source checkout, not by executing
code inside the unverified archive. Independently install and verify Cosign using
the [official installation guidance](https://docs.sigstore.dev/cosign/system_config/installation/).
The verifier requires Python 3.11 or later on Linux.

Download the selected package, SHA256SUMS and SHA256SUMS.sigstore.json from the same
release. In an operator-controlled directory, run:

```sh
python3 -I /trusted/AnonGuard/scripts/verify_release.py \
  --tag v0.2.0 \
  --artifact ./anonguard_0.2.0_amd64.deb \
  --manifest ./SHA256SUMS \
  --bundle ./SHA256SUMS.sigstore.json \
  --cosign /usr/local/bin/cosign \
  --policy /trusted/operator/release-policy.json \
  --staging ./verified-v0.2.0
```

Replace the example tag and package with an actually published release. The
staging directory must not exist. Its parent and the verified output must remain
under operator control; this tool cannot protect against a compromised host or
another process with the same user's privileges. The verifier copies bounded
regular inputs into a private directory, verifies the copied manifest with exact
workflow identity and GitHub Actions issuer, and hashes the copied package. It
does not install, extract or execute the package. Only install the staged copy
whose path is printed after successful verification. Never install the original
download after verification, since its bytes may have changed.

Verification failure removes the new staging directory and exits nonzero. There
is no unsigned fallback or option to bypass certificate identity/transparency
verification. Trust-root retrieval may require connectivity; missing trust data,
missing signatures and timeouts fail verification. Local unsigned lab builds need
an explicitly recorded build provenance and separate acceptance procedure; they
cannot pass this signed-release gate.

The exact tag is a required operator choice. With `--policy`, admission additionally
requires an operator-maintained minimum stable tag, exact approved artifact SHA-256,
and absence from the revoked-tag list. Without `--policy`, the verifier performs
signature/digest verification only and returns `release_admitted: false`; that is
not update approval. Neither mode installs or executes the package.

The policy is obtained through an independently authenticated operator channel,
not from the candidate download. It must be a regular file owned by root or the
current operator, not writable by group/others, and no larger than 64 KiB. Keep
its parent under operator control. The verifier privately snapshots it and reports
its SHA-256. Symlinks, FIFOs, duplicate JSON fields, unknown fields, ambiguous
versions, revoked/older releases and unapproved artifact bytes fail closed.

Policy schema (replace the placeholder with the actual independently approved
64-character lowercase artifact digest; this example intentionally cannot admit
an artifact as written):

```json
{
  "version": 1,
  "minimum_tag": "v0.2.0",
  "approved_releases": {
    "v0.2.0": {
      "anonguard_0.2.0_amd64.deb": "REPLACE_WITH_APPROVED_SHA256"
    }
  },
  "revoked_tags": []
}
```

Policy-controlled admission currently supports canonical stable semantic versions
only. Numeric comparison treats v0.10.0 as newer than v0.9.0. Prerelease artifacts
can be signature-verified without a policy but cannot pass this admission policy.
An approval cannot override publisher signature verification or rebind Debian
artifact filenames to a different release tag.

This is a local admission gate, not a complete secure updater or automatic
monotonic installation journal. It does not authenticate the policy itself,
prevent an administrator from restoring old policy/state, retrieve revocations,
verify installed state compatibility, or provide signing-key compromise recovery.
Operators must distribute fresh policy, raise the floor after accepted upgrades,
revoke affected tags/digests and preserve security state. Never select an old
release merely to bypass a failed upgrade. Apply the documented state compatibility
and incident policy before deployment.

The release workflow verifies actual freshly generated signature bundles before
publishing tagged assets. Local boundary tests stub Cosign to test orchestration;
they are not evidence of cryptographic signature verification. See the
[official signature verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/).

## Exact version and browser release gates

Tagged builds require the release tag to equal `v` followed by Cargo's package
version exactly. Before signing, Debian `Package`, `Version`, `Architecture` and
artifact filename must agree with that version. A `v0.2.0` signature cannot be
used to admit a package named `anonguard_0.1.0_amd64.deb`. Manual workflow builds
without a tag do not publish or pretend to pass tagged signing admission.

The release workflow now requires the reusable actual-Firefox integration gate
in addition to the Rust/privileged verification workflow and dependency audit.
That browser gate uses disposable profiles/fixtures and includes real local
pinned onion testnet browsing. It does **not** verify a Mozilla-signed production
addon or certify an operator-installed whole-device/browser combination.

The Linux transport archive includes native setup/adapter/browser helpers,
reviewable isolation-addon sources and native account/desktop examples alongside
the existing daemon/PT/headless tools. It is still an archive, not a system
installer: extracting it does not provision accounts, install browser policies,
activate firewall rules or create a signed addon. The Debian package provides
the corresponding fixed installed paths. Neither artifact supplies a signed
isolation XPI or a separately bundled Firefox engine.

## Explicit fail-closed upgrade recovery

Package replacement stops routing services. It preserves native firewall rules,
operator configuration and persistent security state; post-installation reloads
systemd but **does not automatically restart an unaccepted deployment**. A service
being stopped after upgrade is intentional fail-closed behavior, not successful
runtime recovery. Retain local-console access and keep protected applications
stopped until the upgraded installation has passed acceptance.

Before upgrading, authenticate the selected release, back up and protect paired
identity keys, authority votes, guard bindings, accepted consensus and retirement
journals. Upgrade all v6 participants together. Raw legacy Ed pins, old cell
formats and incompatible journals require a reviewed coordinated migration;
do not delete state to bypass refusal. Operator approval of a version is separate
from artifact-signature verification.

On an already configured native client, review the retained bootstrap pins and
units, then validate the firewall configuration from the device console:

```sh
sudo nft --check --file /etc/anonguard/native.nft
sudo systemctl daemon-reload
sudo systemctl restart anonguard-native-firewall.service
sudo systemctl start anonguard-client.service anonguard-native-adapter.service
systemctl is-active anonguard-native-firewall.service anonguard-client.service anonguard-native-adapter.service
anonguard-browser --native-client --circuit-isolation --check
```

These commands presume previously accepted role configuration, dedicated accounts
and a protected signed addon/browser setup. `--check` is preflight, not actual
packet/policy acceptance. Starting services alone does not prove usable quorum
or anonymity. Stop the affected transport/application and diagnose refusals;
**never remove the firewall to recover direct traffic**. Volunteer and standalone
roles require their own retained-unit review and explicit restart. System-wide
firewall activation can interrupt SSH; use the local console.

The disposable package lifecycle test now installs a distinct higher Debian
version and then the original version, checking real upgrade/downgrade maintainer
script paths and byte-for-byte persistence of a genuine paired identity and
opaque journal fixtures. The higher package is explicitly a synthetic version
of the same tested payload. This demonstrates lifecycle mechanics, **not**
safe rollback between different protocols or acceptance of those journal fixtures
by a daemon. Production downgrades still require operator-reviewed state and
vulnerability compatibility. Purge keeps security state; the disposable test
removes only state directories it created exclusively.
