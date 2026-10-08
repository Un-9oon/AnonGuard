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

The exact tag is a required operator choice. This tool does not decide whether a
tag is current, approved or revoked, and does not yet implement release rollback
prevention. Never select an old release merely to bypass a failed upgrade. Apply
the documented state compatibility and incident policy before deployment.

The release workflow verifies actual freshly generated signature bundles before
publishing tagged assets. Local boundary tests stub Cosign to test orchestration;
they are not evidence of cryptographic signature verification. See the
[official signature verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/).
