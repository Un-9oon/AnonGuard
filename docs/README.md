# AnonGuard documentation

Start with [practical FYP delivery](FYP_DELIVERY.md), [Linux deployment](../deploy/README.md),
[authority bootstrap](runbook_authority.md), [relay operations](RELAY_OPERATOR_GUIDE.md)
and [headless application containment](LINUX_APP_CONTAINMENT.md).

The current normative protocol is [v3](PROTOCOL_V3.md). Historical reports and
research descriptions may describe earlier behavior; use the v3 specification,
current source and [readiness gates](PRODUCTION_READINESS.md) for release claims.

## Artifact provenance

The tagged release workflow is configured to build with cargo-auditable, generate
SHA256SUMS and sign archives, Debian packages and the manifest using Sigstore.
That configuration alone does not establish that a release ran or that a specific
artifact contains an SBOM or a valid signature. Ordinary local cargo builds and
local FYP bundles may be unsigned and lack embedded dependency metadata.

For a tagged release, obtain the artifact and its matching `.sigstore.json` bundle.
Verify using a trusted cosign installation, the exact release tag and the expected
repository workflow identity. Replace VERSION with the authenticated tag:

```sh
cosign verify-blob \
  --bundle anonguard-linux-amd64.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/Un-9oon/AnonGuard/.github/workflows/release.yml@refs/tags/VERSION" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  anonguard-linux-amd64.tar.gz
```

Verify SHA256SUMS with its corresponding signature in the same way before using
it to check the extracted release artifacts. A checksum from an unauthenticated
source detects accidental corruption but does not prove origin. Run checksum
verification in a dedicated release directory containing the listed files:

```sh
sha256sum -c SHA256SUMS
```

If no signature bundle exists, record the build as unsigned instead of claiming
signed provenance. Record the source commit, build toolchain and dependency lock
file. Embedded dependency metadata, when present, supports inventory and known
advisory analysis; it is not an independent cryptographic or anonymity review.
