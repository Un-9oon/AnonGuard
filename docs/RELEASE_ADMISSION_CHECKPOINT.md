# Operator release-admission checkpoint

This changes the installed-artifact trust boundary (TM-008), not routing,
traffic-analysis protection or signing-key recovery.

`scripts/verify_release.py --policy FILE` now admits only artifacts satisfying
both existing publisher-signature/digest verification and an independently
trusted operator policy. The policy fixes a minimum stable semantic version,
exact approved tag/artifact digests and revoked tags. Missing approval, older
versions, revocation or changed bytes refuse admission and remove the new staging
directory. There is no signature-bypass or downgrade-override flag.

No-policy use remains useful to inspect signed artifacts, but explicitly returns
`release_admitted: false`. Policy approval returns `release_admitted: true` and
`deployment_accepted: false`: this does not install the artifact or certify its
runtime security. The policy snapshot's SHA-256 is included for provenance.

Input constraints: bounded regular policy file, no final symlink/FIFO, owner
root/current operator, no group/other write permission, exact schema, bounded
approval/revocation lists, canonical stable versions and no duplicate JSON keys.
Prereleases are excluded from policy admission. Parent directories and the
operator's policy-distribution channel must be trusted.

Validation: 15 verifier tests passed locally and on Ubuntu 24.04; two version
agreement tests passed locally. Cases cover signed-but-revoked/old/unapproved or
modified artifacts, policy snapshots, permissions/types/size, duplicate keys,
numeric ordering, and publisher-verification failure despite operator approval.
The Cosign test executable is a stub: these are orchestration/admission tests,
not new real signing/transparency verification evidence.

Initial local tests exposed the test environment's group-writable umask; valid
fixture policies now explicitly use mode 0600. The verifier's permission check
was retained. Existing CI already runs the verifier tests.

Remaining: independently maintained signing and policy channels, fresh revocation
delivery, a monotonic accepted-installation journal, compatibility/compromise
recovery, actual signed-browser delivery and composed installed-device acceptance.
An administrator can restore old policy/state; this gate alone cannot prevent it.
Do not describe this checkpoint as a complete secure updater or public-anonymity
approval. Native real PT/client/firewall composition remains a separate open task;
no composed native test was completed in this checkpoint.
