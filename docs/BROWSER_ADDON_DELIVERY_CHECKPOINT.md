# Pinned addon delivery — 17 October 2026

Runtime additions in `scripts/browser_session.py` provide root-only explicit XPI
installation, authenticated operator digest/version pinning, previous-artifact
confirmation for replacement, canonical numeric addon version comparison and
same-version replacement/downgrade refusal. The supported manifest schema and CSP
are exact: added content-script surfaces, addon update URLs and weakened CSP
are refused. Firefox must be stopped. Existing
browser profiles and vendor policies are not overwritten.

A receipt records the exact installed digest and version. Both the normal
isolated launcher and installed offline acceptance checker now refuse an
incoherent or missing receipt. The receipt deliberately records
`signature_verified: false` and `browser_accepted: false`. Mozilla signature
validation remains Firefox's responsibility; the operator's authenticated digest
is a separate delivery control. No signature enforcement is disabled.

Publication uses a nonblocking kernel lock and fsynced atomic replacement of the
XPI followed by the receipt. Interruption between them leaves a launcher-refused
mismatch; it is not a multi-file atomic transaction or automatic rollback.
Administrator or full-disk compromise is outside this boundary. Keep coherent
backups for reviewed recovery.

Debian and Linux archive packaging now include `anonguard-check-browser`. Its
module loader supports the installed extensionless browser helper, fixing the
source-only import assumption. Source and installed helper behavior must remain
covered by regression/package checks.

Tests use deliberately fake Mozilla signature members and never claim signature
authenticity. They exercise pinned installation, upgrade, refused downgrade,
previous-digest requirements, unsafe paths, interrupted receipt publication,
lock contention and mismatch refusal. Existing Firefox fixture tests remain
separate from actual signed-addon distribution acceptance.

Outstanding: supply an actual approved Mozilla-signed XPI through the project's
signing account; run the installed managed browser acceptance with that artifact;
maintain supported Firefox policy/fingerprint consistency and composed native
real-relay boot/restart/network-change acceptance. These changes do not close
public anonymity or adaptive traffic-analysis gates.

Validation: seven addon-delivery, 13 session, two extension-packaging and 21 native
contract tests passed on Ubuntu, plus one actual Firefox isolation and two loaded
policy tests: 46 checks across six suites. Local delivery/session/extension tests
also passed. The native command in the restricted local sandbox could not run
its socket/systemd checks; its complete 21-test VM run passed instead. A temporary
rebuilt Debian package was hash-checked, installed, exercised through the new
checker --help/module-loader and installer --help, then purged. No XPI was
installed and no production Firefox/vendor policy was modified. The first tested
package SHA-256 was
`a04d3de8f8f458f033689939d7b4096400a04f68fdfc9d11c2197a5b7ba9607b`;
subsequent builds, including stricter manifest validation, have their own lab
provenance digest and are not relabelled as that installed package.
