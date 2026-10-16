# Native recovery hardening — 16 October 2026

Threat: TM-005 in the maintained threat model. This patch changes generated
services; it does not establish installed-device acceptance.

The adapter already used `BindsTo=anonguard-client.service` to stop when the
client disappears. It now additionally uses `PartOf=anonguard-client.service`,
so explicit stop/restart transactions propagate to the adapter. Its existing
`After=` ordering starts it after the client and stops it before the client.
The client already wants the adapter. No automatic restart guarantee is added
for a dependency failure that systemd treats as a deliberate stop.

Generated client/relay and adapter units now explicitly set `TimeoutStopSec=5`
and `KillMode=control-group`, matching the bounded stop policy already used by
the native PT. This can terminate pending application streams; there is no replay.
The firewall has no removal-on-stop command. PT pinning, protected credentials,
endpoint allowlists and gateway loopback-only output are unchanged.

Verification in the restricted local environment:

- 18 socket-independent native contract checks passed, including the new
  client/adapter dependency and bounded-stop regression for protected/direct-lab modes.
- 13 browser-session, two browser-extension and two offline PT-supervisor checks passed.
- The real-obfs4 supervisor case was skipped because its opt-in binary variable
  was not configured in this local run.
- The complete native command did not pass: systemd verification could not create
  SO_PASSCRED/SO_PASSRIGHTS sockets, and loopback socket creation was prohibited
  by the execution sandbox. These are retained as blocked checks, not green tests.
- Python compilation and whitespace checks passed.

Subsequent Ubuntu VM verification of these changes:

- All 21 native tests passed, including real loopback and generated systemd parser checks.
- The generated-service lifecycle fixture passed twice, including its final
  race-safe readiness predicates. It retained generated dependency edges and
  stop/restart settings while replacing commands, users and paths with UUID-scoped
  synthetic services. It verified adapter restart on explicit gateway restart,
  dependent shutdown after PT SIGKILL, fresh coherent credentials after recovery,
  and explicit PT restart propagation through client and adapter.
- The firewall service was a no-op fixture. These results establish systemd
  dependency behavior, not actual native daemon/obfs4/firewall composition. The
  separate real-obfs4, real onion/Firefox and kernel egress fixtures remain
  complementary evidence, not interchangeable with that missing composed test.
- The fixture is now included in CI with explicit disposable-root opt-in.

Required next acceptance: the complete generated native deployment with actual
PT/client/adapter and nftables, existing-stream closure, reboot/network changes
and retained firewall rules. Apply generated-unit changes only through reviewed
configuration migration, not by overwriting operator state.
