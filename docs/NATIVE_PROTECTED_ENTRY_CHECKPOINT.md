# Native protected entry engineering checkpoint

Date: 16 October 2026. Status: code integration with focused local verification;
full VM/installed acceptance is deferred. This is not public anonymity approval.

## Why existing defenses did not establish anonymity

Encryption protects content, while timing, connection boundaries, volume,
congestion and both-end observations can remain informative. In particular,
direct client TLS exposes an AnonGuard ALPN marker. Padding does not remove that
marker. The previous 72-capture single-VM pilot measured a bandwidth/latency
tradeoff and mixed classifiers, not realistic adaptive resistance. Public relay
population and operator independence are not created by changing source code.

## Delivered integration

- Native client setup requires an authenticated, private obfs4 config and its
  independent digest, or explicit `--direct-entry-lab`. It refuses an unspecified
  policy before creating output or applying host changes.
- Exact authority-pin coverage, canonical numeric IPv4 endpoints, binding/count/
  argument limits, private ownership/permissions and no-symlink reads are checked.
  The administrator still authenticates the actual pins and transport certificates.
- A dedicated `anonguard-native-pt.service` owns the PT process group under
  `anonguard-pt-native`. It announces READY through the existing supervisor before
  the gateway loads private runtime bindings with systemd credentials.
- Native gateway arguments require protected private entry, authenticated
  authority bootstrap, padded sessions and the selected link/session profiles.
- Protected nftables output limits the gateway UID to loopback TCP and the PT
  UID to provisioned outer address/port pairs plus established loopback replies.
  PT traffic bypasses redirect rules, avoiding a proxy routing loop. Ordinary
  application output is still restricted; no general established-output exception
  is introduced. The namespace fixture's direct policy is explicitly a lab path.
- BindsTo/PartOf and ordering bind the gateway to PT lifetime/restart. The normal
  native browser refuses direct-lab or old profiles without protected policy and
  checks the PT unit alongside firewall/gateway/adapter. No transaction replay.
- Optional economy links and balanced-longtail sessions can be selected through
  setup and are recorded in public policy metadata. Defaults remain strict links
  and balanced sessions; all relay link profiles must match.

## Verification scope

Focused local setup/adapter (20), browser-policy (13), supervisor (2) and extension
packaging (2) checks passed: 37 executed, zero failures. One opt-in real-obfs4
supervisor check was skipped and is not counted as executed. Python syntax,
diff whitespace and unsigned lab package generation also passed. Rust source and
the daemon binary are unchanged by this integration. Systemd dependency parsing requires local socket metadata outside
the default sandbox; it does not activate services or install a firewall.
The first sandbox-only unit-parser attempt was denied socket options; rerunning
with explicit local permission passed. A real-obfs4 opt-in supervisor test is not
counted as executed in this checkpoint. Prior Rust/VM totals describe their own
revision, not fresh validation of these Python/systemd/firewall changes.

## Remaining engineering and external work

Code for signed extension input and release verification exists, but actual
maintained-browser addon signing, authenticated production release identities,
update/recovery acceptance and operator trust ceremonies are not supplied by a
local unsigned package. Existing installations still require reviewed migration;
this setup refuses configuration/state overwrite rather than inventing continuity.

Private onion services and reverse onion-relay transport are not implemented.
They are separate features, not prerequisites to the ordinary TCP exit use case.
Automatic recovery and overload behavior must be evaluated before further policy
changes. Optimal defense selection requires representative independent traffic;
changing defaults without that evidence would not close the security gap.

Next acceptance: actual obfs4 plus generated nftables, PT stop/crash/restart and
credential refresh, gateway denial of direct external TCP, ordinary-user denial
of the PT SOCKS endpoint, allowed outer endpoints only, boot/network changes,
browser missing-extension refusal, and complete real-relay traffic captures.
No host-wide firewall or VM service was changed for this checkpoint.
