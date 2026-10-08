# Practical Linux FYP delivery

Scope: an independent authenticated three-hop implementation, evaluated on an
owned network. Target Ubuntu 24.04 LTS on x86_64 laptops. No additional mix-network
redesign is part of this delivery. A completed lab acceptance is evidence for the
tested configuration, not public anonymity certification.

## Prepare the machines

Use four authority hosts, three relay hosts (one exit), one client/gateway, one
owned destination and one monitoring host. An eleventh machine can be a spare.
Independent machines on the same LAN do not establish independent operators or
geographic diversity. Use real routed subnet separation for the default diversity
checks. If a lab explicitly relaxes a restriction, record it and retain the normal
defaults in the distributed package.

Record distribution, kernel, CPU/RAM, role, numeric address, ports, daemon commit
and artifact SHA-256 in a public lab inventory. Keep private keys, credentials,
raw traffic captures and private state outside Git and the presentation bundle.
Synchronize clocks and allow only the required role ports. Keep the gateway's
SOCKS listener local.

Install the Debian package built for the machine's architecture and runtime
libraries. Install optional containment prerequisites only on the relevant hosts:

```sh
sudo apt-get install iproute2 nftables bubblewrap python3 libseccomp2 util-linux
python3 /usr/share/doc/anonguard/deployment_preflight.py --profile gateway
python3 /usr/share/doc/anonguard/deployment_preflight.py --profile headless
```

The preflight inventories prerequisites without changing configuration or opening
network connections. Its success does not test namespaces, pins, clock accuracy
or application compatibility. The gateway profile does not contain applications.

Initialize distinct identities and authenticate the resulting public keys using
[authority bootstrap](runbook_authority.md). Configure four authority pins with
threshold three. Start authorities, then relays using the [relay guide](RELAY_OPERATOR_GUIDE.md),
then the gateway using [deployment instructions](../deploy/README.md). Preserve
vote, directory and guard state through restarts. Readiness requires a matching,
fresh certified directory, not simply an open listener.

An owned private-address destination requires an explicitly acknowledged lab exit
exception. Record that exception; do not distribute it as a production default.
The repository CLI process test is a separate disposable regression fixture with
zero-cost proof of work and private exits; it is not the multi-machine acceptance.

## Resource budgets

The packaged gateway starts with MemoryHigh=768M, MemoryMax=1G, MemorySwapMax=0,
TasksMax=256, CPUQuota=200%, LimitNOFILE=4096 and disabled core dumps. These are
initial laptop limits, not measured capacity guarantees. Inspect enforcement with:

```sh
systemctl show anonguard.service -p MemoryHigh -p MemoryMax -p MemorySwapMax \
  -p TasksMax -p CPUQuotaPerSecUSec -p LimitNOFILE
systemctl status anonguard.service
```

Measure peak usage and failed requests before tuning. Use a systemd drop-in for
changes. Separately launched applications need their own administrative cgroup
budgets; daemon limits do not extend to them. Follow [headless containment](LINUX_APP_CONTAINMENT.md)
for the dedicated rootfs, namespace and UID requirements. Do not pass a host home
directory, enable GUI brokers or forward inherited descriptors to make an app work.
The current headless profile discards standard output and provides no persistent
application output storage; demonstrate completion through the owned destination
and test assertions. Do not present it as a general protected browser.

## Acceptance record

For every row record commit, command/procedure, expected result, observed result,
timestamp and evidence file. Mark not-run cases explicitly. Have the second team
member reproduce installation and the critical failure tests independently.

| Case | Required observation |
|---|---|
| Clean install | Configuration required before start; private local gateway listener |
| Routing | Owned destination receives a complete request/response through three relays |
| Half-close | Response completes after the client finishes sending |
| Incorrect authority or relay pin | Authentication fails; no plaintext fallback |
| Missing/expired quorum | New circuits refuse construction |
| Relay loss | Affected stream closes; no direct destination fallback |
| Restart | Identity, guards and rollback state survive; new valid circuits work |
| Headless isolation | Direct IPv4/IPv6, DNS, UDP and host IPC probes blocked as specified |
| Helper crash | Protected application cannot regain host connectivity |
| Upgrade/remove/reinstall | Configuration preservation and state recovery verified |
| Load | Bounded resource use, recorded throughput and failure rate |

Use authorized synthetic traffic only. Capturing other people's traffic is not
needed. Re-run a failed case after fixing it and preserve the original failure.

## Measurements and examiner demonstration

Repeat identical owned workloads over direct access and AnonGuard; optionally add
a fair Tor baseline with equivalent isolation. Record sample count, latency
percentiles, useful throughput, total bytes, CPU/RSS and failures. Distinguish
transport performance from correlation-attack evaluation. Report costs as well as
benefits; padding entropy is not an anonymity metric.

Demonstrate, in order: topology and threat assumptions; authenticated startup;
successful transfer; blocked bypass attempt; relay/helper failure; recovery with
preserved state; measurements and limitations. Use no real secrets or personal
browsing during the presentation.

Deliver the exact source commit, package and checksums, installation guide,
inventory, completed acceptance record, measurements, architecture/threat model
and walkthrough. Label local unsigned artifacts as unsigned. Signed release
claims require actual signature verification. Freeze the demonstrated version
after acceptance and keep a tested fallback installation for the presentation.

The remaining wider-release gates are tracked in [production readiness](PRODUCTION_READINESS.md).
Passing this checklist does not establish superiority to Tor or safety against
a global observer or a compromised user host.

## Repeatable HTTP measurements

Install curl from the OS repository. Use only an owned endpoint. The measurement
script requires an explicit target and never contacts a default external service.
Replace OWNED_HOST with your destination; use a fixed response body:

```sh
python3 /usr/share/doc/anonguard/latency_profile.py --url http://OWNED_HOST:8080/payload --requests 20 > direct.json
python3 /usr/share/doc/anonguard/latency_profile.py --url http://OWNED_HOST:8080/payload --proxy socks5h://127.0.0.1:9050 --requests 20 > anonguard.json
```

SOCKS mode resolves destination names remotely and does not fall back to direct
access. Each trial starts a fresh curl process; results include connection setup.
The JSON records all failures and successful-trial latency percentiles (nearest
rank). Any failed request produces exit status 1 while retaining the report.
Downloaded bytes are application body bytes, not network overhead. Measure wire
traffic, CPU and RSS separately. This script runs on the measurement host; it does
not itself establish application containment or traffic-analysis resistance.
