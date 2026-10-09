# Linux deployment

For separate gateway/application VMs, the [two-VM SOCKS-only profile](../docs/VM_SEPARATION.md)
provides an offline configuration generator and installation/acceptance procedure.
It does not configure a hardened browser and has not passed live VM acceptance.

AnonGuard remains experimental. Read [production readiness](../docs/PRODUCTION_READINESS.md) and [the relay operator guide](../docs/RELAY_OPERATOR_GUIDE.md) before deployment. Native installation does not establish fingerprint indistinguishability or anonymity.

Prefer the Debian package for a local gateway service. It installs the daemon, headless launcher, DynamicUser service, and `/etc/anonguard/runtime.env`. Configure real authority endpoints, pinned keys and quorum before starting. Installation does not automatically start an unconfigured service. Preserve identity, vote, guard and accepted-directory state during upgrades; do not rotate identities merely to repair connectivity.

`deploy/anonguard.service` is an alternate manually configured relay template. Install the daemon at `/usr/local/bin/anonguard-daemon`, create its dedicated account, and add the required authority/identity arguments from the operator guide. Its default command alone is not a complete working deployment. Retain diagnostics and restrict journal/metrics access. Do not expose an unauthenticated gateway publicly.

Application isolation is a separate administrative mode. See [the headless launcher](../docs/LINUX_APP_CONTAINMENT.md) for rootfs, identity, proxy and kernel requirements. The packaged service does not grant itself namespace privileges. Service teardown does not delete host nftables tables. Stop protected applications before explicit namespace cleanup.

Before public use, run exact-release checks, rehearse state recovery, verify live kernel boundaries and record sustained multi-region reliability/traffic-analysis evidence. Set explicit cgroup budgets for memory, CPU and processes. Configure time synchronization, monitor authority disagreement/expiry, and establish operator ownership and incident response. A clean build or running service is insufficient evidence.

For the current Linux FYP acceptance and examiner walkthrough, use [FYP delivery](../docs/FYP_DELIVERY.md). The package includes a read-only prerequisite inventory at `/usr/share/doc/anonguard/deployment_preflight.py`; it does not certify live isolation.
