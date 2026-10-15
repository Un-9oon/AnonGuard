# Evidence-led anonymity engineering

Research checkpoint: 2026-10-15. Target: the existing Linux AnonGuard onion-routing
implementation, not a replacement mix network. This document separates sourced
results, engineering choices and unverified acceptance. No reviewed source
establishes an undefeatable technique or a universally optimal security/latency/
bandwidth combination. We must choose under an explicit observer and resource
budget, then measure the actual implementation.

## What the research changes about our approach

An observer watching both ends remains a serious limitation for practical
low-latency onion routing. Tor explicitly documents this boundary. Adding more
random hops or an unpredictable delay generator does not remove it. We preserve
persistent guard behavior and protocol authentication rather than claiming that
more randomness is automatically safer. [Tor attack limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/),
[guard specification](https://spec.torproject.org/guard-spec/).

FRONT and RegulaTor are useful candidate comparisons because their publications
measure traffic-shaping defenses and their costs. We should not transfer their
published results to AnonGuard: our cells, link cover, congestion, TCP behavior,
session reuse and anonymity population differ. Robust Fingerprinting demonstrates
why a classifier that fails against one representation is insufficient evidence
against adaptive attacks. [FRONT](https://www.usenix.org/conference/usenixsecurity20/presentation/gong),
[RegulaTor](https://petsymposium.org/popets/2022/popets-2022-0049.php),
[Robust Fingerprinting](https://www.usenix.org/system/files/usenixsecurity23-shen-meng.pdf).

The 2026 PoPETs work on ephemeral network-layer defenses is a relevant additional
candidate: it studies tunable per-connection defense generation and reports
integration/deployment in a VPN setting. We should evaluate its maintained
artifact against the existing common profiles under matched resource budgets,
not copy its deployment claims to onion circuits. The 2026 MMF multi-tab attack
also makes single-label, one-tab-only evaluation insufficient for a browser
product. Neither system is implemented or evaluated in this batch.
[Ephemeral defenses](https://crysp.petsymposium.org/popets/2026/popets-2026-0022.php),
[few-shot multi-tab fingerprinting](https://www.usenix.org/conference/usenixsecurity26/presentation/liu-lin).

Loopix combines cover traffic with a mixing architecture and corresponding
analysis. We cannot obtain that system's properties by copying its Poisson delay
sampler into an onion stream. A switch to that architecture would change the
product and require separate protocol, reliability and evaluation work. The
user's existing onion-routing scope remains our constraint.
[Loopix](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska).

## Gap-to-technique decisions

| Boundary | Selected engineering direction under current scope | Proof still required |
| --- | --- | --- |
| Timing/volume | Retain current bounded covered links and common session profiles as candidates; compare fixed pacing against separately implemented research baselines at matched latency/wire budgets before changing defaults | Defense-aware timing/direction/size attacks, adaptive models, end-to-end correlation and independent collection |
| Session duration | Measure fixed observation windows, idle/tail traffic and complete session lifetimes separately; do not stop captures at response completion and call the result protected | Session start/stop correlation, failures and workload exclusions; no unbounded padding promise |
| Fingerprinting evaluation | Separate collection-group train/validation/test partitions, frozen threshold, unseen background sites, base-rate-aware false positives and uncertainty | Large real packet datasets, established deep attacks, temporal/device/network drift, independent confirmation |
| Sybil/path compromise | Keep mandatory node ownership, signed quorum admission, persistent guards and diversity checks; treat operator independence separately from key count and prefix diversity | Operator enrollment/independence evidence, coordinated malicious-node tests, path-bias and churn analysis |
| Linux application leaks | Preserve fail-closed namespace/rootfs/syscall/firewall boundaries and explicit OS prerequisite checks | Composed real-relay boot/restart/network-change/pre-existing-socket/IPC acceptance |
| Browser identity | Maintain a common supported browser build/configuration with first-party circuit isolation and signed addon delivery; avoid arbitrary per-user spoofing knobs | Cross-device fingerprint consistency, actual release-browser integration and maintained vendor updates |
| Cryptographic assurance | Keep standardized ML-KEM/ML-DSA primitives with current hybrid transcript/pin checks; extend inventory, independent vectors and failure/retirement exercises | Independent composition review, complete key-compromise/migration validation; algorithm support is not certification |
| Availability | Layer bounded concurrency, handshake start rates, finite queues, deadlines, fair admission and service cgroups; measure at saturation | Per-source fairness, distributed floods, CPU/RAM/wire ceilings and recovery; attacker throttling must not silently disable privacy |
| Distribution | Keep authenticated artifact admission, then use a maintained rollback/freeze-resistant update framework with delegated/threshold roles and offline recovery keys | Real operator keys, expiry/version persistence, compromised-key and interrupted-update exercises |
| Public deployment | Establish independently operated relays and authorities, authenticated bootstrap and transparent operational policies | Diverse real networks and a genuine user population; these cannot be manufactured by a code change |
| Private services | Separate rendezvous/service-side-IP-hiding protocol work from ordinary exit browsing | Not implemented; adding a reverse SOCKS tunnel does not implement onion services |

These are conditional engineering recommendations, not a claim that any individual
technique closes the associated threat by itself.

Browser uniformity and isolation are motivated by the Tor Project's published
fingerprinting approach. Mozilla signing is an external distribution requirement;
we must not bypass it and label the result a normal release.
[Tor Browser protections](https://support.torproject.org/tor-browser/features/fingerprinting-protections/),
[Mozilla signing](https://www.extensionworkshop.com/documentation/publish/signing-and-distribution-overview/).

For updates, The Update Framework provides specified version/expiry and role
checks against rollback/freeze and related attacks. This is a selected direction,
not an assertion that AnonGuard already implements TUF. Cryptographic inventory
and migration should follow maintained standards while retaining strict version
and downgrade boundaries. [TUF specification](https://theupdateframework.github.io/specification/v1.0.36/),
[NIST ML-KEM](https://csrc.nist.gov/pubs/fips/203/final),
[NIST ML-DSA](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).

## Implemented research-enabling changes in this batch

`eval/evaluate_open_world.py` is an additional, standard-library-only attack
baseline. We fit feature scaling on monitored training visits, select the rejection
threshold on separate validation data and evaluate on held-out visits/background
sites. The output keeps wrong monitored labels distinct from background false
alarms, includes uncertainty and reports assumed-prevalence precision. It refuses
incomplete capture inventories, missing source-PCAP hashes, reused captures across
partitions and unassigned/overlapping collection groups. Synthetic input is an
explicit testing mode; a synthetic accuracy result is not an AnonGuard result.

`eval/capture_owned_testnet.py` now hashes retained source PCAPs. The existing small
three-workload collector is still a closed-world pilot: its current datasets do
not magically become a sufficiently diverse open-world dataset. We need additional
owned background workloads and independent collections before using the new
baseline for product claims. The existing link-correlation baseline also now
excludes fractional negative offsets before integer binning.

This work improves the evidence pipeline and catches misleading evaluation. It
has not changed the live traffic shaper, established an anonymity improvement,
implemented private services, issued browser signatures, obtained an independent
audit or recruited independent relay operators. Deployment must continue to use
the explicit gates in [LINUX_RELEASE_GATES.md](LINUX_RELEASE_GATES.md).

## Next implementation order and acceptance

1. Run the candidate on the supported installed Linux system with real relays and
   record failures instead of reclassifying isolated SOCKS fixtures as integration.
2. Add and validate per-source fair admission/resource measurements around the
   existing global tracker budgets, then test slow peers and sustained churn.
3. Collect owned monitored/background workloads with explicit independent groups,
   source-PCAP hashes, matched profiles/windows and failed-visit accounting.
4. Run this baseline and established defense-aware attacks. Optimize profiles on
   validation measurements only; freeze the choice before confirmation collection.
   Report the Pareto trade-off in attack success, latency and actual wire cost.
5. Complete actual signed-browser/update delivery and compromise-recovery drills.
6. Submit the protocol and evidence to independent reviewers; address their
   findings before making public production anonymity claims.

A changed threat model or measured failure can change this order. Neither a low
classifier score nor passing functional tests eliminates endpoint compromise,
account identity, malicious exits, population limitations or global observation.
