# AnonGuard relay operations

AnonGuard is an experimental authenticated three-hop transport. Public anonymity, resistance to global traffic correlation and production reliability have not been independently established. The repository records no deployed independent operator network or core-team exit fleet.

## Roles and deployment

Guards and middle relays forward layered cells; exits connect to destination TCP services under the exit-address policy. Exits can observe destination metadata and application plaintext unless the application uses end-to-end encryption such as TLS. Relay roles alone do not eliminate traffic-correlation risk.

Provision a dedicated account/host, durable private identity storage and authenticated authority bootstrap. Initialize the identity without networking using `--initialize-identity --identity-key-path PRIVATE_PATH`. Start relays with `--relay`, a reachable numeric `--listen IP:PORT`, the private identity path and the shared authority endpoints, keys and quorum. Add `--is-exit` only for an explicitly operated exit. Use a reachable bound address, not an unspecified advertised endpoint. See [authority bootstrap](runbook_authority.md) and the actual CLI `--help`.

Keep normal proof of work and exit-address restrictions. Development switches permitting private exits or open SOCKS require explicit insecure-mode acknowledgment and are not production settings. Do not advertise unsupported onion services, multipath sessions or transparent transaction reconnects.

## Operational responsibilities

No validated universal hardware, bandwidth or uptime guarantee exists. Establish load-tested budgets and circuit-success targets for the intended deployment. Use real operator/subnet diversity, synchronized clocks and retained authenticated v3 state. Monitor CPU/memory/descriptors, relay availability, expired/divergent directories and dependency updates. Restrict metrics and diagnostic logs; never add payload, credential or browsing-history logging.

Retain operational diagnostics needed to investigate failures, protect their access, and define retention. The project does not promise that all current runtime metadata is absent from logs. Keep client gateway ports private and set service/cgroup limits. Rehearse restart, upgrade, rollback rejection and compromised-key response before public service.

Exit operation requires named ownership, abuse handling and jurisdiction-specific assessment. No universal safe-harbor status or project-operated abuse contact/template system is established here. Establish those arrangements directly before accepting public exit traffic.

Use [identity replacement](key_rotation.md), [Linux deployment](../deploy/README.md), and [production readiness](PRODUCTION_READINESS.md). Platform compilation and passing CI do not establish a public-network safety claim.
