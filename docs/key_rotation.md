# Relay identity replacement and decommissioning

Identity replacement is a coordinated operational migration, not an automatic reputation warm-up. No uptime/bandwidth reputation ramp or in-band cryptographic revocation protocol is implemented.

1. Inventory the relay's signed identity, advertised endpoint, pinned guards and operator dependencies. Plan an outage and replacement circuit capacity.
2. Stop the affected relay, preserve restricted identity/state evidence where appropriate, and repair or replace a compromised host before provisioning a new identity.
3. Initialize a distinct protected replacement key with `anonguard-daemon --initialize-identity --identity-key-path NEW_PRIVATE_PATH`. Authenticate its public pin out of band. Do not overwrite an active identity file.
4. Coordinate descriptor/endpoint and guard changes with network operators. Authorities reject conflicting identities for an existing relay identifier or endpoint, and frozen snapshots do not change in place. A new key at the same endpoint cannot be assumed to replace old directory entries immediately; existing registration retention and voting epochs apply.
5. Demonstrate new pinned transport, valid proof of work, fresh quorum directories, guard behavior and usable circuits in an isolated testnet before restoring service.
6. Rehearse old-key rejection, state recovery and operator incident response. Preserve client rollback protections and document any explicit guard migration.

A runtime authority blacklist command is not implemented. A compromise therefore needs coordinated bootstrap/directory policy changes; merely restarting with a new key does not revoke distributed old descriptors or existing pins. Reviewed revocation and rotation remain production gates. See [authority replacement](key_rotation_runbook.md) and [production readiness](PRODUCTION_READINESS.md).
