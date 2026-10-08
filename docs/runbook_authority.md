# Authenticated v3 authority bootstrap

This is an experimental deployment procedure. The daemon does not implement `--init-authority`, `--key-path`, `--role tracker`, `--bind`, HTTP tracker APIs, or a `network_config.json` loader. Use the actual pinned v3 CLI below.

## Provisioning and trust

Provision independent operators and reachable authority endpoints. Four authorities with threshold three tolerate one unavailable authority under the configured greater-than-two-thirds rule; three authorities require all three signatures. Independence and endpoint reachability must be demonstrated by operators, not assumed from a host count. Authorities use authenticated TLS over TCP, not HTTP. Open only the explicitly configured authority/relay ports; keep client SOCKS and metrics listeners private.

## Prepare identity without opening a listener

Under the dedicated operator account, create private state storage and initialize each distinct authority identity:

```sh
install -d -m 700 /var/lib/anonguard-authority
anonguard-daemon --initialize-identity \
  --identity-key-path /var/lib/anonguard-authority/identity.key
```

The command prints JSON containing `public_key_ed25519` and exits without network startup. Repeating it validates and preserves the existing key. Corrupt or insecure key files are refused. Authenticate the public key and endpoint out of band to every operator/client. Never distribute the private 32-byte seed. Protect backups and retain the associated vote journal after voting begins.

## Configure and start

Define `AUTH_ENDPOINTS` as comma-separated `AUTH_ID@NUMERIC_IP:PORT` entries and `AUTH_KEYS` as matching `AUTH_ID:64_HEX_PUBLIC_KEY` entries, with four distinct identities/keys. Every participant must use the same authenticated bootstrap configuration. These are shell variables used to build actual CLI arguments, not a separate file format.

On each authority, replace `AUTH_ID` and `AUTH_LISTEN_IP:PORT` with its identity and reachable numeric bind endpoint:

```sh
anonguard-daemon --authority --authority-id AUTH_ID \
  --listen AUTH_LISTEN_IP:PORT \
  --identity-key-path /var/lib/anonguard-authority/identity.key \
  --authorities "$AUTH_ENDPOINTS" --authority-keys "$AUTH_KEYS" \
  --quorum-threshold 3
```

Each authority's own bootstrap pin must match its key. Real relay registration requires authenticated pinned links and normal proof of work. Admit at least three signed relays, including an exit, before expecting usable snapshots. Persistent authorities defer unusable snapshots. Use relays from distinct real subnet/operator failure domains for the enforced circuit-diversity policy.

Start a local gateway with the same endpoints/pins/threshold, `--onion`, `--enforce-subnet-diversity`, and private persistent identity/guard state. Do not use zero-difficulty proof of work, private exits or unauthenticated registration outside a disposable testnet.

## Acceptance and recovery

Verify pinned connections, matching fresh quorum snapshots, real three-hop traffic, response half-close, restarts preserving identity/votes, rollback rejection, clock changes, partitions and stale directories. Divergent already-frozen authority views can stall until another epoch; this is not a complete asynchronous BFT liveness protocol. Record actual observed results before deployment approval.

For replacement/compromise, follow [the authority key runbook](key_rotation_runbook.md). There is no automatic overlap, HSM integration, in-band revocation, or guaranteed zero-downtime rotation. Never erase client rollback state or authority journals merely to force convergence.
