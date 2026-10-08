# AnonGuard entry transport integration

## Scope

`--onion --bridge-transports /private/path/bridges.json` requires every gateway
first-hop connection to traverse a provisioned local SOCKS5 pluggable transport.
The adapter follows the PT v1 per-connection argument encoding. An independent
obfs4proxy process transforms the wire traffic; AnonGuard still performs its own
Ed25519-pinned TLS 1.3/ALPN authentication and hybrid onion handshake inside it.
Neither the Tor daemon nor the public Tor network is required.

For private entries, add `--private-bridges` and
`--authority-transports /private/path/authorities.json`. The client then uses an
independently provisioned entry absent from the public directory, followed by two
current quorum-certified public hops. Every configured authority must have a
transport binding to its exact pinned identity. There is no direct bootstrap
fallback and no local authority hostname lookup in this mode. Quorum, expiry,
rollback protection and authority handshake authentication are unchanged.

Run the entry backend with `--relay --unlisted-bridge --listen 127.0.0.1:9001`
and the normal pinned authority configuration. This enforces a loopback-only,
non-exit, onion-only backend and skips registration entirely. The bridge still
downloads a signed directory to validate its extensions. Relay/authority outbound
links retain their normal transport: the client protection does not conceal every
infrastructure connection or guarantee resistance to a particular country's censor.

## Binding and failure behavior

The JSON file is an array of one to three bindings:

```json
[
  {
    "identity": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
    "proxy": "127.0.0.1:31000",
    "bridge": "192.0.2.10:443",
    "arguments": {"cert": "REPLACE_WITH_REAL_SERVER_CERT", "iat-mode": "0"}
  }
]
```

These are placeholders, not working credentials. Replace `identity` with the
32 raw bytes of the independently verified entry relay Ed25519 pin, `proxy` with
the PT client's `CMETHOD obfs4 socks5` endpoint, and `bridge`/arguments with the
server's `SMETHOD` endpoint and `ARGS`. Never substitute the obfs4 certificate for
the AnonGuard identity pin: they authenticate different layers.

Use a mode-0600 file and dedicated guard-state path for this profile. In default
transport mode, the pin must match a current directory non-exit relay. In private
mode, obtain the unlisted entry pin through an independently authenticated channel;
it is an explicit local trust anchor. Missing entries, stale directory,
unavailable transport, changed guard pins, authentication downgrade, malformed
reply, TLS mismatch, and timeouts fail closed. They never trigger direct first-hop
fallback. A previous direct-mode guard state outside the provisioned allowlist also
fails closed; provision a separate profile rather than deleting guards repeatedly.

Only numeric bridge addresses and numeric loopback proxy endpoints are accepted.
No local bridge DNS lookup occurs. Arguments are escaped and bounded to 254 bytes;
unknown JSON fields, duplicate identities, zero pins and oversized files are rejected.
Configuration Debug output redacts transport bindings. Local PT socket access is a
trust boundary: deploy on a dedicated account/host and restrict untrusted local apps.

## External transport lifecycle

Use a trusted packaged transport binary with its original license/attribution.
The packaged `anonguard-pt` supervisor and `anonguard-pt@.service` manage an
operator-installed binary. No transport binary is downloaded or vendored. Install
`python3` and `obfs4proxy` from your distribution's trusted repositories separately.

Server PT v1 environment (substitute real paths/addresses):

```text
TOR_PT_MANAGED_TRANSPORT_VER=1
TOR_PT_STATE_LOCATION=/private/server-pt-state
TOR_PT_SERVER_TRANSPORTS=obfs4
TOR_PT_SERVER_BINDADDR=obfs4-PUBLIC_BIND_IP:443
TOR_PT_ORPORT=127.0.0.1:9001
TOR_PT_EXIT_ON_STDIN_CLOSE=1
```

Client environment:

```text
TOR_PT_MANAGED_TRANSPORT_VER=1
TOR_PT_STATE_LOCATION=/private/client-pt-state
TOR_PT_CLIENT_TRANSPORTS=obfs4
TOR_PT_EXIT_ON_STDIN_CLOSE=1
```

Keep PT stdin open, monitor its negotiated `VERSION 1`, requested method and final
`CMETHODS DONE`/`SMETHODS DONE`, and terminate on startup errors. Unset inherited
`TOR_PT_PROXY` and server-only/client-only variables appropriately. Do not set
`TOR_PT_EXTENDED_SERVER_PORT`: the backend is AnonGuard's raw TLS listener, not Tor's
extended ORPort protocol. Allow only the PT to access that backend where deployment
topology permits it. Unlisted bridge mode keeps this backend out of registration.
The PT terminates at the bridge, which necessarily sees the connecting client IP.

### Supervisor and systemd credentials

Place a root-owned private config at `/etc/anonguard/pt-client.json`:

```json
{
  "mode": "client",
  "binary": "/usr/bin/obfs4proxy",
  "bridges": ["REPLACE_WITH_BINDING_OBJECTS_WITHOUT_PROXY_FIELD"],
  "authorities": ["REPLACE_WITH_ONE_BINDING_OBJECT_PER_AUTHORITY_WITHOUT_PROXY_FIELD"]
}
```

Replace each placeholder string with a binding object from the earlier example,
omitting `proxy`: the supervisor fills the negotiated loopback address. This example
intentionally cannot start until real independently verified pins/certificates are
provided. Arrays contain 1..3 bridges and 1..16 authorities. The daemon additionally
requires an exact match to every configured authority; no partial direct bootstrap.

For a server instance, `/etc/anonguard/pt-server.json`:

```json
{"mode":"server","binary":"/usr/bin/obfs4proxy","listen":"0.0.0.0:8443","backend":"127.0.0.1:9001"}
```

Start `anonguard-pt@server.service` only after the unlisted relay backend is configured.
Distribute the resulting `/run/anonguard-pt-server/server.json` arguments privately,
substituting the reachable public IP for a wildcard bind address. NAT/firewall mapping
is an operator responsibility. The service has no capabilities and uses unprivileged
ports; port 443 requires an explicit administrator-controlled mapping.

The client service writes mode-0600 `bridges.json` and `authorities.json` under
`/run/anonguard-pt-client/` only after successful PT v1 initialization. It removes
these files on shutdown/crash, keeps stdin open, bounds startup/control output,
drains diagnostics without logging certificates, and terminates its child at exit.
systemd is notified only after both files are available. State is mode 0700 and
persistent; back it up securely to preserve obfs4 server identity.

For the packaged gateway, create a service drop-in with the following directives:

```ini
[Unit]
Requires=anonguard-pt@client.service
BindsTo=anonguard-pt@client.service
After=anonguard-pt@client.service

[Service]
LoadCredential=bridges.json:/run/anonguard-pt-client/bridges.json
LoadCredential=authorities.json:/run/anonguard-pt-client/authorities.json
ExecStart=
ExecStart=/usr/bin/anonguard-daemon --listen 127.0.0.1:9050 --onion --private-bridges --bridge-transports ${CREDENTIALS_DIRECTORY}/bridges.json --authority-transports ${CREDENTIALS_DIRECTORY}/authorities.json --identity-key-path /var/lib/anonguard/identity.key --guard-state-path /var/lib/anonguard/private-guards.json $ANONGUARD_ARGS
```

Retain independently verified authority arguments in `runtime.env`; do not add
file pools, tracker fetches, relay roles or direct transport flags to this profile.
The credentials mechanism lets distinct DynamicUser services share private files
without making them world-readable. After a PT restart, explicitly restart the
gateway so credentials contain the new SOCKS endpoint. No automatic circuit replay.
Do not enable the existing direct-relay firewall allowlist unchanged: a gateway
transport profile needs access to the local PT socket, and the separate PT process
needs access to the provisioned transport endpoints. Application isolation remains
a separate deployment requirement; this feature does not sandbox the user's apps.

## Verification

Normal tests cover escaping/bounds, mandatory RFC1929 negotiation, no direct
fallback, IPv4/IPv6 framing, byte preservation and entry-pin selection/cooldown.
The opt-in test uses a real transport binary:

```sh
ANONGUARD_OBFS4PROXY=/trusted/path/obfs4proxy cargo test --locked --test test_pluggable_transport -- --ignored
ANONGUARD_OBFS4PROXY=/trusted/path/obfs4proxy cargo test --locked --test test_daemon_testnet
ANONGUARD_TEST_PRIVATE_BRIDGES=1 ANONGUARD_OBFS4PROXY=/trusted/path/obfs4proxy cargo test --locked --test test_daemon_testnet
ANONGUARD_OBFS4PROXY=/trusted/path/obfs4proxy python3 scripts/test_pt_supervisor.py
```

The latter exercises the actual CLI gateway and existing multi-hop payload,
half-close and relay-loss assertions with an obfs4 first hop. Local interoperability
does not establish censorship resistance against a real country's filtering.

## Operational limits and release evidence

Bootstrap metadata must reach the user through a separate authenticated channel;
there is no automatic discovery service resistant to bridge enumeration. Address
prefix diversity cannot prove operator independence. Clients should retain the
small provisioned guard set, not rotate bridges after arbitrary downstream failures.

Real multi-network blocking/detection experiments, sustained resource measurement,
independent review, transport-aware application firewall deployment and the wider
production-readiness blockers remain necessary. A local obfs4 test is not proof of
Tor-level anonymity or protection against global traffic correlation.

Specification: https://torproject.gitlab.io/torspec/pt-spec.html (PT v1 architecture,
environment and section 3.5 argument encoding).
