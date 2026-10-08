# AnonGuard entry transport integration

## Scope

`--onion --bridge-transports /private/path/bridges.json` requires every gateway
first-hop connection to traverse a provisioned local SOCKS5 pluggable transport.
The adapter follows the PT v1 per-connection argument encoding. An independent
obfs4proxy process transforms the wire traffic; AnonGuard still performs its own
Ed25519-pinned TLS 1.3/ALPN authentication and hybrid onion handshake inside it.
Neither the Tor daemon nor the public Tor network is required.

This first integration supports **directory-admitted entry relays**, with private
transport endpoints distributed separately. It does not yet implement unlisted
private bridge descriptors. The directory still reveals the relay's advertised
endpoint. Authority bootstrap and relay-to-relay connections retain their existing
transports. Consequently this is not a complete censorship-resistant bootstrap,
nor a guarantee that a censor cannot discover or block the deployment.

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

Use a mode-0600 file and dedicated guard-state path for this profile. The pin must
match a current accepted directory non-exit relay. Missing entries, stale directory,
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
The operator currently supervises the PT separately; AnonGuard does not download,
launch or restart arbitrary binaries from its configuration.

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
topology permits it. Current directory admission/advertisement does not support a
fully private loopback-only relay deployment; do not claim that it does.

## Verification

Normal tests cover escaping/bounds, mandatory RFC1929 negotiation, no direct
fallback, IPv4/IPv6 framing, byte preservation and entry-pin selection/cooldown.
The opt-in test uses a real transport binary:

```sh
ANONGUARD_OBFS4PROXY=/trusted/path/obfs4proxy cargo test --locked --test test_pluggable_transport -- --ignored
ANONGUARD_OBFS4PROXY=/trusted/path/obfs4proxy cargo test --locked --test test_daemon_testnet
```

The latter exercises the actual CLI gateway and existing multi-hop payload,
half-close and relay-loss assertions with an obfs4 first hop. Local interoperability
does not establish censorship resistance against a real country's filtering.

## Remaining private-bridge release requirements

1. Provision independently authenticated unlisted bridge descriptors without public
   directory advertisement, and preserve identity/subnet/guard selection constraints.
2. Protect authority bootstrap as well as application first-hop traffic; specify how
   bridge metadata and signed directory updates reach a censored client initially.
3. Add managed lifecycle and service packaging with restricted backend exposure,
   failure/crash tests and operator key/state backup/rotation guidance.
4. Integrate the application isolation profile with transport-only outbound policy.
5. Run multi-network tests, blocked-direct-path tests, PT crash tests, and sustained
   resource/traffic measurements. Evaluate detection rather than claiming invisibility.

Specification: https://torproject.gitlab.io/torspec/pt-spec.html (PT v1 architecture,
environment and section 3.5 argument encoding).
