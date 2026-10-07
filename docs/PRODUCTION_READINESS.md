# Production readiness

Status: experimental; public anonymity deployment is not approved by this work.

## Required release evidence

- Passing locked builds, formatting, strict Clippy, integration tests, fuzz campaigns and measured coverage. Keep failing coverage thresholds visible; do not lower them merely to pass CI.
- Independent protocol and implementation review, including authenticated cell metadata, sequence exhaustion, relay teardown, multipath association, quorum freshness and key rotation.
- Live multi-region testnet with independently operated relays and authorities, recorded uptime, bandwidth, circuit success, partitions, restarts and relay failure behavior.
- Reproducible real PCAP website-fingerprinting evaluations with held-out sites, realistic adversaries, uncertainty estimates and comparable Tor configurations. Simulated results do not establish real anonymity or superiority to Tor.
- Reviewed kernel isolation design. The current host-wide nftables table is not a per-process network namespace; established connections are allowed, and the listener endpoint is not the relay transport endpoint. Do not claim zero host traffic leaks.
- Tested package install/upgrade/removal, non-root state persistence, Windows key ACLs, crash recovery, rollback and signed release verification.
- Operator bootstrap keys, validated quorum policy, incident response, upgrade policy and abuse handling.

## Packaged gateway

The Debian service uses a dynamic user and private persistent state under /var/lib/anonguard. Configure /etc/anonguard/runtime.env with ANONGUARD_ARGS containing real authority endpoints, matching pinned keys and a validated quorum. The shipped config.toml sample was not parsed by the daemon; the package now ships the service environment file instead. It is preserved as a Debian conffile.

An empty relay directory fails circuit construction. An insufficient or non-diverse relay pool must never downgrade the requested hop count. Kernel firewall installation errors must stop startup when the operator requested that feature.

This document records release gates, not completed operational validation. No production anonymity assurance or Tor-superiority claim is supplied.

## Foundation remediation (implemented, awaiting release evidence)

The gateway uses one authenticated onion circuit per destination stream. The former
multipath gateway path is disabled because it lacks exit-side session association
and symmetric framing. Experimental multipath utilities are not a supported transport.
Circuit negotiation has a 30-second overall deadline; upload writes have a 30-second deadline.

Cell command 10 (END) authenticates upload half-close. The exit shuts down only its
destination write direction, retaining responses until destination EOF. Older relays
do not implement END; upgrade the complete circuit together. This is a wire-protocol
change, not a backward-compatible negotiated upgrade.

Authority endpoints use `identity@host:port`, with `--authority-keys identity:HEX`.
Unqualified endpoints require a matching endpoint key. Startup rejects missing pins
and duplicate configured signing keys; authority startup receives peer endpoints.
The relay registration transport receives the same aligned key pins.

A loaded directory retains a conservative expiry (the earliest authenticated contributing
document deadline). Expiry blocks new onion path selection, identity pin retrieval,
and directory-based mesh target authorization. Existing circuits are not automatically
terminated. Failed refreshes do not extend expiry. Zero quorum, aliased authority keys,
and conflicting relay identities at one endpoint are rejected.

PoW mining runs off the async executor. Exhausted attempts retry a fresh challenge after
30 seconds. The current 26-bit difficulty and ten-million-attempt budget remain bounded
probabilistic admission, not a guarantee of prompt registration.

## Remaining architectural work

1. Specify and implement version-negotiated authenticated link transport, per-link circuit
   identifiers, transcript binding and key rotation. Clear header correlation remains.
2. Replace per-descriptor authority voting with an explicitly chosen canonical snapshot
   quorum or reviewed Byzantine consensus protocol; add durable epoch rollback protection.
3. Implement real network namespace isolation and platform-specific leak enforcement.
   Current host-wide nftables remains experimental and unsuitable as host leak assurance.
4. Add authenticated stream/circuit flow control, fair scheduling, global resource limits,
   and immediate cancellation wakeups.
5. Design optional multipath sessions with one exit destination socket, symmetric sequencing,
   retransmission and failure handling. Do not reconnect/replay arbitrary TCP transactions.
6. Specify and evaluate traffic shaping against explicit adversaries; remove unsupported
   classifier-immunity and zero-leak claims throughout published material.
7. Onion services require a separate introduction/rendezvous/service-discovery protocol.

These changes do not establish production readiness or superiority to Tor.
