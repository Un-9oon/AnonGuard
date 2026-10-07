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
