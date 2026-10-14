# AnonGuard v6 threat model

AnonGuard is an experimental low-latency TCP onion gateway. The implementation and tests provide engineering evidence, not a formal proof, an independent security audit or evidence of superiority to Tor. See [v6 protocol specification](docs/PROTOCOL_V3.md) for the concrete wire and state contracts.

## Trust boundaries

Clients trust authentic bootstrap pins and a quorum of independently operated authorities. The CLI requires more than two thirds of configured keys, but distinct keys do not establish independent operators. Quorum-signed exact snapshots and persisted votes restrict equivocation; partitions and divergent frozen views may stop service. No complete Byzantine liveness claim is made.

Client operating systems, protected applications and security-state storage must be uncompromised. Local administrators can change keys, rollback files, disable isolation or escape namespaces. Reliable clocks are required for certificates and directory freshness. Durable state blocks accepted epoch rollback across ordinary restarts, not malicious disk rollback by an administrator.

Relay identity signatures, TLS pins and hybrid circuit negotiation are intended to bind paths to advertised keys. Their security depends on the primitives, randomness, implementations and correct deployment. Network authentication requires both Ed25519 and ML-DSA-65 signatures under a composite pin, including an exporter-bound proof on TLS links; key exchange combines X25519 and ML-KEM-768. This custom composition still requires independent review and does not upgrade external website PKI, operating-system trust or software-distribution signatures. Compromised live hop secrets expose the affected hop; ordinary unit tests do not prove forward secrecy under all attacks.

## Adversaries and defenses

A local passive observer sees guard connections, authority fetches, TLS characteristics, timing, volumes and connection lifetimes. Link encryption hides cell contents and link identifiers from that observer. Hop-local covered envelopes use a 20-ms schedule and 8192-byte cells, with substantial bandwidth costs. Connection setup/lifetime and congestion remain observable. Padding is experimental; no classifier accuracy or correlation-resistance guarantee is supplied.

A relay knows adjacent endpoints and its own routing state. An entry can observe the client, an exit can observe the destination and plaintext applications, and colluding ingress/egress observers can correlate traffic. An honest middle hop alone does not guarantee anonymity against traffic analysis. Layered authentication, sequence checks, transcript binding, identity pins and exit-origin response checks reject specified tampering and replay cases. Malicious relays can still drop, delay, deny service or perform timing manipulation.

Directory attackers face signature, freshness, exact-view quorum, PoW and durable rollback checks. A compromised authority quorum can authorize malicious directories. PoW and subnet diversity do not prevent funded Sybil attacks, related operators, AS-level observation or malicious infrastructure concentration. Small networks have small anonymity sets regardless of protocol correctness.

Remote peers and applications can try to exhaust buffers, connections or destination resources. Bounded queues, windows, admission limits and deadlines constrain specific paths. They are not an independently evaluated global memory-budget or network-wide DoS solution. Fixed limits also restrict scalability.

Exit destinations are validated across all DNS results before connection. Private and special addresses are refused by default. This reduces SSRF exposure; operating-system resolution behavior and administrator policy remain dependencies. Plain HTTP is visible to exits. Applications need their own TLS and must avoid identifying credentials if anonymity is intended.

## Optional reverse rendezvous

Tracker controls require pinned hybrid TLS with a distinct ALPN and exporter-bound dual-signature authentication. Private 256-bit capabilities authorize reverse tunnel handoff; discovery lists IDs only. Queued registrations have EOF/early-data detection, a 60-second lifetime, three slots per node and 128 waiting slots within a 512-connection admission budget. Tunnel lifetime is bounded to one hour. These controls constrain the original stale-registration exhaustion path, not all distributed denial of service. The tracker sees the connecting participants and can correlate handoffs. Reverse rendezvous is a private provisioning feature; reverse onion circuit transport remains explicitly unsupported.

## Local protection

Linux kernel mode protects applications deliberately launched inside a fresh loopback-only namespace, with DROP policies and a private bridge to the gateway. Direct external IPv4/IPv6 and DNS have no route. Gateway or helper failure leaves the namespace isolated. This is not host-wide protection, a filesystem sandbox or a defense against root. Unprotected applications elsewhere continue normal networking.

macOS and Windows do not implement equivalent kernel protection. Application socket cancellation is narrower than namespace isolation; strict kernel mode refuses startup. Browser fingerprinting, cookies, accounts, telemetry and identity-bearing application content remain outside the transport boundary.

## Unresolved assurance requirements

Independent protocol and code review; sustained fuzzing and meaningful coverage; privileged crash/leak testing; key rotation and state recovery procedures; measured resource budgets; realistic multi-operator testnets; held-out traffic-analysis evaluations; and signed, reproducible cross-platform releases are release gates. Hidden services, reviewed multipath sessions and censorship-resistant transports require separate designs.
