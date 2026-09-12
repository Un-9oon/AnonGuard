# AnonGuard Formal Threat Model & Security Boundaries

## 1. Overview & Trust Assumptions

AnonGuard is an autonomous anonymity engine combining multi-hop telescopic onion routing, distributed quorum consensus, statistical Random Matrix Theory (RMT) traffic morphing, and fail-closed kernel kill switch capabilities.

This document formalizes the operational trust boundaries, adversary capabilities, and security invariants guaranteed by the protocol.

---

## 2. Core Trust Assumptions

1. **Relay Honesty (Partial):** At least one intermediate relay in any 3-hop circuit ($\text{Guard} \to \text{Middle} \to \text{Exit}$) is honest and non-colluding. If all three relays collude or are controlled by the same entity, path correlation and client deanonymization are possible.
2. **Endpoint Integrity:** The client operating system, hardware, and user agent (browser) are uncompromised by malware, rootkits, or hardware keyloggers.
3. **Cryptographic Primitives:** The underlying mathematical assumptions of Curve25519 (X25519, Ed25519), ChaCha20, and SHA-256 remain computationally intractable for adversaries within current classical and near-term quantum bounds.
4. **Directory Quorum:** Fewer than the configured threshold quorum ($M$-of-$N$) of Directory Authorities are Byzantine or compromised.

---

## 3. Adversary Models & In-Scope Defenses

### Adversary $\mathcal{A}_1$: Local Network & ISP Observer (Passive Wiretap)
- **Capabilities:** Observes all packets entering and leaving the client's network interface, including local router, ISP transit, or public Wi-Fi eavesdropper.
- **In-Scope Defenses:**
  - **Payload Privacy:** All cells are encrypted with ephemeral X25519 shared secrets.
  - **Destination Secrecy:** The local observer sees connections exclusively to the Guard node IP; destination hostnames and downstream relay IPs are completely obscured.
  - **Leak Prevention:** Remote DNS resolution over SOCKS5h, runtime IPv6 blackholing, and fail-closed kernel `nftables` prevent leakage outside the guarded tunnel.
  - **Traffic Fingerprint Disruption:** Statistical RMT Wigner-Surmise level repulsion eliminates predictable inter-arrival packet clustering, reducing Deep Fingerprinting CNN accuracy to near-random levels.

### Adversary $\mathcal{A}_2$: Rogue or Malicious Relay Operator (Semi-Honest / Active)
- **Capabilities:** Operates one or two relays in the network; attempts to inspect traffic, alter cell contents, replay cells, or forge consensus documents.
- **In-Scope Defenses:**
  - **Hop Isolation:** Relays only observe adjacent hops. The Guard knows client IP but not destination; Exit knows destination but not client IP; Middle knows neither.
  - **Integrity & Anti-Tagging:** Every 1024-byte cell is authenticated with a constant-time HMAC-SHA256 MAC. Bit-flipping and cell-tagging attacks fail MAC verification and trigger circuit termination.
  - **Anti-Replay:** Monotonic sequence counters (`sequence_no`) bound into each cell's MAC reject duplicate, stale, or reordered cells.
  - **Anti-SSRF & DNS Rebinding:** Exit relays enforce strict IP address validation against RFC 1918 private subnets, loopback, link-local, and cloud metadata (e.g. `169.254.169.254`), validating resolved socket addresses ahead of TCP connection.

### Adversary $\mathcal{A}_3$: Distributed Sybil Attacker
- **Capabilities:** Attempts to flood the directory with malicious relays to maximize the probability of controlling entire circuits.
- **In-Scope Defenses:**
  - **Proof-of-Work (PoW):** Nodes must solve a SHA-256 challenge (default 20 leading zero bits, $\sim 1\text{M}$ hashes) per registration, imposing non-trivial compute costs on large-scale node generation.
  - **BGP /16 Subnet Diversity:** Circuit path selection strictly forbids nodes from sharing the same `/16` IPv4 subnet, preventing single-datacenter or single-ISP clustering.
  - **Cryptographic Key Binding:** Relay identity is anchored by Ed25519 signing keys, preventing unauthorized node hijacking or last-write-wins directory overwriting.

---

## 4. Out-of-Scope Scenarios & Non-Guarantees

The following attack vectors are explicitly **out of scope** or represent fundamental limitations common to low-latency anonymity networks:

1. **Global Passive Adversary (End-to-End Traffic Confirmation):**
   If a state-level adversary simultaneously observes ingress traffic at the client's Guard and egress traffic at the destination Exit with synchronized microsecond timestamps, statistical traffic confirmation remains theoretically possible over large data transfers. AnonGuard significantly increases the required observation window via RMT jitter, but low-latency design precludes perfect resistance to full-network observers.
2. **Client Endpoint Compromise:**
   AnonGuard operates at L4–L7 network transport. It cannot protect against compromised operating systems, memory dumping, browser zero-days, or telemetry baked into proprietary browsers.
3. **Exit Node Cleartext Modification (Plain HTTP):**
   If an application connects to plain, unencrypted HTTP (`port 80`), the exit relay can observe and modify plaintext data. Users must enforce end-to-end TLS (HTTPS) across all connections.
4. **Target Application-Level Attribution:**
   If a user logs into a personal identity account (e.g. personal email, social media) through an AnonGuard circuit, the target service will identify the user via application credentials regardless of network-level anonymity.
5. **ASIC-Scale Sybil Adversary:**
   While 20-bit PoW deters automated botnets and casual Sybil generation, a nation-state adversary with dedicated ASIC hardware can compute $2^{20}$ hashes in milliseconds. Full defense against state-funded Sybil attacks requires manual directory authority curation and stake/reputation metrics.
6. **Application-Layer (L7) TLS Interception & Header Decryption:**
   AnonGuard operates as an authentic L4/L5 transport proxy (SOCKS5 stream pipe and in-band onion cells). It deliberately avoids TLS Man-in-the-Middle (MitM) decryption or certificate forging to preserve zero-trust end-to-end cryptographic confidentiality without requiring users to trust local root CAs. Consequently, external browser binaries emit their native TLS ClientHello (JA3/JA4) and HTTP headers. AnonGuard provides reference profile structures (`TlsProfile`) and header normalization routines (`HeaderNormalizer`) for programmatic clients, bots, and headless browser drivers, but does not intercept or terminate end-to-end encrypted TLS sessions in the network daemon.
7. **Cross-Platform Kernel Fail-Closed Guarantees:**
   The `NetnsConfig` fail-closed kernel killswitch currently relies strictly on Linux network namespaces and `nftables`. Running AnonGuard on macOS (pf), Windows (WFP), or BSD environments falls back to application-layer fail-closed semantics (`ConnectionAborted` via `GuardedSocket`). Strong OS-level egress blocking on non-Linux platforms must currently be configured externally by the user.
8. **Empirical Website Fingerprinting (WF) Validation:**
   AnonGuard implements Random Matrix Theory (RMT) Wigner-Surmise repulsion algorithms mathematically to disrupt inter-packet arrival times. However, true empirical validation of Deep Fingerprinting (CNN) evasion requires continuous adversarial modeling over live, global, and highly-variable ISP transit networks. AnonGuard provides the algorithmic framework, but localized sandbox tests cannot certify resistance against an actively-trained state-level traffic classifier.
