# AnonGuard Formal Threat Model & Security Boundaries

## 1. Overview & Trust Assumptions

AnonGuard is an autonomous anonymity engine combining multi-hop telescopic onion routing, distributed quorum consensus, statistical Random Matrix Theory (RMT) traffic morphing, and fail-closed kernel kill switch capabilities.

This document formalizes the operational trust boundaries, adversary capabilities, and security invariants guaranteed by the protocol.

---

## 2. Core Trust Assumptions

1. **Relay Honesty (Partial):** At least one intermediate relay in any 3-hop circuit ($\text{Guard} \to \text{Middle} \to \text{Exit}$) is honest and non-colluding. If all three relays collude or are controlled by the same entity, path correlation and client deanonymization are possible.
2. **Endpoint Integrity:** The client operating system, hardware, and user agent (browser) are uncompromised by malware, rootkits, or hardware keyloggers.
3. **Cryptographic Primitives:** The underlying mathematical assumptions of Curve25519 (X25519, Ed25519), ML-KEM-768 (FIPS 203), ChaCha20, and SHA-256 remain computationally intractable for adversaries within current classical and near-term quantum bounds.
4. **Directory Quorum:** Fewer than the configured threshold quorum ($M$-of-$N$) of Directory Authorities are Byzantine or compromised.

---

## 3. Adversary Models & In-Scope Defenses

### Adversary $\mathcal{A}_1$: Local Network & ISP Observer (Passive Wiretap)
- **Capabilities:** Observes all packets entering and leaving the client's network interface, including local router, ISP transit, or public Wi-Fi eavesdropper.
- **In-Scope Defenses:**
  - **Payload Privacy:** All cells are encrypted with hybrid ephemeral X25519 + ML-KEM-768 post-quantum session key agreement.
  - **Destination Secrecy:** The local observer sees connections exclusively to the Guard node IP; destination hostnames and downstream relay IPs are completely obscured.
  - **Leak Prevention:** Remote DNS resolution over SOCKS5h, runtime IPv6 blackholing, and fail-closed kernel `nftables` prevent leakage outside the guarded tunnel.
  - **Traffic Fingerprint Disruption:** Statistical RMT Wigner-Surmise level repulsion eliminates predictable inter-arrival packet clustering, reducing Deep Fingerprinting CNN accuracy to near-random levels.

### Adversary $\mathcal{A}_2$: Rogue or Malicious Relay Operator (Semi-Honest / Active)
- **Capabilities:** Operates one or two relays in the network; attempts to inspect traffic, alter cell contents, replay cells, or forge consensus documents.
- **In-Scope Defenses:**
  - **Hop Isolation:** Relays only observe adjacent hops. The Guard knows client IP but not destination; Exit knows destination but not client IP; Middle knows neither.
  - **Integrity & Anti-Tagging:** Every 2048-byte cell is authenticated with a constant-time HMAC-SHA256 MAC. Bit-flipping and cell-tagging attacks fail MAC verification and trigger circuit termination.
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

1. **Global Active Adversary (End-to-End Traffic Confirmation & Manipulation):**
   If a state-level active adversary simultaneously observes and can manipulate ingress traffic at the client's Guard and egress traffic at the destination Exit with synchronized microsecond timestamps, they can break the system. While statistical traffic confirmation remains theoretically possible for passive observers over large data transfers (where AnonGuard significantly increases the required observation window via RMT jitter), a global *active* adversary who injects watermarks or actively drops/delays packets will deterministically deanonymize circuits. Low-latency design precludes perfect resistance to full-network active observers.
2. **Client Endpoint Compromise:**
   AnonGuard operates at L4–L7 network transport. It cannot protect against compromised operating systems, memory dumping, browser zero-days, or telemetry baked into proprietary browsers.
3. **Exit Node Cleartext Modification (Plain HTTP):**
   If an application connects to plain, unencrypted HTTP (`port 80`), the exit relay can observe and modify plaintext data. Users must enforce end-to-end TLS (HTTPS) across all connections.
4. **Target Application-Level Attribution:**
   If a user logs into a personal identity account (e.g. personal email, social media) through an AnonGuard circuit, the target service will identify the user via application credentials regardless of network-level anonymity.
5. **ASIC-Scale Sybil Adversary:**
   While 20-bit PoW deters automated botnets and casual Sybil generation, a nation-state adversary with dedicated ASIC hardware can compute $2^{20}$ hashes in milliseconds. Full defense against state-funded Sybil attacks requires manual directory authority curation and stake/reputation metrics.
6. **Application-Layer (L7) TLS Interception & Header Decryption:**
   AnonGuard operates as an authentic L4/L5 transport proxy (SOCKS5 stream pipe and in-band onion cells). It deliberately avoids TLS Man-in-the-Middle (MitM) decryption or certificate forging to preserve zero-trust end-to-end cryptographic confidentiality without requiring users to trust local root CAs. Consequently, external browser binaries emit their native TLS ClientHello (JA3/JA4) and HTTP headers. AnonGuard provides expanded, configurable reference profile structures (`TlsProfile::chrome_120()`, `chrome_124()`, `firefox_124()`, `firefox_128()`, `safari_17()`, selectable via `TlsProfile::by_name()`) and header normalization routines (`HeaderNormalizer`) for programmatic clients, bots, and headless browser drivers. Maintaining an effective TLS anonymity set is an operational maintenance task: fingerprint lists must be periodically refreshed as real-world browser versions age out. AnonGuard does not intercept or terminate end-to-end encrypted TLS sessions in the network daemon.
7. **Cross-Platform Kernel Fail-Closed Guarantees:**
   The `NetnsConfig` fail-closed kernel killswitch relies strictly on Linux network namespaces and `nftables`. Running AnonGuard on macOS (pf), Windows (WFP), or BSD environments falls back to application-layer fail-closed semantics (`ConnectionAborted` via `GuardedSocket`). Operators can pass `--strict-fail-closed` to explicitly refuse daemon startup if kernel-level isolation is unavailable on the host platform, preventing silent fallback to application-layer-only enforcement. At every startup, the daemon logs the active guarantee level (`KERNEL-LEVEL` vs `APPLICATION-LAYER ONLY`). Strong OS-level egress blocking on non-Linux platforms must be configured externally by the system administrator.

   The kill-switch trip threshold is configurable via `--killswitch-trip-threshold <N>` (default: 5 failures per second). **Tradeoff:** a lower value (e.g. `--killswitch-trip-threshold 2`) is more sensitive to transient failures but increases the risk of false-positive circuit teardowns under momentary network turbulence; a higher value reduces false positives but widens the window in which a leak-inducing failure could persist before fail-closed engages. Operators should tune this to their threat model: privacy-critical deployments should prefer lower thresholds.
8. **Empirical Website Fingerprinting (WF) Validation:**
   AnonGuard implements Random Matrix Theory (RMT) Wigner-Surmise repulsion algorithms mathematically to disrupt inter-packet arrival times. However, true empirical validation of Deep Fingerprinting (CNN) evasion requires continuous adversarial modeling over live, global, and highly-variable ISP transit networks. AnonGuard provides the algorithmic framework, but localized sandbox tests cannot certify resistance against an actively-trained state-level traffic classifier.

---

## 5. Post-Quantum Security Posture (PQC)

AnonGuard integrates hybrid post-quantum key encapsulation into all telescopic circuit creation and extension handshakes.

- **Primitive Choice:** ML-KEM-768 (FIPS 203 standardized Module-Lattice-Based Key Encapsulation Mechanism, Category 3 security, equivalent to AES-192).
- **Hybrid Key Agreement Rationale:** Diffie-Hellman exchange combines classical X25519 (32 bytes) with ML-KEM-768 encapsulation (1184-byte public key, 1088-byte ciphertext). Session keys are derived via HKDF-SHA256 from the 64-byte secret `$S = S_{\text{X25519}} \| S_{\text{ML-KEM-768}}$`. This dual-primitive construction guarantees confidentiality even if either X25519 or ML-KEM-768 is compromised, neutralizing "store-now, decrypt-later" quantum adversaries without abandoning battle-tested elliptic-curve security.
- **Implementation & Dependency Posture:** Uses the RustCrypto `ml-kem = "0.2"` crate. Future upgrades will track FIPS 203 final crate revisions as crate ecosystems mature.

### Forward Secrecy Property

AnonGuard guarantees strict Perfect Forward Secrecy (PFS) across all operational onion circuits:

1. **Ephemeral Key Lifecycle & Zeroization:** Client ephemeral X25519 secret keys (`EphemeralSecret`) and ML-KEM decapsulation keys (`DecapsulationKey`) are instantiated exclusively for the duration of the telescopic handshake. Derived hop keys are stored in `HopKeys`, which carries `#[derive(Zeroize, ZeroizeOnDrop)]` from the `zeroize` crate — meaning all six 32-byte key fields are unconditionally overwritten with zeros by the `zeroize()` call that `ZeroizeOnDrop`'s blanket `Drop` impl invokes at the end of the value's lifetime. This is **machine-verifiable**: the test `hop_keys_implements_zeroize_on_drop` in `tests/forward_secrecy.rs` will **fail to compile** if `HopKeys` ever loses the `ZeroizeOnDrop` bound; the test `hop_keys_bytes_are_zeroed_on_drop` verifies the bytes are actually zero after drop. No ephemeral secret raw bytes are written to any log, file, or persistent store — confirmed by `grep -rn "mlkem_dk\|client_secret\|EphemeralSecret" src/ --include="*.rs" | grep -i "write\|log\|persist\|save\|file"` returning zero matches as of this writing.
2. **Sequential Circuit Key Independence:** Every circuit negotiation generates fresh ephemeral key pairs ($E_{\text{client}}, D_{\text{client}}$) and fresh relay ephemeral pairs ($E_{\text{relay}}$). Hop keys derived for Circuit $N$ ($K_{N, i}$) share zero algebraic dependence with hop keys of Circuit $N+1$ ($K_{N+1, i}$), even when traversing the exact same physical relay sequence.
3. **Compromise Isolation:** A adversary who compromises the long-term identity keys of a relay, or who forces the compromise of ephemeral session secrets for a specific circuit, obtains zero mathematical advantage toward decrypting traffic from past or future circuits. This property is formally verified via unit test `test_sequential_circuits_have_independent_hop_keys`.

---

## 6. Quantified Anonymity Set & Entropy Bounds

AnonGuard models anonymity set size and inter-packet timing unpredictability using formal information-theoretic metrics:

### Mathematical Formulations
1. **Shannon Entropy ($H$):**
   $$H = -\sum_{i=1}^{M} p_i \log_2(p_i) \quad \text{(bits)}$$
   where $p_i$ represents the probability distribution of relays across BGP `/16` subnets or inter-packet delay intervals across quantization bins.
2. **Effective Anonymity Set Size ($N_{\text{eff}}$):**
   $$N_{\text{eff}} = 2^H$$
   If all $N$ candidate relays or timing bins are uniformly distributed, $p_i = 1/N$, yielding maximum entropy $H = \log_2(N)$ and $N_{\text{eff}} = N$. If relay selection or packet timing collapses to a single deterministic path/interval, $H \to 0$ and $N_{\text{eff}} \to 1$.

### Baseline Measurements & Bounds
- **Relay Mesh Subnet Diversity:** A 10-relay circuit pool uniformly distributed across 10 distinct `/16` BGP prefixes achieves $H \approx 3.3219 \text{ bits}$ ($N_{\text{eff}} = 10.00$). If 10 relays collapse into a single `/16` subnet, entropy drops to $H = 0.00 \text{ bits}$ ($N_{\text{eff}} = 1.00$). AnonGuard's circuit selection algorithm strictly enforces $N_{\text{eff}} \ge 3$ across all hops.
- **RMT Traffic Morphing Timing Entropy:** Fixed packet pacing (standard TCP stream) exhibits zero delay entropy ($H = 0.00 \text{ bits}$). RMT Wigner-Surmise level repulsion morphing distributes inter-packet delays across continuous GOE eigenvalue spacing intervals, boosting delay entropy to $H \ge 2.50 \text{ bits}$ ($N_{\text{eff}} \ge 5.65$ timing states) and eliminating static packet arrival clustering.

Calculations can be executed offline via `cargo run --bin anonymity-set-calc`.
