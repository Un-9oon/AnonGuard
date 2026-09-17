# Comprehensive Report: Cryptography, Perfect Forward Secrecy, and Onion Encryption

## Executive Summary
This report catalogs 50 distinct scenarios, edge cases, and hypotheses focusing on the cryptographic architecture of AnonGuard. It explores the implementation of Perfect Forward Secrecy (PFS), the mechanics of Layered (Onion) Encryption, Identity Key management, and theoretical attacks including quantum decryption and side-channel vulnerabilities.

---

## Comprehensive Introduction: The Cryptographic Engine

### Symmetric vs Asymmetric Encryption
Cryptography in AnonGuard relies on two fundamental math systems. 
1. **Asymmetric (Public/Private Key):** Used for Identity. A server has a Public Key (which everyone knows, like an email address) and a Private Key (which only the server knows, like a password). These are slow but necessary for establishing trust.
2. **Symmetric (Shared Key):** Used for Speed. Once trust is established, both parties agree on a single shared "Burner Key" (using Diffie-Hellman). They use this single key to encrypt and decrypt the fast-flowing 512-byte cells using algorithms like AES. 

### Perfect Forward Secrecy (PFS)
If a server used its long-term Private Key to encrypt all user data, a hacker stealing that key could decrypt years of recorded past traffic. PFS solves this by generating "Burner Keys" (Ephemeral Keys) for every single circuit. The long-term Private Key is only used as an ID card to prove identity during the handshake. The actual data is encrypted with the Burner Keys. When the connection closes, the Burner Keys are permanently deleted from RAM, meaning future key compromises cannot decrypt past data.

### Onion Routing (Layered Encryption)
AnonGuard routes traffic through three nodes (Entry, Middle, Exit). If it only encrypted the data once, the Entry node would know both who you are and what you are saying. Onion Routing solves this by wrapping the data in three layers of encryption (like an onion). 
- The Client encrypts the data first with the Exit Node's Burner Key.
- Then encrypts that with the Middle Node's Burner Key.
- Then encrypts that with the Entry Node's Burner Key.
As the packet travels, each node "peels" off its specific layer. No single node ever knows both the sender's identity and the final destination.

## Frequently Asked Questions (Q&A)

**Q: Does AnonGuard use "Key Ratcheting" to change keys mid-session?**
**A:** No. While AnonGuard has Perfect Forward Secrecy (keys are burned after the session ends), it does not implement mid-session asynchronous ratcheting (like the Signal Protocol). This is because executing heavy Diffie-Hellman math continuously on thousands of high-speed 512-byte cells would cause massive CPU bottlenecks and destroy network latency.

**Q: What happens if a hacker recovers the Burner Keys from RAM after the session?**
**A:** When a circuit is destroyed, the software explicitly zeroes out the memory where the keys were stored before freeing it back to the OS. The keys are mathematically irrecoverable.

**Q: Can the Exit Node read my passwords?**
**A:** The Exit Node removes the final layer of Onion encryption. If you are visiting a plain `http://` website, the Exit Node can see the plain text. However, because 99% of the web is `https://` (TLS), the Exit Node only sees TLS-encrypted gibberish. The Exit Node knows *where* you are going, but not *who* you are, and not *what* your HTTPS data contains.

**Q: How does AnonGuard prevent someone from tampering with the encrypted cells?**
**A:** Every cell includes a Message Authentication Code (MAC), typically a running SHA-256 digest. If an attacker flips a single bit in the encrypted payload, the MAC verification will fail at the Exit Node, and the circuit will be instantly destroyed to prevent Padding Oracle attacks.

---

## Part 1: Master Keys & Identity (Scenarios 1-10)

**Scenario 1: Long-Term Key Theft**
*   **Hypothesis:** A government seizes an Entry node and extracts its long-term Ed25519 Private Key.
*   **Result:** They can now spin up a fake server and impersonate that specific Entry node. However, because of PFS, they cannot decrypt any historical traffic that flowed through that node prior to the seizure.

**Scenario 2: Hardware Security Modules (HSM)**
*   **Edge Case:** The node operator stores the Master Key in an HSM (like a YubiKey) rather than on the hard drive.
*   **Result:** If the server is hacked or physically seized, the Master Key cannot be copied. The attacker can only sign data while the HSM is plugged in. Once unplugged, the node's identity is safe.

**Scenario 3: Offline Master Keys**
*   **Hypothesis:** The operator creates the Master Key on an offline laptop, uses it to sign a temporary "Sub-Key" valid for 30 days, and puts the Sub-Key on the server.
*   **Result:** If the server is hacked, the attacker only gets a 30-day key. The true Master Identity is safe offline, drastically reducing the blast radius of a server compromise.

**Scenario 4: Key Revocation Lists (CRLs)**
*   **Edge Case:** A node is hacked, and the operator needs to tell the network to ignore the compromised Master Key.
*   **Result:** The operator must contact the Tracker Authorities out-of-band to add the key to a global blacklist. AnonGuard currently lacks an automated in-band cryptographic revocation system.

**Scenario 5: Impersonating the Directory Tracker**
*   **Hypothesis:** An attacker generates a fake Master Key for a Tracker Authority and distributes a fake Phonebook.
*   **Result:** The true Public Keys of the Tracker Authorities are hardcoded directly into the AnonGuard client's source code. The client software will mathematically reject the fake signature.

**Scenario 6: Key Generation Weakness (Debian Bug)**
*   **Hypothesis:** The server generates its Master Key using a broken Random Number Generator (like the infamous 2008 Debian OpenSSL bug), resulting in only 32,000 possible keys.
*   **Result:** An attacker can pre-compute all 32,000 keys in minutes and impersonate the node perfectly. Robust OS entropy (`/dev/urandom`) is absolutely critical during key generation.

**Scenario 7: RSA vs Elliptic Curve (Ed25519)**
*   **Environment:** The system uses Ed25519 instead of traditional RSA-4096.
*   **Result:** Ed25519 keys are only 32 bytes long (compared to RSA's 512 bytes) but offer the same security. This allows the keys to easily fit inside the constrained 512-byte cell structures during handshakes.

**Scenario 8: Man-in-the-Middle (MITM) on the Handshake**
*   **Hypothesis:** An ISP intercepts the connection and replaces the node's Public Key with their own.
*   **Result:** The client cross-references the Public Key presented in the TLS handshake with the Public Key listed in the cryptographically signed Tracker Consensus. The mismatch instantly terminates the connection.

**Scenario 9: Node Identity Collision**
*   **Edge Case:** Two nodes accidentally generate the exact same Master Key.
*   **Result:** Mathematically impossible in the lifespan of the universe (probability of 1 in $2^{256}$).

**Scenario 10: State-Sponsored Certificate Authorities (CAs)**
*   **Hypothesis:** A government forces a global CA (like Verisign) to issue a fake TLS certificate for an AnonGuard node.
*   **Result:** AnonGuard does not rely on the Web's CA infrastructure (X.509). Nodes self-sign their certificates, and trust is established solely through the Decentralized Tracker Consensus, rendering CA coercion useless.

---

## Part 2: Perfect Forward Secrecy & Ephemeral Keys (Scenarios 11-20)

**Scenario 11: The Memory Forensics Attack**
*   **Hypothesis:** An attacker freezes the server's RAM with liquid nitrogen, physically extracts it, and scans it for active Ephemeral Keys.
*   **Result:** If a circuit is currently active, the Burner Keys will be found in the RAM dump, and the active session can be decrypted. PFS only protects *past* sessions that have already been deleted.

**Scenario 42: Forced Circuit Longevity**
*   **Hypothesis:** An attacker sends 1 byte every 59 seconds to keep a circuit alive for 30 days, preventing the Burner Key from being deleted.
*   **Result:** The relay implements a hard maximum lifetime for circuits (e.g., 24 hours). After this timeout, the circuit is forcefully destroyed and the keys are burned, forcing the client to build a new circuit.

**Scenario 13: Mid-Session Post-Compromise (The Lack of a Ratchet)**
*   **Edge Case:** A hacker steals the Burner Key mid-session while a 50GB file is downloading.
*   **Result:** Because AnonGuard lacks a Diffie-Hellman Ratchet, the hacker can decrypt the remainder of that specific 50GB transfer until the circuit is finally closed. 

**Scenario 14: Ephemeral Key Generation Predictability**
*   **Hypothesis:** The client uses a weak random number to pick its side of the Diffie-Hellman exchange.
*   **Result:** An attacker can guess the ephemeral key, completely bypassing PFS. Clients must use high-quality entropy for ephemeral key generation.

**Scenario 15: The "Record Now, Decrypt Later" Attack**
*   **Environment:** The NSA records all encrypted traffic globally and archives it for 20 years.
*   **Result:** Because the Burner Keys were generated on the fly, never transmitted over the wire, and destroyed locally, they do not exist anywhere in the universe. The archived traffic remains permanently unreadable.

**Scenario 16: RAM Wiping Failures**
*   **Edge Case:** The OS reallocates the memory where the key was stored to another program without wiping it, due to a bug in Rust's memory allocator.
*   **Result:** A local user on the server could read the uncleared memory. Secure zeroing functions (like `zeroize` crate in Rust) must be used to ensure compiler optimizations do not skip the memory wipe.

**Scenario 17: Swap File Leakage**
*   **Hypothesis:** The server runs out of RAM and writes the Burner Keys to the hard drive's Swap partition.
*   **Result:** The keys are now permanently written to disk, defeating PFS. *Remediation:* Nodes must disable Swap partitions or configure the OS to encrypt the Swap space.

**Scenario 18: CPU Register Leakage**
*   **Edge Case:** The Burner Key remains stuck in the CPU's L1 cache or registers after the encryption function finishes.
*   **Result:** Advanced side-channel attacks (like Meltdown/Spectre) could read the keys from the CPU. Cryptographic libraries must explicitly clear sensitive registers.

**Scenario 19: Perfect Forward Secrecy on the Tracker**
*   **Hypothesis:** Does downloading the Phonebook from the Tracker use PFS?
*   **Result:** Yes. The connection to the Tracker is a standard TLS 1.3 connection, which natively enforces Ephemeral Key exchanges (ECDHE), ensuring directory requests cannot be retroactively audited.

**Scenario 20: Reusing Ephemeral Keys for Speed**
*   **Edge Case:** To save CPU cycles, a node operator modifies the code to reuse the same "Ephemeral" Diffie-Hellman share for 100 different clients.
*   **Result:** This catastrophic flaw destroys PFS and allows an attacker to correlate and decrypt traffic across multiple users. AnonGuard strict adherence requires fresh entropy for every circuit.

---

## Part 3: Onion Routing & Layered Encryption (Scenarios 21-30)

**Scenario 21: The Global Passive Observer**
*   **Hypothesis:** An adversary monitors the Entry Node and the Exit Node simultaneously.
*   **Result:** The data payload is completely different (encrypted differently) at both ends. The adversary must rely solely on timing and size correlation. The Quantum/Chaos morphing engines are designed specifically to destroy this correlation.

**Scenario 22: Malicious Entry Node**
*   **Hypothesis:** The FBI runs the Entry Node.
*   **Result:** They see the user's IP address. However, the data is still encrypted twice more (Middle and Exit layers). They cannot see the final website or the data contents.

**Scenario 23: Malicious Exit Node**
*   **Hypothesis:** A hacker runs the Exit Node.
*   **Result:** The Exit Node decrypts the final Onion layer. If the user is visiting `http://example.com`, the hacker sees the traffic. However, they only see the IP of the Middle Node, not the user's real IP. 

**Scenario 24: End-to-End TLS (HTTPS)**
*   **Environment:** The user visits `https://bank.com` through a Malicious Exit Node.
*   **Result:** Even though the Exit Node peels the final Onion layer, the payload inside is *still* encrypted by standard TLS. The Malicious Exit Node sees encrypted gibberish and cannot steal the banking password.

**Scenario 25: The Two-Node Circuit Bypass**
*   **Edge Case:** A user manually configures the client to only use 2 nodes (Entry and Exit) to improve speed.
*   **Result:** If the Entry and Exit nodes collude (are run by the same adversary), they instantly de-anonymize the user. The 3-node minimum is mathematically required to ensure at least one honest node (the Middle) breaks the chain of knowledge.

**Scenario 26: Layer Peeling Verification**
*   **Hypothesis:** The Entry node attempts to peel the Middle node's encryption layer.
*   **Result:** Cryptographically impossible. The keys were negotiated directly between the Client and the Middle node (via a tunnel through the Entry node). The Entry node does not have the Burner Key for the Middle layer.

**Scenario 27: Injecting Tags (Watermarking)**
*   **Hypothesis:** The Entry Node alters a few bits in the encrypted cell to "watermark" it, hoping the colluding Exit Node notices the flipped bits.
*   **Result:** The Middle Node's decryption uses AES-CTR and verifies a MAC. If the cell was altered by the Entry Node, the MAC fails at the Middle Node, and the cell is dropped before ever reaching the Exit Node.

**Scenario 28: Sybil-Controlled Path**
*   **Hypothesis:** A hacker registers 5,000 nodes and hopes the user randomly selects three of their nodes for a circuit.
*   **Result:** The Tracker's Circuit Diversity algorithm forces the client to pick nodes from different `/16` IP subnets and different Autonomous Systems (ASNs), making it statistically near-impossible to randomly pick three colluding nodes.

**Scenario 29: Middle Node Drop-out**
*   **Edge Case:** The Middle Node suddenly loses power mid-transfer.
*   **Result:** The Onion chain is physically broken. The Entry Node cannot bypass the Middle Node to reach the Exit Node because it lacks the routing information (which was encrypted inside the cell meant for the Middle Node). The circuit is safely torn down.

**Scenario 30: Cryptographic Overhead of Onion Layers**
*   **Environment:** The client must perform 3 AES encryptions for every 512-byte cell sent.
*   **Result:** Modern CPUs with AES-NI instructions can perform AES encryption at ~4 GB/s. The cryptographic overhead on the client is negligible compared to the network latency.

---

## Part 4: Symmetric Encryption (AES) & Stream Ciphers (Scenarios 31-40)

**Scenario 31: AES-CTR vs AES-GCM**
*   **Hypothesis:** The protocol uses AES-CTR (Counter Mode) instead of AES-GCM for cell encryption.
*   **Result:** AES-CTR allows the node to maintain a continuous encryption stream across thousands of 512-byte cells. However, CTR is malleable. Therefore, a separate, running SHA-256 HMAC digest must be appended to ensure integrity.

**Scenario 32: Nonce/IV Reuse in AES-CTR**
*   **Edge Case:** A coding bug causes the AES-CTR counter to reset to zero mid-session.
*   **Result:** Catastrophic failure. Encrypting two different cells with the same Key and Nonce allows an attacker to XOR them together and recover the plain text instantly. Strict counter incrementation is mathematically vital.

**Scenario 33: The Padding Oracle Attack**
*   **Hypothesis:** An attacker alters the padding bytes to see how the server responds, attempting to steal the key bit-by-bit.
*   **Result:** AES-CTR does not use block padding (like PKCS#7), so there are no padding errors to observe. The attack is mathematically impossible.

**Scenario 34: Bit-Flipping Attacks**
*   **Hypothesis:** An attacker flips the 10th bit in the encrypted cell, knowing it will flip the 10th bit in the plain text upon decryption.
*   **Result:** While true for AES-CTR, the separate HMAC verification detects the altered payload. The cell is discarded before the flipped bit can be processed by the application layer.

**Scenario 35: Replay Attacks on the Stream Cipher**
*   **Edge Case:** An attacker captures cell #5 and sends it again as cell #6.
*   **Result:** The receiving node decrypts cell #6 using Counter=6. The resulting plain text is garbage, the MAC fails, and the circuit is destroyed.

**Scenario 36: Cryptographic Agility**
*   **Hypothesis:** A flaw is found in AES. The network needs to switch to ChaCha20.
*   **Result:** The protocol includes Cipher Suites in the handshake. The client and server negotiate the strongest mutually supported algorithm, allowing the network to upgrade ciphers without breaking old clients.

**Scenario 37: Random Number Generator Bias**
*   **Environment:** The OS random number generator slightly favors producing even numbers over odd numbers.
*   **Result:** The Diffie-Hellman keys become weaker and easier to brute-force. Security relies entirely on perfectly uniform entropy from the host OS.

**Scenario 38: MAC Timing Attacks**
*   **Hypothesis:** An attacker measures exactly how many microseconds it takes the node to return a "MAC Verification Failed" error.
*   **Result:** If the MAC verification uses a standard string comparison (`==`), it fails faster on the 1st byte than the 20th byte. The code must use a "Constant-Time Compare" function to prevent leaking the correct MAC via timing.

**Scenario 39: Stream Desynchronization**
*   **Edge Case:** A cell is lost in transit due to UDP dropping, but the circuit remains open.
*   **Result:** The sender's AES Counter is now at 10, but the receiver's Counter is at 9. All future cells decrypt to garbage. The circuit must be rebuilt. (This is why the cell protocol runs over reliable TCP).

**Scenario 40: Zero-Day in Cryptographic Libraries**
*   **Hypothesis:** A bug in OpenSSL or Rust's `ring` crate compromises the AES implementation.
*   **Result:** All anonymity networks relying on that library are instantly compromised. Compiling AnonGuard with diverse, audited cryptographic backends is essential for defense in depth.

---

## Part 5: Theoretical Attacks & Future Proofing (Scenarios 41-50)

**Scenario 41: Shor's Algorithm (Quantum Computers)**
*   **Hypothesis:** A nation-state builds a stable Quantum Computer and breaks Elliptic Curve Cryptography (Ed25519) and Diffie-Hellman.
*   **Result:** The attacker can forge Tracker signatures and break the initial Key Exchange to steal the Burner Keys. *Remediation:* AnonGuard must upgrade to Post-Quantum Cryptography (PQC) algorithms like Kyber or NTRU for handshakes.

**Scenario 42: Quantum Resistance of AES**
*   **Hypothesis:** A Quantum Computer uses Grover's Algorithm to attack the symmetric AES encryption.
*   **Result:** Grover's algorithm halves the effective bit-length of symmetric keys. AES-128 becomes equivalent to AES-64 (breakable). AnonGuard must use AES-256, which reduces to AES-128 under quantum attack, remaining secure.

**Scenario 43: Side-Channel Attacks (Power Analysis)**
*   **Environment:** An attacker gains physical access to the server room and monitors the power consumption of the CPU using an oscilloscope.
*   **Result:** Different cryptographic operations consume different amounts of wattage. The attacker could theoretically extract the Master Key by observing power spikes during TLS handshakes.

**Scenario 44: Electromagnetic Leakage (TEMPEST)**
*   **Hypothesis:** An attacker parks a van outside a data center and measures the electromagnetic radiation emitted by the CPU processing AES encryptions.
*   **Result:** TEMPEST shielding of server racks is required for hardware-level security against physical proximity attacks.

**Scenario 45: Acoustic Cryptanalysis**
*   **Edge Case:** An attacker places a microphone near the server and listens to the high-frequency whine of the CPU capacitors during RSA/ECC operations.
*   **Result:** Researchers have successfully extracted keys using this method. Constant-time cryptographic libraries mitigate the distinct acoustic signatures of variable-time math operations.

**Scenario 46: The Bribe Attack (Rubber-Hose Cryptanalysis)**
*   **Environment:** A government agency bribes or threatens an Entry Node operator to install malware that logs Ephemeral Keys directly from RAM.
*   **Result:** No math can defeat physical coercion. However, Onion Routing ensures the Entry Node operator still doesn't know the final destination or content of the traffic, minimizing the damage.

**Scenario 47: Sybil Attack on Cryptographic Upgrades**
*   **Hypothesis:** The network releases a Post-Quantum upgrade. An attacker keeps 10,000 nodes on the old, vulnerable version.
*   **Result:** The Tracker Authorities must enforce a "Minimum Version" rule in the Consensus document, automatically kicking old, vulnerable nodes off the network.

**Scenario 48: Hash-Length Extension Attacks**
*   **Edge Case:** The protocol uses standard SHA-256 for MAC generation instead of HMAC.
*   **Result:** An attacker could append extra data to a cell and forge a valid hash without knowing the secret key. AnonGuard must strictly use HMAC-SHA256 or modern AEAD ciphers (like AES-GCM or ChaCha20-Poly1305) to prevent this.

**Scenario 49: Compromised Compiler (Trusting Trust)**
*   **Hypothesis:** A nation-state hacks the Rust compiler infrastructure. The compiler intentionally inserts a backdoor into the AES implementation of any software it compiles.
*   **Result:** The source code looks perfectly secure, but the compiled binary leaks keys. Deterministic builds and diverse compiler toolchains are required to detect this.

**Scenario 50: The Ultimate Omniscient Adversary**
*   **Hypothesis:** A global adversary possesses a Quantum Computer, taps every fiber optic cable on Earth, and runs AI on all flows simultaneously.
*   **Result:** Statistical anonymity networks (like Tor and AnonGuard) eventually fall to global, omniscient passive observation combined with Quantum decryption. The only theoretical defense is steganography (hiding the existence of communication entirely) or quantum entanglement communication networks.

---
*Report Generated by AnonGuard Systems Engineering.*
