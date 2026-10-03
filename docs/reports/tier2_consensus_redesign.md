# Tier 2: Real Consensus Byzantine-Fault-Tolerance Redesign

## Objective

The objective of Tier 2 was to address the structural gap in the Directory Authority consensus mechanism where clients were responsible for merging independently self-signed views. The goal was to formalize the Byzantine Fault Tolerance (BFT) bounds and implement a pre-signing cross-check round at the authority layer.

## Work Completed

### 1. Formalized Threat Model (BFT Bounds)
- Updated `THREAT_MODEL.md` to explicitly define the Byzantine Fault Tolerance bounds for the Directory Authority Quorum.
- Formally adopted the Lamport/Shostak/Pease bound of `N >= 3f + 1`, meaning the system can tolerate `f` malicious/colluding authorities out of `N` total authorities.
- Documented that the client-side quorum threshold `M` corresponds to `2f + 1`, ensuring that any accepted consensus document is signed by at least one honest authority and that a malicious minority cannot forge a quorum.

### 2. Pre-Signing Cross-Check Round Implementation
- Modified `src/mesh/authority.rs` to implement a BFT Cross-Check.
- Implemented `fetch_peer_cross_check` to query peer authorities with `BFT_CROSS_CHECK <digest_hex>`.
- In `generate_consensus`, the authority now queries all peers before finalizing the `ConsensusDocument`. If a peer independently computes the exact same digest for their relay view, they sign the digest and return the signature.
- The authority aggregates these signatures to achieve the `2f + 1` quorum requirement *before* the document is ever served to a client, fixing the critical issue where malicious authorities could push a disjoint, false view.

### 3. PoW Validation in Gossip (Fixing False View Propagation)
- Found and fixed a vulnerability where `reconcile_relays` only verified identity signatures but NOT Proof-of-Work when accepting relayed descriptors from peer gossip.
- Added strict `verify_pow` and timestamp checks into the peer gossip loop, preventing a single malicious authority from flooding the honest authorities with unverified, fake relays.

### 4. Adversarial Simulation
- Created `tests/bft_adversarial.rs` to simulate `N=4` authorities, tolerating `f=1` malicious authority.
- The simulation empirically demonstrates that an honest authority can successfully generate a consensus document with `2f + 1` signatures by cross-checking with the remaining honest authorities, even when the malicious authority drops out or serves a mismatched digest.

## Status

**Tier 2 is COMPLETE.** The system now enforces a real, BFT cross-checked quorum at the directory level prior to serving consensus documents.
