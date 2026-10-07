# AnonGuard Testnet Report Template

This unfilled template is not evidence of a deployed testnet or an independent review. Local automated CLI tests use one host and do not establish geographic independence or anonymity.

## Dates of Operation
**Start Date:** YYYY-MM-DD  
**End Date:** YYYY-MM-DD  
*(Minimum 4-8 weeks required)*

## Topology
- **Number of Relays:** (Minimum 3 distributed)
- **Number of Authorities:** (Minimum 4 for f=1 tolerance)
- **Geographic Diversity:** (List general regions/ASNs to prove distribution)

## Operational Metrics
- **Average Uptime:** 
- **Consensus Quorum Health:**
- **Circuit Build Success Rate:**

## Attack Simulations
*For each simulation, document the date, methodology, and outcome.*

### 1. Sybil Relay Domination Attempt
- **Date:** 
- **Method:** Span multiple Sybil nodes across various IPs.
- **Outcome:** (Record attacker identities, IP/subnet allocation, computing budget and observed selection share. PoW and subnet diversity alone do not prove Sybil resistance.)

### 2. Mid-Circuit Relay Kill
- **Date:**
- **Method:** Terminate process on a middle relay actively routing traffic.
- **Outcome:** (Measure connection closure and new circuit construction. Do not replay arbitrary TCP transactions; verify application isolation separately with direct IPv4/IPv6/DNS attempts.)

### 3. Authority Partitioning (Split-Brain)
- **Date:**
- **Method:** Isolate 2 authorities from the other 2.
- **Outcome:** (Record exact-snapshot vote counts, rejection of insufficient/conflicting certificates, retained snapshot expiry and recovery time after reconnection. Distinct frozen views may stall until the next epoch.)

### 4. Malicious Exit Node
- **Date:**
- **Method:** Intentionally throttle or tamper with exit traffic.
- **Outcome:** (Record availability effects and authenticated cell rejection. An exit can observe or alter unencrypted destination traffic; test end-to-end TLS separately.)

## Incidents & Resolutions
*(Log any unplanned downtime, real incidents, or unexpected behavior here, and how the runbook was applied)*
