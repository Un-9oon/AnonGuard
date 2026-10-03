# AnonGuard Testnet Report (Beta)

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
- **Outcome:** (Verify PoW + subnet diversity prevented them from dominating circuit selection)

### 2. Mid-Circuit Relay Kill
- **Date:**
- **Method:** Terminate process on a middle relay actively routing traffic.
- **Outcome:** (Verify client fail-over and kill-switch behavior worked as expected)

### 3. Authority Partitioning (Split-Brain)
- **Date:**
- **Method:** Isolate 2 authorities from the other 2.
- **Outcome:** (Verify `ERROR_BFT_QUORUM_NOT_REACHED` is triggered per Phase 0 fix)

### 4. Malicious Exit Node
- **Date:**
- **Method:** Intentionally throttle or tamper with exit traffic.
- **Outcome:** (Verify graceful handling by clients and the network)

## Incidents & Resolutions
*(Log any unplanned downtime, real incidents, or unexpected behavior here, and how the runbook was applied)*
