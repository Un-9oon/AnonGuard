# AnonGuard Relay Operator Guide

Thank you for volunteering to run an AnonGuard relay! This document outlines the technical, operational, and legal responsibilities of running a node.

## Node Types

### 1. Guard / Middle Relays
These relays route encrypted traffic from clients to other AnonGuard relays. They never see the original IP of the destination server, nor the unencrypted traffic. 
- **Risk Level:** Low.
- **Legal Posture:** Since you only transmit encrypted bytes to other nodes within the network, you are generally protected under common carrier and safe harbor provisions in most jurisdictions.

### 2. Exit Relays
Exit relays form the final hop. They decrypt the outer layer of the packet and send the traffic to its final destination on the open internet (e.g., a website). The destination server sees the IP address of the Exit Relay, not the original client.
- **Risk Level:** High.
- **Legal Posture:** Exit relays are subject to DMCA notices, abuse complaints, and potential law enforcement inquiries. 

## Exit Relay Policy (Current Status)
**DECISION:** For the initial Beta Release, we are **restricting the public network to Guard/Middle relays only**. Exit relays will be exclusively operated by the core team and trusted partners until Phase 4 (External Audit) is complete and a standardized Abuse Response Template is finalized.

## Minimum Requirements
- **Bandwidth:** At least 100 Mbps unmetered.
- **Uptime:** 99% expected.
- **Hardware:** 2 CPU cores, 4GB RAM minimum (RMT morphing requires moderate memory overhead).
- **Network:** A dedicated public IPv4 address.

## Security Best Practices
1. Run AnonGuard on a dedicated VPS or server. Do not co-locate with your personal services.
2. Keep the host OS updated (enable unattended upgrades).
3. Disable password authentication for SSH (use Ed25519 keys).
4. Do not log traffic. AnonGuard does not log connections by default; do not modify it to do so.

## Abuse Response (For Future Exit Operators)
When public Exit operation opens, you MUST:
1. Register a dedicated abuse contact email in your relay configuration.
2. Use our provided standard response templates for DMCA and abuse inquiries.
3. Understand your local jurisdiction's safe harbor laws (e.g., Section 230 in the US).
