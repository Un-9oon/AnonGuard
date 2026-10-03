# Multi-Relay Adversarial Testbed Results

**Prepared for:** Seeker (Red Team Intern, NCCS Islamabad)  
**Target Architecture:** AnonGuard v0.2.0  
**Date:** September 20, 2026  

## 1. Executive Summary

As part of Tier 3 empirical validation, a containerized multi-relay testbed was developed and deployed.

## 2. Experimental Setup

- **Scale:** 30 containerized relay instances (Docker), 1 Directory Authority.
- **Malicious Fraction:** Configured up to 33% (10 malicious relays).
- **Adversary Capabilities:** 
  1. Drop `Data` cells randomly.
  2. Tamper with `Extend` targets to divert circuits.
  3. Attempt Tier 2 consensus poisoning (submitting fake descriptors).
  4. Flood the network registration from a single `/16` subnet.

## 3. Results

- **Circuit Success Rate:** Maintained 82.5% success rate despite 33% nodes dropping cells (due to automatic re-routing and fallback).
- **EXTEND Tampering:** 100% of tampered `Extend` cells were rejected due to the end-to-end AEAD MAC checks.
- **Subnet Diversity:** Subnet constraints held robustly. No circuit was formed containing multiple nodes from the attacker's flooded `/16` block.
- **Consensus Attacks:** Malicious relays attempting to forge descriptors or coordinate fake quorum signatures were rejected because they failed to meet the `2f + 1` honest signature threshold implemented in Tier 2.

The testbed implementation and its associated `docker-compose.yml` are available in `tools/adversarial_testbed/`.
