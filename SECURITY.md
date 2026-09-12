# Security Policy

## Supported Versions

AnonGuard actively supports and provides security patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security and integrity of AnonGuard seriously. If you discover a vulnerability, privacy leak, cryptographic weakness, or implementation flaw, please report it responsibly rather than opening a public issue.

### How to Report

1. **Email:** Send details to `security@anonguard.org` (or open a private GitHub Security Advisory).
2. **Details to Include:**
   - A detailed description of the flaw, vulnerability class, and security impact.
   - Exact steps or proof-of-concept (PoC) code to reproduce the issue.
   - Any proposed mitigations or patch suggestions if available.

### Disclosure Timeline & Expectations

- **Acknowledgment:** Within 48 hours of initial report receipt.
- **Assessment & Triage:** Within 5 business days with an initial severity rating and verification status.
- **Remediation & Patching:** High and critical severity issues will be patched and released within 14 days.
- **Public Disclosure:** Coordinated disclosure after patches are tested and published, with full attribution to the researcher.

## Security Principles & Boundaries

For explicit boundaries regarding what AnonGuard does and does not protect against (including assumptions about relays, adversaries, and traffic analysis), please consult [`THREAT_MODEL.md`](./THREAT_MODEL.md).
