# Relay Key Rotation and Decommissioning

Relay operators must safeguard their long-term Ed25519 identity key, which anchors their reputation and PoW registration. 

## Key Rotation Procedure
If a relay operator needs to gracefully rotate their key (e.g., proactive security rotation):
1. **Generate New Key**: Stop the relay and generate a new keypair `new_identity.key`.
2. **Re-register**: Start the relay with the new key. It will automatically generate a new registration descriptor, solve the PoW challenge, and submit it to the tracker authorities.
3. **Warm-up**: The new key starts with zero historical reputation in the consensus. Traffic will gradually ramp up over hours as the authorities observe its uptime and bandwidth.

## Key Compromise and Decommissioning
If a relay's identity key is stolen or the host is compromised:
1. **Revocation**: The operator must notify the network administrators out-of-band to manually blacklist the compromised public key at the directory authorities.
2. **Scrub Host**: Destroy the host and delete the compromised key from backups.
3. **Fresh Start**: Follow the rotation procedure to generate a new key on a fresh host.

*Note: AnonGuard does not yet support in-band cryptographic revocation certificates.*
