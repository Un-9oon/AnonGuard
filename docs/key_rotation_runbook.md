# Authority Key Rotation Runbook

## Objective
To safely rotate the identity and signing keys of a directory authority without causing consensus failures, network partition, or downtime.

## Prerequisites
- Physical or secure remote access to the HSM or encrypted keystore.
- 2f+1 quorum of authorities must be online and healthy before beginning.
- Coordination with at least one other independent authority operator (depending on key ceremony constraints).

## Procedure

1. **Pre-flight Checks**
   - Verify network health via Grafana dashboards: `generate_consensus` success rate must be 100% over the last 15 minutes.
   - Run `anonguard-cli node status` to ensure all peers are reachable.

2. **Generate Next Epoch Keypair**
   - Use the secure offline machine to generate the new Ed25519 keypair.
   - Export the public key.

3. **Gossip the Key Rotation Intent**
   - Broadcast a `KeyRotationIntent` document containing the new public key, signed by the *old* private key.
   - Ensure the intent is registered by the other authorities (check logs for `Accepted KeyRotationIntent from [NodeID]`).

4. **Grace Period**
   - Wait for the next consensus epoch boundary to ensure all nodes have agreed on the new key.
   - During this window, both the old and new keys may be accepted depending on the specific protocol implementation rules.

5. **Apply New Key and Restart**
   - Load the new private key into the authority node's HSM/keystore.
   - Restart the authority service gracefully (`systemctl restart anonguard-authority`).

6. **Post-Rotation Verification**
   - Verify the node rejoins the consensus pool successfully.
   - Verify the next consensus document includes signatures from the new key.
   - Destroy or securely archive the old private key according to retention policy.

## Tabletop Exercise Log
*Must be completed against the Phase 2 testnet.*
- **Exercise Date:**
- **Scenario:** (e.g., Authority A's signing key was compromised)
- **Outcome:** (e.g., Successfully rotated without dropping consensus)
- **Lessons Learned / Adjustments Made:**
