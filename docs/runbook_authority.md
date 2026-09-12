# Authority Bootstrapping Runbook

The AnonGuard network consensus relies on directory authorities. To stand up a new production network or bootstrap 3 independent directory authorities, follow this runbook.

## 1. Provision Infrastructure
- Provision three geographically diverse hosts (e.g., US, EU, AS).
- Ensure ports `9001` (Relay) and `8080` (Tracker HTTP) are open.

## 2. Generate Authority Keys
On each node, initialize the long-term Ed25519 identity key:
```bash
anonguard-daemon --init-authority --key-path /etc/anonguard/auth.key
```
This generates a private key file. **Back this up securely offline**. Extract the public key.

## 3. Configure the Quorum
- Gather the 3 public keys.
- Create a network configuration file (`network_config.json`) listing all 3 authorities' IPs and Ed25519 public keys.
- Distribute this file to all relays and clients that wish to join this network.

## 4. Start the Authority Nodes
On each node, start the authority tracker:
```bash
anonguard-daemon --role tracker --bind 0.0.0.0:8080 --key-path /etc/anonguard/auth.key
```

## 5. Key Rotation (Compromise Scenario)
If an authority key is compromised:
1. Generate a new keypair offline.
2. Publish an out-of-band update to the `network_config.json` signaling the key transition to all clients and relays.
3. Restart the compromised authority with the new key.
4. Clients will refuse consensus documents signed by the old key immediately upon receiving the configuration update.
