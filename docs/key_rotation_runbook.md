# Authority key replacement in v3

Status: coordinated administrative procedure requiring testnet rehearsal. Automatic key-rotation intents, HSM integration and overlap acceptance are not implemented. The daemon does not provide an `anonguard-cli node status` command.

1. Inventory all clients, relays and authority peers that pin the authority, and authenticate the operator coordination channel. Confirm the remaining independent authorities meet the configured quorum; otherwise plan an outage.
2. Generate and protect a replacement Ed25519 identity using the actual supported key-file mechanism in an isolated environment. Authenticate the new public key to every operator outside the directory itself.
3. Agree on a maintenance epoch and distribute updated endpoint-bound pins. Do not accept both keys under aliased identities to inflate quorum. A compromised old key must not be the sole authentication channel for its replacement.
4. Stop the affected authority. Preserve its vote journal and identity files for incident analysis in private storage. Vote records signed by the old key cannot be loaded under the new key. Replace the key and explicitly initialize a new journal under a new protected state path; never delete client rollback state to bypass stale or conflicting directories.
5. Restart the authority and update all peers, clients and relays together. Verify pinned transport, distinct signing-key quorum and a fresh identical snapshot accepted across participants. Mixed pins may cause an outage. There is no guarantee of zero downtime.
6. Test restarts and rollback rejection, record the ceremony and revoke/archive the old identity according to operator policy. Clients with unchanged pins must fail rather than silently trust the new identity.

Do not rehearse a compromise response for the first time on a public anonymity network. A reviewed rotation/revocation protocol remains a production release gate.
