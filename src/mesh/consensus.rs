//! Distributed Multi-Authority Directory Consensus System.
//!
//! Replaces single-point-of-failure trackers with a cryptographically signed,
//! M-of-N quorum consensus protocol modeled after Tor Directory Authorities.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// An individual relay descriptor submitted by volunteer nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayDescriptor {
    pub node_id: String,
    pub host: String,
    pub port: u16,
    pub onion_key_x25519: [u8; 32],
    pub identity_key_ed25519: [u8; 32],
    pub is_exit: bool,
    pub pow_nonce: u64,
    pub registered_at: u64,
    pub signature: Vec<u8>,
}

impl RelayDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: String,
        host: String,
        port: u16,
        onion_key_x25519: [u8; 32],
        identity_key_ed25519: [u8; 32],
        is_exit: bool,
        pow_nonce: u64,
        registered_at: u64,
    ) -> Self {
        Self {
            node_id,
            host,
            port,
            onion_key_x25519,
            identity_key_ed25519,
            is_exit,
            pow_nonce,
            registered_at,
            signature: Vec::new(),
        }
    }

    /// Computes canonical bytes to sign for this descriptor.
    pub fn compute_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AnonGuard-RelayDescriptor-v1");
        bytes.extend_from_slice(self.node_id.as_bytes());
        bytes.extend_from_slice(self.host.as_bytes());
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes.extend_from_slice(&self.onion_key_x25519);
        bytes.extend_from_slice(&self.identity_key_ed25519);
        bytes.push(if self.is_exit { 1 } else { 0 });
        bytes.extend_from_slice(&self.pow_nonce.to_be_bytes());
        bytes.extend_from_slice(&self.registered_at.to_be_bytes());
        bytes
    }

    /// Signs this descriptor using the relay's private Ed25519 signing key.
    pub fn sign_with_key(&mut self, key: &SigningKey) {
        self.identity_key_ed25519 = key.verifying_key().to_bytes();
        let signing_bytes = self.compute_signing_bytes();
        let sig = key.sign(&signing_bytes);
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verifies the cryptographic Ed25519 signature binding this descriptor to its identity key.
    pub fn verify_identity(&self) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.identity_key_ed25519) else {
            return false;
        };
        let Ok(sig_bytes): Result<&[u8; 64], _> = self.signature.as_slice().try_into() else {
            return false;
        };
        let signature = Signature::from_bytes(sig_bytes);
        let signing_bytes = self.compute_signing_bytes();
        verifying_key.verify(&signing_bytes, &signature).is_ok()
    }
}

/// A cryptographic signature by an independent Directory Authority over the consensus digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySignature {
    pub authority_id: String,
    pub signature_bytes: Vec<u8>,
}

/// The network-wide consensus document determining verified, active relays.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusDocument {
    pub valid_after: u64,
    pub valid_until: u64,
    pub relays: Vec<RelayDescriptor>,
    pub signatures: Vec<AuthoritySignature>,
}

impl ConsensusDocument {
    pub fn new(valid_after: u64, valid_until: u64, relays: Vec<RelayDescriptor>) -> Self {
        Self {
            valid_after,
            valid_until,
            relays,
            signatures: Vec::new(),
        }
    }

    /// Computes the deterministic SHA-256 digest of the consensus content (excluding signatures).
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.valid_after.to_be_bytes());
        hasher.update(self.valid_until.to_be_bytes());

        // Sort relays deterministically by node_id
        let mut sorted_relays = self.relays.clone();
        sorted_relays.sort_by(|a, b| a.node_id.cmp(&b.node_id));

        for r in &sorted_relays {
            hasher.update(r.node_id.as_bytes());
            hasher.update(r.host.as_bytes());
            hasher.update(r.port.to_be_bytes());
            hasher.update(r.onion_key_x25519);
            hasher.update(r.identity_key_ed25519);
            hasher.update([if r.is_exit { 1 } else { 0 }]);
        }

        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        digest
    }

    /// Signs this consensus with a Directory Authority's private key.
    pub fn sign_with_authority(&mut self, authority_id: &str, signing_key: &SigningKey) {
        let digest = self.compute_digest();
        let signature = signing_key.sign(&digest);
        self.signatures.push(AuthoritySignature {
            authority_id: authority_id.to_string(),
            signature_bytes: signature.to_bytes().to_vec(),
        });
    }

    /// Verifies that the consensus has valid signatures from at least `quorum_threshold`
    /// recognized Directory Authorities.
    pub fn verify_quorum(
        &self,
        trusted_authorities: &HashMap<String, VerifyingKey>,
        quorum_threshold: usize,
        current_time: u64,
    ) -> bool {
        // 1. Check validity window
        if current_time < self.valid_after || current_time > self.valid_until {
            return false;
        }

        let digest = self.compute_digest();
        let mut valid_auth_count = 0;
        let mut verified_authorities = Vec::new();

        for sig in &self.signatures {
            if verified_authorities.contains(&sig.authority_id) {
                continue; // Avoid duplicate votes from same authority
            }

            if let Some(pubkey) = trusted_authorities.get(&sig.authority_id) {
                if let Ok(sig_bytes) = sig.signature_bytes.as_slice().try_into() {
                    let ed_sig = Signature::from_bytes(sig_bytes);
                    if pubkey.verify(&digest, &ed_sig).is_ok() {
                        valid_auth_count += 1;
                        verified_authorities.push(sig.authority_id.clone());
                    }
                }
            }
        }

        valid_auth_count >= quorum_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_multi_authority_consensus_and_quorum() {
        let mut csprng = OsRng;

        // 1. Create 3 independent Directory Authorities (e.g. Zurich, Reykjavik, Tokyo)
        let auth1_priv = SigningKey::generate(&mut csprng);
        let auth2_priv = SigningKey::generate(&mut csprng);
        let auth3_priv = SigningKey::generate(&mut csprng);

        let mut trusted_authorities = HashMap::new();
        trusted_authorities.insert("auth-zurich".to_string(), auth1_priv.verifying_key());
        trusted_authorities.insert("auth-reykjavik".to_string(), auth2_priv.verifying_key());
        trusted_authorities.insert("auth-tokyo".to_string(), auth3_priv.verifying_key());

        // 2. Build consensus document with 2 active signed relays
        let relay1_key = SigningKey::generate(&mut csprng);
        let relay2_key = SigningKey::generate(&mut csprng);

        let mut r1 = RelayDescriptor::new(
            "relay-alpha".to_string(),
            "198.51.100.10".to_string(),
            9001,
            [1u8; 32],
            [0u8; 32],
            false,
            12345,
            1000,
        );
        r1.sign_with_key(&relay1_key);
        assert!(r1.verify_identity());

        let mut r2 = RelayDescriptor::new(
            "relay-beta".to_string(),
            "203.0.113.20".to_string(),
            9002,
            [2u8; 32],
            [0u8; 32],
            true,
            67890,
            1000,
        );
        r2.sign_with_key(&relay2_key);
        assert!(r2.verify_identity());

        let relays = vec![r1, r2];

        let mut consensus = ConsensusDocument::new(1000, 4600, relays);

        // 3. Authorities 1 and 2 sign the document (2-of-3 Quorum)
        consensus.sign_with_authority("auth-zurich", &auth1_priv);
        consensus.sign_with_authority("auth-reykjavik", &auth2_priv);

        // Quorum of 2 should pass
        assert!(consensus.verify_quorum(&trusted_authorities, 2, 2000));

        // Quorum of 3 should fail because Tokyo has not signed
        assert!(!consensus.verify_quorum(&trusted_authorities, 3, 2000));

        // Expired timestamp should fail
        assert!(!consensus.verify_quorum(&trusted_authorities, 2, 5000));
    }
}
