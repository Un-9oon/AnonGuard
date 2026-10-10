//! Mandatory composite identities used by the coordinated v6 network protocol.
//! A 32-byte public pin hashes both public-key components. Proofs carry the full
//! versioned key and require both classical and post-quantum signatures.
use super::hybrid_identity::{HybridPublicKey, HybridSigningKey, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::io;
use zeroize::Zeroizing;

pub const PROOF_SIZE: usize = PUBLIC_KEY_SIZE + SIGNATURE_SIZE;

/// Compact, bounded wire/storage encoding avoids JSON arrays of thousands of integers.
pub mod proof_encoding {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() > super::PROOF_SIZE.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom("Oversized hybrid proof"));
        }
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone)]
pub struct SigningKey(HybridSigningKey);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerifyingKey([u8; 32]);
#[derive(Clone, Debug)]
pub struct Signature(Vec<u8>);
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HybridSigningKey")
            .field(&self.verifying_key())
            .finish()
    }
}

impl SigningKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seeds = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(seeds.as_mut());
        Self(HybridSigningKey::from_seeds(&seeds))
    }
    /// Deterministic test-fixture constructor. Production storage uses paired seeds.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        let mut seeds = Zeroizing::new([0u8; 64]);
        seeds[..32].copy_from_slice(seed);
        let mut hash = Sha256::new();
        hash.update(b"AnonGuard-test-fixture-PQ-seed-v6");
        hash.update(seed);
        seeds[32..].copy_from_slice(&hash.finalize());
        Self(HybridSigningKey::from_seeds(&seeds))
    }
    pub fn from_hybrid(key: HybridSigningKey) -> Self {
        Self(key)
    }
    pub fn hybrid(&self) -> &HybridSigningKey {
        &self.0
    }
    pub fn classical_key(&self) -> &ed25519_dalek::SigningKey {
        self.0.classical_key()
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.public_key().fingerprint())
    }
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        self.0.private_bundle()
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        let key = self.0.public_key();
        let mut proof = key.encode().to_vec();
        proof.extend_from_slice(
            &self
                .0
                .sign(b"network-identity-v6", message)
                .expect("bounded protocol message"),
        );
        Signature(proof)
    }
}
impl VerifyingKey {
    pub fn from_bytes(pin: &[u8; 32]) -> io::Result<Self> {
        if *pin == [0; 32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Zero identity pin",
            ));
        }
        Ok(Self(*pin))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn is_weak(&self) -> bool {
        self.0 == [0; 32]
    }
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> io::Result<()> {
        let key = signature.public_key()?;
        if key.fingerprint() != self.0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Composite identity pin mismatch",
            ));
        }
        key.verify(
            b"network-identity-v6",
            message,
            &signature.0[PUBLIC_KEY_SIZE..],
        )
    }
}
impl Signature {
    pub fn component_pins(&self) -> io::Result<([u8; 32], [u8; 32])> {
        let key = self.public_key()?;
        Ok((
            key.classical_bytes(),
            Sha256::digest(key.post_quantum_bytes()).into(),
        ))
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    pub fn from_slice(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != PROOF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid composite proof size",
            ));
        }
        Ok(Self::from_bytes(bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    pub fn public_key(&self) -> io::Result<HybridPublicKey> {
        if self.0.len() != PROOF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid composite proof size",
            ));
        }
        HybridPublicKey::decode(&self.0[..PUBLIC_KEY_SIZE])
    }
}
