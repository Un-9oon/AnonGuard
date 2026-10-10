//! Versioned Ed25519 AND ML-DSA-65 identity proofs.
//! The coordinated v6 protocol uses these paired identities for mandatory authentication.
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use ml_dsa::{Keypair, MlDsa65, Signer as _, Verifier as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"AGID0001";
pub const PUBLIC_KEY_SIZE: usize = 8 + 32 + 1952;
pub const SIGNATURE_SIZE: usize = 8 + 64 + 3309;
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// FIPS 203 encapsulation-key modulus check for the three ML-KEM-768 polynomials.
/// The final 32 bytes are the unconstrained matrix seed.
pub fn mlkem768_public_is_canonical(bytes: &[u8]) -> bool {
    bytes.len() == 1184
        && bytes[..1152].chunks_exact(3).all(|triple| {
            let first = u16::from(triple[0]) | (u16::from(triple[1] & 15) << 8);
            let second = u16::from(triple[1] >> 4) | (u16::from(triple[2]) << 4);
            first < 3329 && second < 3329
        })
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid hybrid identity proof")
}

#[derive(Clone)]
pub struct HybridSigningKey {
    classical: SigningKey,
    post_quantum: ml_dsa::SigningKey<MlDsa65>,
}

#[derive(Clone)]
pub struct HybridPublicKey {
    encoded: Vec<u8>,
    classical: VerifyingKey,
    post_quantum: ml_dsa::VerifyingKey<MlDsa65>,
}

impl HybridSigningKey {
    pub fn classical_key(&self) -> &SigningKey {
        &self.classical
    }

    pub fn private_bundle(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(72));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.classical.to_bytes());
        bytes.extend_from_slice(self.post_quantum.as_seed().as_slice());
        bytes
    }
    /// Read only the explicit paired-key format. Legacy Ed-only files fail closed.
    pub fn read_private_file(path: &std::path::Path) -> io::Result<Self> {
        use std::io::Read;
        let file = crate::core::storage::open_regular_file(path, 72)?;
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Hybrid identity must be private",
                ));
            }
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(73));
        file.take(73).read_to_end(&mut bytes)?;
        if bytes.len() != 72 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let mut seeds = Zeroizing::new([0u8; 64]);
        seeds.copy_from_slice(&bytes[8..]);
        Ok(Self::from_seeds(&seeds))
    }

    /// Race-safe publication without replacement or silent legacy-key conversion.
    /// The caller must use an administrator-controlled directory.
    pub fn load_or_create(path: &std::path::Path) -> io::Result<Self> {
        use std::{fs, io::Write, path::Path};
        match Self::read_private_file(path) {
            Ok(key) => return Ok(key),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(
            ".anonguard-hybrid-{:032x}.tmp",
            rand::random::<u128>()
        ));
        let result = (|| {
            let mut seeds = Zeroizing::new([0u8; 64]);
            OsRng.fill_bytes(seeds.as_mut());
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(MAGIC)?;
            file.write_all(seeds.as_ref())?;
            file.sync_all()?;
            match fs::hard_link(&temporary, path) {
                Ok(()) => Ok(Self::from_seeds(&seeds)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    Self::read_private_file(path)
                }
                Err(error) => Err(error),
            }
        })();
        let cleanup = fs::remove_file(&temporary);
        let key = result?;
        cleanup?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(key)
    }

    /// Independent OS-random seeds; never derive a PQ identity from a public Ed key.
    pub fn generate() -> Self {
        let mut seeds = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(seeds.as_mut());
        Self::from_seeds(&seeds)
    }

    pub fn from_seeds(seeds: &[u8; 64]) -> Self {
        let ed: &[u8; 32] = seeds[..32].try_into().expect("fixed seed length");
        let pq = Zeroizing::new(ml_dsa::Seed::try_from(&seeds[32..]).expect("fixed seed length"));
        Self {
            classical: SigningKey::from_bytes(ed),
            post_quantum: ml_dsa::SigningKey::from_seed(&pq),
        }
    }

    pub fn public_key(&self) -> HybridPublicKey {
        let classical = self.classical.verifying_key();
        let post_quantum = self.post_quantum.verifying_key();
        let mut encoded = Vec::with_capacity(PUBLIC_KEY_SIZE);
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(classical.as_bytes());
        encoded.extend_from_slice(post_quantum.encode().as_slice());
        HybridPublicKey {
            encoded,
            classical,
            post_quantum,
        }
    }

    pub fn sign(&self, purpose: &[u8], message: &[u8]) -> io::Result<Vec<u8>> {
        let transcript = transcript(&self.public_key(), purpose, message)?;
        let ed = self.classical.sign(&transcript);
        let pq: ml_dsa::Signature<MlDsa65> = self.post_quantum.sign(&transcript);
        let mut proof = Vec::with_capacity(SIGNATURE_SIZE);
        proof.extend_from_slice(MAGIC);
        proof.extend_from_slice(&ed.to_bytes());
        proof.extend_from_slice(pq.encode().as_slice());
        Ok(proof)
    }
}

impl HybridPublicKey {
    pub fn classical_bytes(&self) -> [u8; 32] {
        self.classical.to_bytes()
    }
    pub fn post_quantum_bytes(&self) -> &[u8] {
        &self.encoded[40..]
    }
    pub fn decode(encoded: &[u8]) -> io::Result<Self> {
        if encoded.len() != PUBLIC_KEY_SIZE || &encoded[..8] != MAGIC {
            return Err(invalid());
        }
        let classical = VerifyingKey::from_bytes(encoded[8..40].try_into().map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        if classical.is_weak() {
            return Err(invalid());
        }
        let pq = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(&encoded[40..])
            .map_err(|_| invalid())?;
        let post_quantum = ml_dsa::VerifyingKey::decode(&pq);
        Ok(Self {
            encoded: encoded.to_vec(),
            classical,
            post_quantum,
        })
    }

    pub fn encode(&self) -> &[u8] {
        &self.encoded
    }

    /// Pins bind both algorithms and the wire version, not just one component.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"AnonGuard-HybridIdentity-Pin-v1");
        hash.update(&self.encoded);
        hash.finalize().into()
    }

    pub fn verify(&self, purpose: &[u8], message: &[u8], proof: &[u8]) -> io::Result<()> {
        if proof.len() != SIGNATURE_SIZE || &proof[..8] != MAGIC {
            return Err(invalid());
        }
        let transcript = transcript(self, purpose, message)?;
        let ed = ed25519_dalek::Signature::from_slice(&proof[8..72]).map_err(|_| invalid())?;
        let pq = ml_dsa::Signature::<MlDsa65>::try_from(&proof[72..]).map_err(|_| invalid())?;
        self.classical
            .verify_strict(&transcript, &ed)
            .map_err(|_| invalid())?;
        self.post_quantum
            .verify(&transcript, &pq)
            .map_err(|_| invalid())
    }
}

fn transcript(key: &HybridPublicKey, purpose: &[u8], message: &[u8]) -> io::Result<Vec<u8>> {
    if purpose.is_empty() || purpose.len() > 255 || message.len() > MAX_MESSAGE {
        return Err(invalid());
    }
    let mut result = Vec::with_capacity(64 + message.len());
    result.extend_from_slice(b"AnonGuard-HybridIdentity-Proof-v1");
    result.extend_from_slice(&key.fingerprint());
    result.push(purpose.len() as u8);
    result.extend_from_slice(purpose);
    result.extend_from_slice(&(message.len() as u64).to_be_bytes());
    result.extend_from_slice(message);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_key_is_stable_and_legacy_key_is_not_converted() {
        let directory =
            std::env::temp_dir().join(format!("ag-hybrid-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("identity");
        let first = HybridSigningKey::load_or_create(&path)
            .unwrap()
            .public_key()
            .fingerprint();
        assert_eq!(
            first,
            HybridSigningKey::load_or_create(&path)
                .unwrap()
                .public_key()
                .fingerprint()
        );
        std::fs::write(&path, [1u8; 32]).unwrap();
        assert!(HybridSigningKey::load_or_create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), [1u8; 32]);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn both_signatures_and_context_are_mandatory() {
        let signer = HybridSigningKey::from_seeds(&[7; 64]);
        let public = signer.public_key();
        let decoded = HybridPublicKey::decode(public.encode()).unwrap();
        let proof = signer.sign(b"directory", b"snapshot").unwrap();
        decoded.verify(b"directory", b"snapshot", &proof).unwrap();
        assert!(decoded.verify(b"relay", b"snapshot", &proof).is_err());
        assert!(decoded.verify(b"directory", b"changed", &proof).is_err());
        for offset in [0, 8, 72, SIGNATURE_SIZE - 1] {
            let mut altered = proof.clone();
            altered[offset] ^= 1;
            assert!(decoded.verify(b"directory", b"snapshot", &altered).is_err());
        }
        assert!(decoded
            .verify(b"directory", b"snapshot", &proof[..72])
            .is_err());
        let mut extended = proof.clone();
        extended.push(0);
        assert!(decoded
            .verify(b"directory", b"snapshot", &extended)
            .is_err());
    }

    #[test]
    fn identity_pin_binds_each_component() {
        let original = HybridSigningKey::from_seeds(&[1; 64]).public_key();
        let mut seeds = [1; 64];
        seeds[0] = 2;
        let ed_changed = HybridSigningKey::from_seeds(&seeds).public_key();
        seeds = [1; 64];
        seeds[32] = 2;
        let pq_changed = HybridSigningKey::from_seeds(&seeds).public_key();
        assert_ne!(original.fingerprint(), ed_changed.fingerprint());
        assert_ne!(original.fingerprint(), pq_changed.fingerprint());
        let mut version = original.encode().to_vec();
        version[7] ^= 1;
        assert!(HybridPublicKey::decode(&version).is_err());
        assert!(HybridPublicKey::decode(&original.encode()[..40]).is_err());
        assert!(HybridSigningKey::generate().sign(b"", b"x").is_err());
    }
}
