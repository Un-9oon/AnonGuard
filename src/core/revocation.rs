//! Offline quorum-authorized, cumulative identity retirement for owned deployments.
//! Policies take effect at coordinated restart; this is not online revocation gossip.
use crate::mesh::AuthoritySignature;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

pub const MAX_REVOKED_IDENTITIES: usize = 512;
pub const MAX_POLICY_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPolicy {
    pub version: u32,
    pub generation: u64,
    pub authority_set: [u8; 32],
    pub revoked: Vec<[u8; 32]>,
    pub signatures: Vec<AuthoritySignature>,
}

pub fn authority_set_digest(keys: &HashMap<String, VerifyingKey>) -> [u8; 32] {
    let mut keys: Vec<_> = keys.iter().collect();
    keys.sort_by(|a, b| a.0.cmp(b.0));
    let mut digest = Sha256::new();
    digest.update(b"AnonGuard-RevocationAuthoritySet-v1");
    digest.update((keys.len() as u32).to_be_bytes());
    for (id, key) in keys {
        digest.update((id.len() as u32).to_be_bytes());
        digest.update(id.as_bytes());
        digest.update(key.as_bytes());
    }
    digest.finalize().into()
}

impl RevocationPolicy {
    pub fn new(
        generation: u64,
        keys: &HashMap<String, VerifyingKey>,
        revoked: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            version: 1,
            generation,
            authority_set: authority_set_digest(keys),
            revoked,
            signatures: Vec::new(),
        }
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.version != 1
            || self.generation == 0
            || self.revoked.len() > MAX_REVOKED_IDENTITIES
            || self.signatures.len() > 16
        {
            return Err("Unsupported or oversized identity retirement policy".into());
        }
        let mut identities = HashSet::new();
        for identity in &self.revoked {
            let key = VerifyingKey::from_bytes(identity).map_err(|_| "Invalid retired identity")?;
            if key.is_weak() || !identities.insert(*identity) {
                return Err("Weak or duplicate retired identity".into());
            }
        }
        for signature in &self.signatures {
            if signature.authority_id.is_empty()
                || signature.authority_id.len() > 128
                || signature.signature_bytes.len() != 64
            {
                return Err("Invalid retirement signature shape".into());
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"AnonGuard-IdentityRetirement-v1");
        digest.update(self.version.to_be_bytes());
        digest.update(self.generation.to_be_bytes());
        digest.update(self.authority_set);
        let mut identities = self.revoked.clone();
        identities.sort();
        digest.update((identities.len() as u32).to_be_bytes());
        for identity in identities {
            digest.update(identity);
        }
        digest.finalize().into()
    }

    pub fn sign(&mut self, authority_id: &str, key: &SigningKey) -> Result<(), String> {
        self.validate_shape()?;
        if authority_id.is_empty()
            || authority_id.len() > 128
            || self
                .signatures
                .iter()
                .any(|s| s.authority_id == authority_id)
            || self.signatures.len() == 16
        {
            return Err("Invalid or duplicate retirement signer".into());
        }
        let signature = key.sign(&self.digest()).to_bytes().to_vec();
        self.signatures.push(AuthoritySignature {
            authority_id: authority_id.into(),
            signature_bytes: signature,
        });
        Ok(())
    }

    pub fn verify(
        &self,
        keys: &HashMap<String, VerifyingKey>,
        quorum: usize,
    ) -> Result<(), String> {
        self.validate_shape()?;
        let distinct: HashSet<_> = keys.values().map(|k| k.to_bytes()).collect();
        if keys.is_empty()
            || keys.len() > 16
            || distinct.len() != keys.len()
            || keys.values().any(VerifyingKey::is_weak)
            || quorum <= (2 * keys.len()) / 3
            || quorum > keys.len()
            || self.authority_set != authority_set_digest(keys)
        {
            return Err(
                "Identity retirement requires the exact pinned authority set and >2/3 quorum"
                    .into(),
            );
        }
        let mut signers = HashSet::new();
        let digest = self.digest();
        for signature in &self.signatures {
            if let Some(key) = keys.get(&signature.authority_id) {
                let bytes: &[u8; 64] = signature
                    .signature_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid retirement signature")?;
                if key
                    .verify_strict(&digest, &Signature::from_bytes(bytes))
                    .is_ok()
                {
                    signers.insert(key.to_bytes());
                }
            }
        }
        if signers.len() < quorum {
            return Err("Identity retirement policy lacks a valid authority quorum".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedPolicy {
    generation: u64,
    digest: [u8; 32],
    revoked: Vec<[u8; 32]>,
}

struct PolicyLock {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
}
impl Drop for PolicyLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Journal absence permits opt-in deployment; after enrollment, omission is fatal.
/// The journal must be preserved in administrator-controlled persistent storage.
pub fn load_and_commit(
    policy_path: Option<&Path>,
    journal: &Path,
    keys: &HashMap<String, VerifyingKey>,
    quorum: usize,
) -> Result<HashSet<[u8; 32]>, String> {
    // Serialize check-and-commit across processes. A crash leaves a stale lock;
    // operators must stop all users of this state before explicitly removing it.
    let _lock = if policy_path.is_some() {
        if let Some(parent) = journal.parent().filter(|path| !path.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|_| "Cannot prepare retirement state directory")?;
        }
        let path = journal.with_extension("lock");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|_| {
            "Retirement state is locked; inspect concurrent process or interrupted startup"
        })?;
        Some(PolicyLock {
            path,
            file: Some(file),
        })
    } else {
        None
    };
    let previous: Option<AcceptedPolicy> =
        match crate::core::storage::read_bounded_file(journal, MAX_POLICY_BYTES) {
            Ok(bytes) => Some(
                serde_json::from_slice(&bytes).map_err(|_| "Invalid retirement rollback state")?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("Cannot read retirement rollback state".into()),
        };
    let Some(path) = policy_path else {
        match std::fs::symlink_metadata(journal.with_extension("lock")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(
                    "Retirement enrollment is in progress or interrupted; inspect persistent state"
                        .into(),
                )
            }
        }
        if previous.is_some() {
            return Err(
                "Enrolled deployment requires its signed identity retirement policy".into(),
            );
        }
        return Ok(HashSet::new());
    };
    let bytes = crate::core::storage::read_bounded_file(path, MAX_POLICY_BYTES)
        .map_err(|_| "Cannot read identity retirement policy")?;
    let policy: RevocationPolicy =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid identity retirement policy JSON")?;
    policy.verify(keys, quorum)?;
    let digest = policy.digest();
    let identities: HashSet<_> = policy.revoked.iter().copied().collect();
    if let Some(previous) = previous {
        if previous.generation == 0
            || previous.revoked.len() > MAX_REVOKED_IDENTITIES
            || previous
                .revoked
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .len()
                != previous.revoked.len()
        {
            return Err("Invalid retirement rollback state".into());
        }
        if policy.generation < previous.generation
            || (policy.generation == previous.generation && digest != previous.digest)
            || previous
                .revoked
                .iter()
                .any(|identity| !identities.contains(identity))
        {
            return Err(
                "Retirement rollback, equivocation or identity resurrection rejected".into(),
            );
        }
    }
    let accepted = AcceptedPolicy {
        generation: policy.generation,
        digest,
        revoked: policy.revoked,
    };
    let bytes = serde_json::to_vec(&accepted).map_err(|_| "Cannot encode retirement state")?;
    crate::core::storage::atomic_write(journal, &bytes)
        .map_err(|_| "Cannot persist identity retirement policy")?;
    Ok(identities)
}
