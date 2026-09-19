//! Directory Authority Node Implementation.
//!
//! Collects authenticated volunteer relay registrations, validates Proof-of-Work,
//! and issues cryptographically signed consensus documents.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::mesh::consensus::{ConsensusDocument, RelayDescriptor};
use crate::mesh::sybil::{current_timestamp_secs, verify_pow, DEFAULT_POW_DIFFICULTY};
use crate::mesh::transport::SecureTransportSession;

/// TTL for relay entries: relays not refreshed within 2 hours are evicted.
const RELAY_TTL_SECS: u64 = 7200;


pub const DEFAULT_MAX_AUTHORITY_CONNECTIONS: usize = 512;

pub struct DirectoryAuthority {
    pub authority_id: String,
    signing_key: SigningKey,
    listen_addr: String,
    active_relays: Arc<RwLock<HashMap<String, RelayDescriptor>>>,
    pub pow_difficulty: u32,
    connection_semaphore: Arc<tokio::sync::Semaphore>,
    nonce_registry: Arc<crate::mesh::sybil::NonceRegistry>,
}

impl DirectoryAuthority {
    /// Creates a new DirectoryAuthority with an ephemeral signing key (useful for tests).
    pub fn new(authority_id: String, listen_addr: String) -> Self {
        Self::with_difficulty(authority_id, listen_addr, DEFAULT_POW_DIFFICULTY)
    }

    /// Creates a new DirectoryAuthority, always generating a fresh ephemeral key.
    ///
    /// For production use, prefer `with_persistent_key` which loads or creates a stable key.
    pub fn with_difficulty(authority_id: String, listen_addr: String, pow_difficulty: u32) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            authority_id,
            signing_key,
            listen_addr,
            active_relays: Arc::new(RwLock::new(HashMap::new())),
            pow_difficulty,
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(
                DEFAULT_MAX_AUTHORITY_CONNECTIONS,
            )),
            nonce_registry: Arc::new(crate::mesh::sybil::NonceRegistry::new()),
        }
    }

    /// Loads or creates the authority signing key from `key_path`, creating the file with
    /// mode 0o600 (owner-read/write only) if it does not already exist.
    ///
    /// Treats a corrupt key file or an unwritable path as **fatal** — logs the error and
    /// calls `std::process::exit(1)`.  Silently generating a new key on corruption would
    /// invalidate all pinned consensus documents already distributed to relays.
    pub fn load_or_create_signing_key(key_path: impl AsRef<Path>) -> SigningKey {
        use std::io::Read;

        let path = key_path.as_ref();
        if path.exists() {
            // Load existing key
            let mut file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => {
                    error!("FATAL: Cannot open authority key file {:?}: {}", path, e);
                    std::process::exit(1);
                }
            };
            let mut bytes = Vec::new();
            if let Err(e) = file.read_to_end(&mut bytes) {
                error!("FATAL: Cannot read authority key file {:?}: {}", path, e);
                std::process::exit(1);
            }
            let arr: [u8; 32] = match bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    error!(
                        "FATAL: Authority key file {:?} is corrupt (expected 32 bytes, got {}). \
                        Delete the file to generate a fresh key, but note this will invalidate \
                        all previously distributed consensus documents.",
                        path,
                        bytes.len()
                    );
                    std::process::exit(1);
                }
            };
            SigningKey::from_bytes(&arr)
        } else {
            // Create new key and persist it at 0o600
            let key = SigningKey::generate(&mut OsRng);
            Self::write_key_file(path, key.as_bytes());
            key
        }
    }

    fn write_key_file(path: &Path, bytes: &[u8; 32]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => {
                error!("FATAL: Cannot create authority key file {:?}: {}", path, e);
                std::process::exit(1);
            }
        };
        if let Err(e) = file.write_all(bytes) {
            error!("FATAL: Cannot write authority key file {:?}: {}", path, e);
            std::process::exit(1);
        }
        // Ensure the OS-level permissions are 0o600 even on existing files
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            error!("FATAL: Cannot set permissions on authority key file {:?}: {}", path, e);
            std::process::exit(1);
        }
    }

    /// Creates a DirectoryAuthority with a persistent signing key loaded from `key_path`.
    pub fn with_persistent_key(
        authority_id: String,
        listen_addr: String,
        pow_difficulty: u32,
        key_path: impl AsRef<Path>,
    ) -> Self {
        let signing_key = Self::load_or_create_signing_key(key_path);
        Self {
            authority_id,
            signing_key,
            listen_addr,
            active_relays: Arc::new(RwLock::new(HashMap::new())),
            pow_difficulty,
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(
                DEFAULT_MAX_AUTHORITY_CONNECTIONS,
            )),
            nonce_registry: Arc::new(crate::mesh::sybil::NonceRegistry::new()),
        }
    }


    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Registers a relay after verifying its Proof-of-Work and Ed25519 identity signature.
    pub async fn register_relay(&self, descriptor: RelayDescriptor) -> Result<(), String> {
        if !descriptor.verify_identity() {
            return Err("Invalid or missing Ed25519 cryptographic identity signature".to_string());
        }

        let now = current_timestamp_secs();
        let is_valid_pow = verify_pow(
            &descriptor.node_id,
            descriptor.registered_at,
            descriptor.pow_nonce,
            self.pow_difficulty,
            now,
        );

        if !is_valid_pow {
            return Err("Invalid or insufficient Proof-of-Work challenge solution".to_string());
        }

        if self
            .nonce_registry
            .check_and_record(&descriptor.node_id, descriptor.pow_nonce, now)
        {
            return Err("PoW replay attack detected".to_string());
        }

        let mut relays = self.active_relays.write().await;
        if let Some(existing) = relays.get(&descriptor.node_id) {
            if existing.identity_key_ed25519 != descriptor.identity_key_ed25519 {
                return Err(format!(
                    "Relay impersonation prevented: node_id '{}' already claimed by another Ed25519 key",
                    descriptor.node_id
                ));
            }
            if descriptor.registered_at <= existing.registered_at {
                return Err(
                    "Replay attack prevented: registration timestamp is not newer".to_string(),
                );
            }
        }

        info!(
            "Authority [{}]: Registered verified relay {} ({}:{})",
            self.authority_id, descriptor.node_id, descriptor.host, descriptor.port
        );
        relays.insert(descriptor.node_id.clone(), descriptor);
        Ok(())
    }

    /// Generates and signs the current consensus document.
    ///
    /// Evicts relay entries that have not refreshed within `RELAY_TTL_SECS` (2 hours)
    /// before building the consensus — prevents unbounded map growth under relay churn (#5).
    pub async fn generate_consensus(&self) -> ConsensusDocument {
        let now = current_timestamp_secs();
        {
            let mut relays = self.active_relays.write().await;
            relays.retain(|id, r| {
                let age = now.saturating_sub(r.registered_at);
                if age > RELAY_TTL_SECS {
                    info!("Authority [{}]: Evicting stale relay {} (age {}s > TTL {}s)",
                        self.authority_id, id, age, RELAY_TTL_SECS);
                    false
                } else {
                    true
                }
            });
        }

        let relays = self.active_relays.read().await;
        let relay_list: Vec<RelayDescriptor> = relays.values().cloned().collect();

        let mut consensus = ConsensusDocument::new(
            now,
            now + 3600, // Valid for 1 hour
            relay_list,
        );

        consensus.sign_with_authority(&self.authority_id, &self.signing_key);
        consensus
    }


    /// Starts the asynchronous authority listener.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!(
            "Directory Authority [{}] listening securely on {}",
            self.authority_id, self.listen_addr
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        "Directory Authority [{}] DoS defense: max concurrent limit ({}) reached, dropped connection from {}",
                        self.authority_id, DEFAULT_MAX_AUTHORITY_CONNECTIONS, addr
                    );
                    continue;
                }
            };
            let active_relays = self.active_relays.clone();
            let auth_id = self.authority_id.clone();
            let signing_key = self.signing_key.clone();
            let pow_difficulty = self.pow_difficulty;
            let registry = self.nonce_registry.clone();

            tokio::spawn(async move {
                let _permit = permit;
                let handshake_res = tokio::time::timeout(
                    tokio::time::Duration::from_secs(15),
                    SecureTransportSession::server_handshake(stream, Some(&signing_key)),
                )
                .await;

                match handshake_res {
                    Ok(Ok(mut session)) => {
                        while let Ok(Ok(frame)) = tokio::time::timeout(
                            tokio::time::Duration::from_secs(15),
                            session.read_frame(),
                        )
                        .await
                        {
                            let text = String::from_utf8_lossy(&frame);
                            if text.starts_with("GET_CONSENSUS") {
                                let relays = active_relays.read().await;
                                let relay_list: Vec<RelayDescriptor> =
                                    relays.values().cloned().collect();
                                let now = current_timestamp_secs();
                                let mut consensus =
                                    ConsensusDocument::new(now, now + 3600, relay_list);
                                consensus.sign_with_authority(&auth_id, &signing_key);

                                if let Ok(serialized) = serde_json::to_vec(&consensus) {
                                    let _ = session.write_frame(&serialized).await;
                                }
                            } else if let Some(json_part) = text.strip_prefix("REGISTER_RELAY ") {
                                match serde_json::from_str::<RelayDescriptor>(json_part) {
                                    Ok(desc) => {
                                        let mut relays = active_relays.write().await;
                                        let now = current_timestamp_secs();
                                        if !desc.verify_identity() {
                                            let _ = session
                                                .write_frame(b"ERROR_SIGNATURE_INVALID")
                                                .await;
                                        } else if !verify_pow(
                                            &desc.node_id,
                                            desc.registered_at,
                                            desc.pow_nonce,
                                            pow_difficulty,
                                            now,
                                        ) {
                                            let _ = session.write_frame(b"ERROR_POW_INVALID").await;
                                        } else if registry.check_and_record(
                                            &desc.node_id,
                                            desc.pow_nonce,
                                            now,
                                        ) {
                                            let _ = session.write_frame(b"ERROR_POW_REPLAY").await;
                                        } else if let Some(existing) = relays.get(&desc.node_id) {
                                            if existing.identity_key_ed25519
                                                != desc.identity_key_ed25519
                                            {
                                                let _ = session
                                                    .write_frame(
                                                        b"ERROR_KEY_MISMATCH_HIJACK_PREVENTED",
                                                    )
                                                    .await;
                                            } else if desc.registered_at <= existing.registered_at {
                                                let _ = session
                                                    .write_frame(b"ERROR_REPLAY_DETECTED")
                                                    .await;
                                            } else {
                                                relays.insert(desc.node_id.clone(), desc);
                                                let _ = session.write_frame(b"OK_REGISTERED").await;
                                            }
                                        } else {
                                            relays.insert(desc.node_id.clone(), desc);
                                            let _ = session.write_frame(b"OK_REGISTERED").await;
                                        }
                                    }
                                    Err(_) => {
                                        let _ = session.write_frame(b"ERROR_MALFORMED_JSON").await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Authority secure handshake from {} failed: {}", addr, e);
                    }
                    Err(_) => {
                        warn!(
                            "Authority secure handshake from {} timed out (Slowloris defense)",
                            addr
                        );
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::sybil::solve_pow_bounded;

    #[tokio::test]
    async fn test_authority_registration_signature_and_anti_hijack() {
        let test_difficulty = 12;
        let auth = DirectoryAuthority::with_difficulty(
            "auth-1".to_string(),
            "127.0.0.1:0".to_string(),
            test_difficulty,
        );
        let mut rng = OsRng;
        let relay_key1 = SigningKey::generate(&mut rng);
        let relay_key2 = SigningKey::generate(&mut rng);

        let now = current_timestamp_secs();
        let nonce = solve_pow_bounded("relay-1", now, test_difficulty).expect("PoW failed");

        let mut desc = RelayDescriptor::new(
            "relay-1".to_string(),
            "1.2.3.4".to_string(),
            9001,
            [42u8; 32],
            [0u8; 32],
            false,
            nonce,
            now,
        );

        // 1. Without signature, registration must fail
        assert!(auth.register_relay(desc.clone()).await.is_err());

        // 2. With valid signature from relay_key1, registration succeeds
        desc.sign_with_key(&relay_key1);
        assert!(auth.register_relay(desc.clone()).await.is_ok());

        // 3. Hijacker attempts to overwrite "relay-1" with relay_key2 -> must fail
        let mut hijack_desc = RelayDescriptor::new(
            "relay-1".to_string(),
            "6.6.6.6".to_string(),
            9001,
            [99u8; 32],
            [0u8; 32],
            true,
            solve_pow_bounded("relay-1", now + 1, test_difficulty).expect("PoW failed"),
            now + 1,
        );
        hijack_desc.sign_with_key(&relay_key2);
        let hijack_res = auth.register_relay(hijack_desc).await;
        assert!(hijack_res.is_err());
        assert!(hijack_res.unwrap_err().contains("already claimed"));

        // 4. Legitimate update from relay_key1 with newer timestamp succeeds
        let mut legit_update = RelayDescriptor::new(
            "relay-1".to_string(),
            "1.2.3.4".to_string(),
            9005,
            [43u8; 32],
            [0u8; 32],
            true,
            solve_pow_bounded("relay-1", now + 5, test_difficulty).expect("PoW failed"),
            now + 5,
        );
        legit_update.sign_with_key(&relay_key1);
        assert!(auth.register_relay(legit_update).await.is_ok());
    }
}
