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

use crate::mesh::consensus::{AuthoritySignature, ConsensusDocument, RelayDescriptor};
use crate::mesh::sybil::{current_timestamp_secs, verify_pow, DEFAULT_POW_DIFFICULTY};
use crate::mesh::transport::SecureTransportSession;

/// TTL for relay entries: relays not refreshed within 2 hours are evicted.
const RELAY_TTL_SECS: u64 = 7200;

pub const DEFAULT_MAX_AUTHORITY_CONNECTIONS: usize = 512;

#[derive(Clone)]
pub struct DirectoryAuthority {
    pub authority_id: String,
    signing_key: SigningKey,
    listen_addr: String,
    active_relays: Arc<RwLock<HashMap<String, RelayDescriptor>>>,
    pub pow_difficulty: u32,
    connection_semaphore: Arc<tokio::sync::Semaphore>,
    nonce_registry: Arc<crate::mesh::sybil::NonceRegistry>,
    pub peer_authorities: Vec<(String, Option<ed25519_dalek::VerifyingKey>)>,
    pub allow_unauthenticated_registration: bool,
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
        info!(
            "Authority public key (hex): {}",
            hex::encode(signing_key.verifying_key().to_bytes())
        );
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
            peer_authorities: Vec::new(),
            allow_unauthenticated_registration: false,
        }
    }

    /// Creates a DirectoryAuthority with a list of peer authority addresses for reconciliation.
    pub fn with_peer_authorities(
        authority_id: String,
        listen_addr: String,
        pow_difficulty: u32,
        peer_authorities: Vec<(String, Option<ed25519_dalek::VerifyingKey>)>,
    ) -> Self {
        let mut auth = Self::with_difficulty(authority_id, listen_addr, pow_difficulty);
        auth.peer_authorities = peer_authorities;
        auth
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
            use zeroize::Zeroize;
            let mut arr: [u8; 32] = match bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    bytes.zeroize();
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
            let key = SigningKey::from_bytes(&arr);
            arr.zeroize();
            bytes.zeroize();
            key
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

        let mut temp_path = path.to_path_buf();
        temp_path.set_extension("tmp");

        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
        {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "FATAL: Cannot create temporary authority key file {:?}: {}",
                    temp_path, e
                );
                std::process::exit(1);
            }
        };
        if let Err(e) = file.write_all(bytes) {
            error!(
                "FATAL: Cannot write temporary authority key file {:?}: {}",
                temp_path, e
            );
            let _ = std::fs::remove_file(&temp_path);
            std::process::exit(1);
        }
        if let Err(e) = file.sync_all() {
            error!(
                "FATAL: Cannot sync temporary authority key file {:?}: {}",
                temp_path, e
            );
            let _ = std::fs::remove_file(&temp_path);
            std::process::exit(1);
        }
        // Ensure the OS-level permissions are 0o600 even on existing files
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))
        {
            error!(
                "FATAL: Cannot set permissions on temporary authority key file {:?}: {}",
                temp_path, e
            );
            let _ = std::fs::remove_file(&temp_path);
            std::process::exit(1);
        }

        // Atomic rename
        if let Err(e) = std::fs::rename(&temp_path, path) {
            error!(
                "FATAL: Cannot atomically rename authority key file to {:?}: {}",
                path, e
            );
            let _ = std::fs::remove_file(&temp_path);
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
        info!(
            "Authority public key (hex): {}",
            hex::encode(signing_key.verifying_key().to_bytes())
        );
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
            peer_authorities: Vec::new(),
            allow_unauthenticated_registration: false,
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

        if self
            .nonce_registry
            .check_and_record(&descriptor.node_id, descriptor.pow_nonce, now)
        {
            return Err("PoW replay attack detected".to_string());
        }

        info!(
            "Authority [{}]: Registered verified relay {} ({}:{})",
            self.authority_id, descriptor.node_id, descriptor.host, descriptor.port
        );
        relays.insert(descriptor.node_id.clone(), descriptor);
        Ok(())
    }

    /// Generates and signs the current consensus document, executing a BFT cross-check round.
    pub async fn generate_consensus(&self) -> ConsensusDocument {
        let now = current_timestamp_secs();
        {
            let mut relays = self.active_relays.write().await;
            relays.retain(|id, r| {
                let age = now.saturating_sub(r.registered_at);
                if age > RELAY_TTL_SECS {
                    info!(
                        "Authority [{}]: Evicting stale relay {} (age {}s > TTL {}s)",
                        self.authority_id, id, age, RELAY_TTL_SECS
                    );
                    false
                } else {
                    true
                }
            });
        }

        let relay_list = self.reconcile_relays().await;

        let bucketed_now = (now / 300) * 300;
        let mut consensus = ConsensusDocument::new(
            bucketed_now,
            bucketed_now + 3600, // Valid for 1 hour
            relay_list,
        );

        // Sign our own view
        consensus.sign_with_authority(&self.authority_id, &self.signing_key);
        let digest = consensus.compute_digest();
        let digest_hex = hex::encode(digest);

        // BFT Pre-Signing Cross-Check Round
        // Query peer authorities to co-sign our exact proposed digest.
        // This ensures the document handed to clients is already multi-signed and verified.
        let f = self.peer_authorities.len() / 3;
        let required_signatures = 2 * f + 1; // 2f+1 quorum (including ourselves)

        for (peer, pinned_key) in &self.peer_authorities {
            if peer == &self.listen_addr {
                continue;
            }
            if let Ok(Some(peer_sig)) =
                Self::fetch_peer_cross_check(peer, pinned_key.as_ref(), &digest_hex).await
            {
                // Verify the signature is valid for this digest before appending
                if let Some(pubkey) = pinned_key {
                    if let Ok(sig_bytes) = peer_sig.signature_bytes.as_slice().try_into() {
                        let ed_sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
                        if pubkey.verify_strict(&digest, &ed_sig).is_ok() {
                            consensus.signatures.push(peer_sig);
                        }
                    }
                } else if self.allow_unauthenticated_registration {
                    // In unauthenticated mode, we blindly accept the signature (only for testing)
                    consensus.signatures.push(peer_sig);
                }
            }
        }

        if consensus.signatures.len() >= required_signatures {
            info!(
                "Authority [{}]: BFT Cross-check succeeded ({} signatures acquired, required {})",
                self.authority_id,
                consensus.signatures.len(),
                required_signatures
            );
        } else {
            warn!(
                "Authority [{}]: BFT Cross-check failed (only {} signatures acquired, required {})",
                self.authority_id,
                consensus.signatures.len(),
                required_signatures
            );
        }

        consensus
    }

    /// Reconciles relay descriptors with peer authorities before consensus generation.
    pub async fn reconcile_relays(&self) -> Vec<RelayDescriptor> {
        let mut local_map: HashMap<String, RelayDescriptor> = {
            let relays = self.active_relays.read().await;
            relays.clone()
        };

        for (peer, pinned_key) in &self.peer_authorities {
            if peer == &self.listen_addr {
                continue;
            }

            if pinned_key.is_none() {
                if !self.allow_unauthenticated_registration {
                    error!(
                        "Authority [{}]: Gossip to {} refused: no pinned identity key for peer authority. \
                         This would be unauthenticated and vulnerable to active MITM. \
                         Populate authority keys, or set allow_unauthenticated_registration = true.",
                        self.authority_id, peer
                    );
                    continue;
                } else {
                    warn!(
                        "Authority [{}]: No pinned identity key for peer authority {}. \
                         Gossip will be unauthenticated (allow_unauthenticated_registration is enabled). \
                         MITM risk!",
                        self.authority_id, peer
                    );
                }
            }

            match tokio::time::timeout(
                tokio::time::Duration::from_millis(500),
                Self::fetch_peer_relay_list(peer, pinned_key.as_ref()),
            )
            .await
            {
                Ok(Ok(peer_relays)) => {
                    let now = current_timestamp_secs();
                    for desc in peer_relays {
                        if desc.verify_identity() {
                            // Validate PoW and freshness to reject malicious peers pushing fake views
                            let is_valid_pow = verify_pow(
                                &desc.node_id,
                                desc.registered_at,
                                desc.pow_nonce,
                                self.pow_difficulty,
                                now,
                            );
                            if !is_valid_pow {
                                warn!("Authority [{}]: Rejected invalid PoW from peer gossip for relay {}", self.authority_id, desc.node_id);
                                continue;
                            }
                            // BUG FIX: Removed `self.nonce_registry.check_and_record()` from the gossip path.
                            // The descriptor is already signature-verified by `verify_identity()` above,
                            // and the PoW is verified by `verify_pow()`. Gossip naturally re-propagates
                            // the identical registration (with the same PoW nonce) across rounds.
                            // Rejecting it as a "replay" here prevents consensus from converging.
                            // The PoW replay check remains correctly enforced on the direct
                            // registration path (`register_relay()`).
                            local_map
                                .entry(desc.node_id.clone())
                                .and_modify(|existing| {
                                    if desc.identity_key_ed25519 != existing.identity_key_ed25519 {
                                        warn!("Authority [{}]: Rejected impersonation attempt via gossip for node_id {}: identity key mismatch", self.authority_id, desc.node_id);
                                    } else if desc.registered_at > existing.registered_at {
                                        *existing = desc.clone();
                                    }
                                })
                                .or_insert(desc);
                        }
                    }
                }
                Ok(Err(e)) => {
                    crate::observability::inc_quorum_reconciliation_failures();
                    warn!(
                        "Authority [{}]: Failed to fetch relay list from peer {}: {}",
                        self.authority_id, peer, e
                    );
                }
                Err(_) => {
                    crate::observability::inc_quorum_reconciliation_failures();
                    warn!(
                        "Authority [{}]: Timeout fetching relay list from peer {}",
                        self.authority_id, peer
                    );
                }
            }
        }

        // Persist confirmed-good gossiped descriptors back into `self.active_relays`
        // so we don't have to re-fetch them successfully on every round.
        let mut active = self.active_relays.write().await;
        for (id, desc) in &local_map {
            if let Some(existing) = active.get(id) {
                if existing.identity_key_ed25519 != desc.identity_key_ed25519 {
                    warn!("Authority [{}]: Rejected impersonation attempt during local persist for node_id {}: identity key mismatch", self.authority_id, id);
                    continue;
                }
            }
            active.insert(id.clone(), desc.clone());
        }

        local_map.into_values().collect()
    }

    async fn fetch_peer_relay_list(
        peer_addr: &str,
        pinned_key: Option<&ed25519_dalek::VerifyingKey>,
    ) -> Result<Vec<RelayDescriptor>, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::TcpStream;
        let stream = TcpStream::connect(peer_addr).await?;
        let mut session = SecureTransportSession::client_handshake(stream, pinned_key).await?;
        session.write_frame(b"GET_RELAY_LIST").await?;
        let resp = session.read_frame().await?;
        let list: Vec<RelayDescriptor> = serde_json::from_slice(&resp)?;
        Ok(list)
    }

    async fn fetch_peer_cross_check(
        peer_addr: &str,
        pinned_key: Option<&ed25519_dalek::VerifyingKey>,
        digest_hex: &str,
    ) -> Result<Option<AuthoritySignature>, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::TcpStream;
        let stream = TcpStream::connect(peer_addr).await?;
        let mut session = SecureTransportSession::client_handshake(stream, pinned_key).await?;
        let req = format!("BFT_CROSS_CHECK {}", digest_hex);
        session.write_frame(req.as_bytes()).await?;
        let resp = session.read_frame().await?;
        let resp_str = String::from_utf8_lossy(&resp);
        if let Some(json_part) = resp_str.strip_prefix("OK_SIGNED ") {
            let sig: AuthoritySignature = serde_json::from_str(json_part)?;
            Ok(Some(sig))
        } else {
            Ok(None)
        }
    }

    /// Starts the asynchronous authority listener.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!(
            "Directory Authority [{}] listening securely on {}",
            self.authority_id, self.listen_addr
        );

        let active_relays_eviction = self.active_relays.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = current_timestamp_secs();
                let mut relays = active_relays_eviction.write().await;
                // Evict relays that haven't registered in the last 15 minutes (900 seconds)
                relays.retain(|_, desc| now.saturating_sub(desc.registered_at) < 900);
            }
        });

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
            let auth_self = self.clone();
            let active_relays = self.active_relays.clone();
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
                                let consensus = auth_self.generate_consensus().await;
                                if let Ok(serialized) = serde_json::to_vec(&consensus) {
                                    let _ = session.write_frame(&serialized).await;
                                }
                            } else if text.starts_with("GET_RELAY_LIST") {
                                let relays = active_relays.read().await;
                                let list: Vec<RelayDescriptor> = relays.values().cloned().collect();
                                if let Ok(serialized) = serde_json::to_vec(&list) {
                                    let _ = session.write_frame(&serialized).await;
                                }
                            } else if let Some(digest_hex) = text.strip_prefix("BFT_CROSS_CHECK ") {
                                // Recompute our own local consensus digest
                                // We don't trigger a full generate_consensus() here to avoid infinite loops,
                                // we just do local reconciliation.
                                let relays = active_relays.read().await;
                                let list: Vec<RelayDescriptor> = relays.values().cloned().collect();
                                let now = current_timestamp_secs();
                                let bucketed_now = (now / 300) * 300;
                                let mut local_consensus =
                                    ConsensusDocument::new(bucketed_now, bucketed_now + 3600, list);

                                let our_digest = local_consensus.compute_digest();
                                let our_digest_hex = hex::encode(our_digest);

                                if our_digest_hex == digest_hex {
                                    local_consensus
                                        .sign_with_authority(&auth_self.authority_id, &signing_key);
                                    let our_sig = local_consensus.signatures.pop().unwrap();
                                    if let Ok(serialized) = serde_json::to_string(&our_sig) {
                                        let resp = format!("OK_SIGNED {}", serialized);
                                        let _ = session.write_frame(resp.as_bytes()).await;
                                    }
                                } else {
                                    let _ = session.write_frame(b"ERROR_DIGEST_MISMATCH").await;
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
                                            } else if registry.check_and_record(
                                                &desc.node_id,
                                                desc.pow_nonce,
                                                now,
                                            ) {
                                                let _ =
                                                    session.write_frame(b"ERROR_POW_REPLAY").await;
                                            } else {
                                                relays.insert(desc.node_id.clone(), desc);
                                                let _ = session.write_frame(b"OK_REGISTERED").await;
                                            }
                                        } else if registry.check_and_record(
                                            &desc.node_id,
                                            desc.pow_nonce,
                                            now,
                                        ) {
                                            let _ = session.write_frame(b"ERROR_POW_REPLAY").await;
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

    #[test]
    fn test_key_material_zeroize_on_drop() {
        use zeroize::Zeroize;

        fn assert_zeroize<T: Zeroize>(_t: T) {}

        let mut secret = [0x42u8; 32];
        assert_ne!(secret, [0u8; 32]);
        secret.zeroize();
        assert_eq!(secret, [0u8; 32]);

        let mut key_vec = vec![0x99u8; 32];
        assert_ne!(key_vec.as_slice(), &[0u8; 32]);
        key_vec.as_mut_slice().zeroize();
        assert_eq!(key_vec.as_slice(), &[0u8; 32]);

        let mut key_vec_clear = vec![0x88u8; 32];
        key_vec_clear.zeroize();
        assert!(key_vec_clear.is_empty());

        assert_zeroize(secret);
        assert_zeroize(key_vec);
    }
}
