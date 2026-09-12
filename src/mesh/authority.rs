//! Directory Authority Node Implementation.
//!
//! Collects authenticated volunteer relay registrations, validates Proof-of-Work,
//! and issues cryptographically signed consensus documents.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::mesh::consensus::{ConsensusDocument, RelayDescriptor};
use crate::mesh::sybil::{current_timestamp_secs, verify_pow, DEFAULT_POW_DIFFICULTY};
use crate::mesh::transport::SecureTransportSession;

pub struct DirectoryAuthority {
    pub authority_id: String,
    signing_key: SigningKey,
    listen_addr: String,
    active_relays: Arc<RwLock<HashMap<String, RelayDescriptor>>>,
}

impl DirectoryAuthority {
    pub fn new(authority_id: String, listen_addr: String) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            authority_id,
            signing_key,
            listen_addr,
            active_relays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Registers a relay after verifying its Proof-of-Work.
    pub async fn register_relay(&self, descriptor: RelayDescriptor) -> Result<(), String> {
        let now = current_timestamp_secs();
        let is_valid_pow = verify_pow(
            &descriptor.node_id,
            descriptor.registered_at,
            descriptor.pow_nonce,
            DEFAULT_POW_DIFFICULTY,
            now,
        );

        if !is_valid_pow {
            return Err("Invalid or insufficient Proof-of-Work challenge solution".to_string());
        }

        let mut relays = self.active_relays.write().await;
        info!(
            "Authority [{}]: Registered verified relay {} ({}:{})",
            self.authority_id, descriptor.node_id, descriptor.host, descriptor.port
        );
        relays.insert(descriptor.node_id.clone(), descriptor);
        Ok(())
    }

    /// Generates and signs the current consensus document.
    pub async fn generate_consensus(&self) -> ConsensusDocument {
        let relays = self.active_relays.read().await;
        let relay_list: Vec<RelayDescriptor> = relays.values().cloned().collect();
        let now = current_timestamp_secs();

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
            let active_relays = self.active_relays.clone();
            let auth_id = self.authority_id.clone();
            let signing_key = self.signing_key.clone();

            tokio::spawn(async move {
                match SecureTransportSession::server_handshake(stream).await {
                    Ok(mut session) => {
                        while let Ok(frame) = session.read_frame().await {
                            let text = String::from_utf8_lossy(&frame);
                            if text.starts_with("GET_CONSENSUS") {
                                let relays = active_relays.read().await;
                                let relay_list: Vec<RelayDescriptor> = relays.values().cloned().collect();
                                let now = current_timestamp_secs();
                                let mut consensus = ConsensusDocument::new(now, now + 3600, relay_list);
                                consensus.sign_with_authority(&auth_id, &signing_key);

                                if let Ok(serialized) = serde_json::to_vec(&consensus) {
                                    let _ = session.write_frame(&serialized).await;
                                }
                            } else if let Some(json_part) = text.strip_prefix("REGISTER_RELAY ") {
                                match serde_json::from_str::<RelayDescriptor>(json_part) {
                                    Ok(desc) => {
                                        let now = current_timestamp_secs();
                                        if verify_pow(&desc.node_id, desc.registered_at, desc.pow_nonce, 12, now) {
                                            active_relays.write().await.insert(desc.node_id.clone(), desc);
                                            let _ = session.write_frame(b"OK_REGISTERED").await;
                                        } else {
                                            let _ = session.write_frame(b"ERROR_POW_INVALID").await;
                                        }
                                    }
                                    Err(_) => {
                                        let _ = session.write_frame(b"ERROR_MALFORMED_DESCRIPTOR").await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Authority secure handshake from {} failed: {}", addr, e);
                    }
                }
            });
        }
    }
}
