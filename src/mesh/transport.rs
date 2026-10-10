//! Authenticated Cryptographic Framing for Secure Node & Directory Transport.
//!
//! AGDIR004 requires ephemeral X25519 + ML-KEM-768 key agreement, pinned
//! Ed25519 AND ML-DSA-65 server authentication and bidirectional key confirmation.
//! There is no unauthenticated or classical-only fallback. Application frames
//! use ChaCha20-Poly1305 with direction-separated keys and monotonic counters.
//!
//! # Security (#8 fix)
//! `write_frame` and `read_frame` previously used raw ChaCha20 with no authentication,
//! allowing a network attacker to silently flip bits in frames without detection.
//! This version uses ChaCha20-Poly1305 AEAD with a per-frame monotonic nonce counter,
//! preventing both bit-flipping and frame replay.
//!
//! Frame format on the wire:
//!   4-byte big-endian ciphertext length (= plaintext len + 16 tag bytes)
//!   <ciphertext || 16-byte Poly1305 tag>

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Maximum allowed plaintext frame size (1 MiB).
const MAX_FRAME_LEN: usize = 1024 * 1024;
const VERSION: &[u8; 8] = b"AGDIR004";
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PURPOSE: &[u8] = b"directory-transport-v4";

fn hybrid_transcript(client: &[u8], response: &[u8]) -> Vec<u8> {
    let mut bytes = b"AnonGuard-directory-transport-v4/initiator/responder".to_vec();
    bytes.extend_from_slice(client);
    bytes.extend_from_slice(response);
    bytes
}

fn rejected(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn make_nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(n)
}

pub struct SecureTransportSession {
    stream: TcpStream,
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    /// Monotonic send counter — encoded in nonce, wraps to Err on overflow.
    send_counter: u64,
    /// Monotonic recv counter — encoded in nonce, wraps to Err on overflow.
    recv_counter: u64,
    peer_verifying_key: Option<crate::crypto::identity::VerifyingKey>,
    peer_hybrid_key: Option<crate::crypto::hybrid_identity::HybridPublicKey>,
    poisoned: bool,
}

impl SecureTransportSession {
    /// Mandatory hybrid directory handshake. Missing pins never enable fallback.
    pub async fn client_handshake(
        stream: TcpStream,
        pinned: Option<&crate::crypto::identity::VerifyingKey>,
    ) -> io::Result<Self> {
        let pinned = pinned.ok_or_else(|| rejected("Directory hybrid identity pin required"))?;
        Self::client_handshake_hybrid_pin(stream, pinned.to_bytes()).await
    }

    pub async fn server_handshake(
        stream: TcpStream,
        key: Option<&crate::crypto::identity::SigningKey>,
    ) -> io::Result<Self> {
        let key = key.ok_or_else(|| rejected("Directory hybrid signing identity required"))?;
        Self::server_handshake_hybrid(stream, key.hybrid()).await
    }

    pub fn peer_verifying_key(&self) -> Option<crate::crypto::identity::VerifyingKey> {
        self.peer_verifying_key
    }
    pub fn peer_hybrid_key(&self) -> Option<&crate::crypto::hybrid_identity::HybridPublicKey> {
        self.peer_hybrid_key.as_ref()
    }

    pub async fn client_handshake_hybrid(
        stream: TcpStream,
        pinned: &crate::crypto::hybrid_identity::HybridPublicKey,
    ) -> io::Result<Self> {
        Self::client_handshake_hybrid_pin(stream, pinned.fingerprint()).await
    }

    pub async fn client_handshake_hybrid_pin(
        mut stream: TcpStream,
        pinned: [u8; 32],
    ) -> io::Result<Self> {
        use crate::crypto::hybrid_identity::{HybridPublicKey, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
        use ml_kem::{kem::Decapsulate, EncodedSizeUser, KemCore, MlKem768};
        if pinned == [0; 32] {
            return Err(rejected("Zero hybrid identity pin"));
        }
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let secret = EphemeralSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let (kem_secret, kem_public) = MlKem768::generate(&mut OsRng);
            let mut hello = VERSION.to_vec();
            hello.extend_from_slice(public.as_bytes());
            hello.extend_from_slice(kem_public.as_bytes().as_slice());
            stream.write_all(&hello).await?;
            let mut response = vec![0u8; 8 + 32 + 1088 + PUBLIC_KEY_SIZE];
            stream.read_exact(&mut response).await?;
            if &response[..8] != VERSION {
                return Err(rejected("Directory protocol downgrade/version mismatch"));
            }
            let identity = HybridPublicKey::decode(&response[1128..])?;
            if identity.fingerprint() != pinned {
                return Err(rejected("Directory composite identity pin mismatch"));
            }
            let mut proof = vec![0u8; SIGNATURE_SIZE];
            stream.read_exact(&mut proof).await?;
            let mut context = hybrid_transcript(&hello, &response);
            identity.verify(PURPOSE, &context, &proof)?;
            context.extend_from_slice(&proof);
            let server_public = PublicKey::from(
                <[u8; 32]>::try_from(&response[8..40]).map_err(|_| rejected("Malformed KEX"))?,
            );
            let dh = secret.diffie_hellman(&server_public);
            if !dh.was_contributory() {
                return Err(rejected("Non-contributory directory KEX"));
            }
            let ciphertext: [u8; 1088] = response[40..1128]
                .try_into()
                .map_err(|_| rejected("Malformed KEM"))?;
            let mut kem = kem_secret
                .decapsulate(&ml_kem::Ciphertext::<MlKem768>::from(ciphertext))
                .map_err(|_| rejected("Directory KEM failed"))?;
            let mut kem_bytes = zeroize::Zeroizing::new([0u8; 32]);
            kem_bytes.copy_from_slice(kem.as_slice());
            zeroize::Zeroize::zeroize(kem.as_mut_slice());
            let mut shared = zeroize::Zeroizing::new([0u8; 64]);
            shared[..32].copy_from_slice(dh.as_bytes());
            shared[32..].copy_from_slice(kem_bytes.as_ref());
            let mut session =
                Self::from_hybrid_keys(stream, &shared[..], true, &context, Some(identity))?;
            session.write_frame(b"AGDIR004/client-confirm").await?;
            if session.read_frame().await? != b"AGDIR004/server-confirm" {
                return Err(rejected("Directory server confirmation failed"));
            }
            Ok(session)
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Hybrid directory handshake timed out",
            )
        })?
    }

    pub async fn server_handshake_hybrid(
        mut stream: TcpStream,
        key: &crate::crypto::hybrid_identity::HybridSigningKey,
    ) -> io::Result<Self> {
        use ml_kem::{
            kem::{Encapsulate, EncapsulationKey},
            EncodedSizeUser, MlKem768Params,
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut version = [0u8; 8];
            stream.read_exact(&mut version).await?;
            if &version != VERSION {
                return Err(rejected("Directory protocol downgrade/version mismatch"));
            }
            let mut hello = vec![0u8; 8 + 32 + 1184];
            hello[..8].copy_from_slice(&version);
            stream.read_exact(&mut hello[8..]).await?;
            let client_public = PublicKey::from(
                <[u8; 32]>::try_from(&hello[8..40]).map_err(|_| rejected("Malformed KEX"))?,
            );
            let secret = EphemeralSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let dh = secret.diffie_hellman(&client_public);
            if !dh.was_contributory() {
                return Err(rejected("Non-contributory directory KEX"));
            }
            let encoded: [u8; 1184] = hello[40..]
                .try_into()
                .map_err(|_| rejected("Malformed KEM"))?;
            if !crate::crypto::hybrid_identity::mlkem768_public_is_canonical(&encoded) {
                return Err(rejected("Noncanonical ML-KEM encapsulation key"));
            }
            let kem_public = EncapsulationKey::<MlKem768Params>::from_bytes((&encoded).into());
            let (ciphertext, mut kem) = kem_public
                .encapsulate(&mut OsRng)
                .map_err(|_| rejected("Directory KEM failed"))?;
            let mut kem_bytes = zeroize::Zeroizing::new([0u8; 32]);
            kem_bytes.copy_from_slice(kem.as_slice());
            zeroize::Zeroize::zeroize(kem.as_mut_slice());
            let identity = key.public_key();
            let mut response = VERSION.to_vec();
            response.extend_from_slice(public.as_bytes());
            response.extend_from_slice(ciphertext.as_slice());
            response.extend_from_slice(identity.encode());
            let mut context = hybrid_transcript(&hello, &response);
            let proof = key.sign(PURPOSE, &context)?;
            stream.write_all(&response).await?;
            stream.write_all(&proof).await?;
            context.extend_from_slice(&proof);
            let mut shared = zeroize::Zeroizing::new([0u8; 64]);
            shared[..32].copy_from_slice(dh.as_bytes());
            shared[32..].copy_from_slice(kem_bytes.as_ref());
            let mut session = Self::from_hybrid_keys(stream, &shared[..], false, &context, None)?;
            if session.read_frame().await? != b"AGDIR004/client-confirm" {
                return Err(rejected("Directory client confirmation failed"));
            }
            session.write_frame(b"AGDIR004/server-confirm").await?;
            Ok(session)
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Hybrid directory handshake timed out",
            )
        })?
    }

    fn from_hybrid_keys(
        stream: TcpStream,
        shared: &[u8],
        client: bool,
        context: &[u8],
        peer: Option<crate::crypto::hybrid_identity::HybridPublicKey>,
    ) -> io::Result<Self> {
        let (send, recv) = derive_transport_keys(shared, client, context);
        let send = zeroize::Zeroizing::new(send);
        let recv = zeroize::Zeroizing::new(recv);
        let peer_verifying_key = peer
            .as_ref()
            .map(|key| crate::crypto::identity::VerifyingKey::from_bytes(&key.fingerprint()))
            .transpose()?;
        Ok(Self {
            stream,
            send_cipher: ChaCha20Poly1305::new_from_slice(send.as_ref())
                .map_err(|_| rejected("AEAD key failed"))?,
            recv_cipher: ChaCha20Poly1305::new_from_slice(recv.as_ref())
                .map_err(|_| rejected("AEAD key failed"))?,
            send_counter: 0,
            recv_counter: 0,
            peer_verifying_key,
            peer_hybrid_key: peer,
            poisoned: false,
        })
    }

    /// Encrypts and writes a length-prefixed AEAD-authenticated frame.
    ///
    /// Wire format: 4-byte BE length of (ciphertext || 16-byte tag) || ciphertext || tag.
    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        if self.poisoned {
            return Err(rejected("Directory session is poisoned; reconnect"));
        }
        self.poisoned = true;
        let result = self.write_frame_inner(payload).await;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    async fn write_frame_inner(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_FRAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Frame payload exceeds limit",
            ));
        }
        let counter = self.send_counter;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| io::Error::other("send nonce counter exhausted — rotate session key"))?;

        let nonce = make_nonce(counter);
        let ciphertext = self
            .send_cipher
            .encrypt(&nonce, payload)
            .map_err(|e| io::Error::other(format!("AEAD encrypt error: {e}")))?;

        // ciphertext already includes the 16-byte Poly1305 tag appended by the AEAD
        let ct_len = ciphertext.len() as u32;
        tokio::time::timeout(tokio::time::Duration::from_secs(15), async {
            self.stream.write_all(&ct_len.to_be_bytes()).await?;
            self.stream.write_all(&ciphertext).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Directory write timed out"))??;
        Ok(())
    }

    /// Reads and decrypts a length-prefixed AEAD-authenticated frame.
    ///
    /// Returns `InvalidData` if authentication fails — the caller must close the connection.
    pub async fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        if self.poisoned {
            return Err(rejected("Directory session is poisoned; reconnect"));
        }
        self.poisoned = true;
        let result = self.read_frame_inner().await;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    async fn read_frame_inner(&mut self) -> io::Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        tokio::time::timeout(
            tokio::time::Duration::from_secs(15),
            self.stream.read_exact(&mut len_bytes),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "Timeout waiting for frame header")
        })??;

        // Length on wire is ciphertext + 16-byte tag
        let ct_len = u32::from_be_bytes(len_bytes) as usize;
        // Sanity check: plaintext is ct_len - 16; enforce MAX_FRAME_LEN on plaintext
        if !(16..=MAX_FRAME_LEN + 16).contains(&ct_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Frame size out of bounds",
            ));
        }

        let mut ct_buf = vec![0u8; ct_len];
        tokio::time::timeout(
            tokio::time::Duration::from_secs(15),
            self.stream.read_exact(&mut ct_buf),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "Timeout waiting for frame payload")
        })??;

        // BUG-02 FIX: Counter must only advance on successful decryption.
        // Previously, the counter was incremented before decrypt(), meaning any attacker
        // who sends a single tampered frame would permanently desync the session.
        let counter = self.recv_counter;
        let nonce = make_nonce(counter);
        let plaintext = self
            .recv_cipher
            .decrypt(&nonce, ct_buf.as_slice())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AEAD authentication failed — possible tampering or replay",
                )
            })?;

        // Only advance counter after successful decryption
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or_else(|| io::Error::other("recv nonce counter exhausted — rotate session key"))?;

        Ok(plaintext)
    }

    /// Authenticated bounded document envelope; ordinary control RPCs use frames.
    pub async fn write_document(&mut self, document: &[u8]) -> io::Result<()> {
        if self.poisoned {
            return Err(rejected("Directory session is poisoned; reconnect"));
        }
        self.poisoned = true;
        let result = self.write_document_inner(document).await;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    async fn write_document_inner(&mut self, document: &[u8]) -> io::Result<()> {
        if document.is_empty() || document.len() > 6 * MAX_FRAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Directory document size out of bounds",
            ));
        }
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let mut header = b"AGDOC006".to_vec();
            header.extend_from_slice(&(document.len() as u32).to_be_bytes());
            self.write_frame_inner(&header).await?;
            for chunk in document.chunks(MAX_FRAME_LEN) {
                self.write_frame_inner(chunk).await?;
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Directory document write timed out",
            )
        })?
    }

    pub async fn read_document(&mut self) -> io::Result<Vec<u8>> {
        if self.poisoned {
            return Err(rejected("Directory session is poisoned; reconnect"));
        }
        self.poisoned = true;
        let result = self.read_document_inner().await;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    async fn read_document_inner(&mut self) -> io::Result<Vec<u8>> {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let header = self.read_frame_inner().await?;
            if header.len() != 12 || &header[..8] != b"AGDOC006" {
                return Err(rejected("Directory document envelope required"));
            }
            let total = u32::from_be_bytes(
                header[8..]
                    .try_into()
                    .map_err(|_| rejected("Malformed document header"))?,
            ) as usize;
            if total == 0 || total > 6 * MAX_FRAME_LEN {
                return Err(rejected("Directory document size out of bounds"));
            }
            let mut document = Vec::with_capacity(total);
            while document.len() < total {
                let chunk = self.read_frame_inner().await?;
                if chunk.len() != MAX_FRAME_LEN.min(total - document.len()) {
                    return Err(rejected("Directory document chunk length mismatch"));
                }
                document.extend_from_slice(&chunk);
            }
            Ok(document)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Directory document read timed out"))?
    }

    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

fn derive_transport_keys(
    shared_secret: &[u8],
    is_client: bool,
    context: &[u8],
) -> ([u8; 32], [u8; 32]) {
    use hkdf::Hkdf;

    use sha2::Digest;
    let salt = sha2::Sha256::digest(context);
    let hk = Hkdf::<sha2::Sha256>::new(Some(&salt), shared_secret);

    let mut k_c2s = [0u8; 32];
    // SAFETY: HKDF-Expand into a 32-byte buffer using Sha256 cannot fail because 32 bytes is well within the 8160-byte maximum output limit (255 * 32).
    hk.expand(b"AnonGuard-Client-To-Server-v4-HKDF", &mut k_c2s)
        .expect("safe: HKDF-Expand only fails above 8160 bytes output for SHA-256; requesting 32-byte symmetric key");

    let mut k_s2c = [0u8; 32];
    // SAFETY: HKDF-Expand into a 32-byte buffer using Sha256 cannot fail because 32 bytes is well within the 8160-byte maximum output limit (255 * 32).
    hk.expand(b"AnonGuard-Server-To-Client-v4-HKDF", &mut k_s2c)
        .expect("safe: HKDF-Expand only fails above 8160 bytes output for SHA-256; requesting 32-byte symmetric key");

    if is_client {
        (k_c2s, k_s2c)
    } else {
        (k_s2c, k_c2s)
    }
}

#[cfg(test)]
mod hybrid_transport_tests {
    use super::*;
    use crate::crypto::hybrid_identity::HybridSigningKey;
    use tokio::net::TcpListener;

    async fn pair() -> (SecureTransportSession, SecureTransportSession) {
        let key = HybridSigningKey::generate();
        let pin = key.public_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            SecureTransportSession::server_handshake_hybrid(
                listener.accept().await.unwrap().0,
                &key,
            )
            .await
            .unwrap()
        });
        let client = SecureTransportSession::client_handshake_hybrid(
            TcpStream::connect(endpoint).await.unwrap(),
            &pin,
        )
        .await
        .unwrap();
        (client, server.await.unwrap())
    }

    #[tokio::test]
    async fn hybrid_authenticated_confirmed_frames() {
        let (mut client, mut server) = pair().await;
        assert!(client.peer_hybrid_key().is_some());
        assert!(client.peer_verifying_key().is_some());
        assert_eq!(client.send_counter, 1);
        assert_eq!(server.recv_counter, 1);
        client.write_frame(b"GET_CONSENSUS").await.unwrap();
        assert_eq!(server.read_frame().await.unwrap(), b"GET_CONSENSUS");
        server.write_frame(b"SIGNED_CONSENSUS").await.unwrap();
        assert_eq!(client.read_frame().await.unwrap(), b"SIGNED_CONSENSUS");
    }

    #[tokio::test]
    async fn hybrid_wrong_composite_pin_refused() {
        let key = HybridSigningKey::generate();
        let wrong = HybridSigningKey::generate().public_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            SecureTransportSession::server_handshake_hybrid(
                listener.accept().await.unwrap().0,
                &key,
            )
            .await
            .is_err()
        });
        assert!(SecureTransportSession::client_handshake_hybrid(
            TcpStream::connect(endpoint).await.unwrap(),
            &wrong
        )
        .await
        .is_err());
        assert!(server.await.unwrap());
    }

    #[tokio::test]
    async fn legacy_version_and_unpinned_mode_refused() {
        let key = HybridSigningKey::generate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            SecureTransportSession::server_handshake_hybrid(
                listener.accept().await.unwrap().0,
                &key,
            )
            .await
            .is_err()
        });
        let mut socket = TcpStream::connect(endpoint).await.unwrap();
        socket.write_all(b"AGDIR003").await.unwrap();
        assert!(server.await.unwrap());
        assert!(SecureTransportSession::client_handshake(socket, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn hybrid_low_order_client_kex_refused() {
        let key = HybridSigningKey::generate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            SecureTransportSession::server_handshake_hybrid(
                listener.accept().await.unwrap().0,
                &key,
            )
            .await
            .is_err()
        });
        let mut socket = TcpStream::connect(endpoint).await.unwrap();
        let mut hello = vec![0; 8 + 32 + 1184];
        hello[..8].copy_from_slice(VERSION);
        socket.write_all(&hello).await.unwrap();
        assert!(server.await.unwrap());
    }

    #[tokio::test]
    async fn ciphertext_tampering_and_replay_refused() {
        let (mut client, mut server) = pair().await;
        let counter = server.send_counter;
        let ciphertext = server
            .send_cipher
            .encrypt(&make_nonce(counter), b"owned".as_slice())
            .unwrap();
        server
            .stream
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await
            .unwrap();
        server.stream.write_all(&ciphertext).await.unwrap();
        assert_eq!(client.read_frame().await.unwrap(), b"owned");
        server
            .stream
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await
            .unwrap();
        server.stream.write_all(&ciphertext).await.unwrap();
        assert_eq!(
            client.read_frame().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let (mut client, mut server) = pair().await;
        server.stream.write_all(&21u32.to_be_bytes()).await.unwrap();
        server.stream.write_all(&[0xde; 21]).await.unwrap();
        assert_eq!(
            client.read_frame().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn dual_proof_tampering_and_cross_handshake_replay_refused() {
        use ml_kem::{
            kem::{Encapsulate, EncapsulationKey},
            EncodedSizeUser, MlKem768Params,
        };
        for replay in [false, true] {
            let key = HybridSigningKey::generate();
            let identity = key.public_key();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let attacker = tokio::spawn(async move {
                let mut stream = listener.accept().await.unwrap().0;
                let mut hello = vec![0; 8 + 32 + 1184];
                stream.read_exact(&mut hello).await.unwrap();
                let secret = EphemeralSecret::random_from_rng(OsRng);
                let public = PublicKey::from(&secret);
                let encoded: [u8; 1184] = hello[40..].try_into().unwrap();
                let kem = EncapsulationKey::<MlKem768Params>::from_bytes((&encoded).into());
                let (ciphertext, _) = kem.encapsulate(&mut OsRng).unwrap();
                let mut response = VERSION.to_vec();
                response.extend_from_slice(public.as_bytes());
                response.extend_from_slice(ciphertext.as_slice());
                response.extend_from_slice(key.public_key().encode());
                // A proof from a different hello must not authorize this connection.
                if replay {
                    hello[8] ^= 1;
                }
                let mut proof = key
                    .sign(PURPOSE, &hybrid_transcript(&hello, &response))
                    .unwrap();
                if !replay {
                    let last = proof.len() - 1;
                    proof[last] ^= 1;
                }
                stream.write_all(&response).await.unwrap();
                stream.write_all(&proof).await.unwrap();
            });
            assert!(SecureTransportSession::client_handshake_hybrid(
                TcpStream::connect(endpoint).await.unwrap(),
                &identity
            )
            .await
            .is_err());
            attacker.await.unwrap();
        }
    }

    #[tokio::test]
    async fn bounded_segmented_documents_and_malformed_envelopes() {
        let (mut client, mut server) = pair().await;
        let document = vec![42; MAX_FRAME_LEN + 7];
        let expected = document.clone();
        let sender = tokio::spawn(async move {
            server.write_document(&document).await.unwrap();
        });
        assert_eq!(client.read_document().await.unwrap(), expected);
        sender.await.unwrap();
        for declared in [0u32, (6 * MAX_FRAME_LEN + 1) as u32, MAX_FRAME_LEN as u32] {
            let (mut client, mut server) = pair().await;
            let mut header = b"AGDOC006".to_vec();
            header.extend_from_slice(&declared.to_be_bytes());
            server.write_frame(&header).await.unwrap();
            if declared == MAX_FRAME_LEN as u32 {
                server.write_frame(b"short-chunk").await.unwrap();
            }
            assert!(client.read_document().await.is_err());
        }
        let (mut client, mut server) = pair().await;
        server.write_frame(b"raw document fallback").await.unwrap();
        assert!(client.read_document().await.is_err());
    }

    #[tokio::test]
    async fn cancelled_partial_frames_and_documents_poison_session() {
        let (mut client, mut server) = pair().await;
        server.stream.write_all(&[0, 0]).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), client.read_frame())
                .await
                .is_err()
        );
        assert!(client.poisoned);
        assert_eq!(
            client.read_frame().await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(client.write_frame(b"must not resume").await.is_err());
        let (mut client, mut server) = pair().await;
        let mut header = b"AGDOC006".to_vec();
        header.extend_from_slice(&100u32.to_be_bytes());
        server.write_frame(&header).await.unwrap();
        // Valid envelope followed by an incomplete encrypted chunk header.
        server.stream.write_all(&[0]).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), client.read_document())
                .await
                .is_err()
        );
        assert!(client.poisoned);
        assert!(client.read_document().await.is_err());
    }

    #[tokio::test]
    async fn noncanonical_mlkem_public_key_refused_before_signature() {
        let key = HybridSigningKey::generate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            SecureTransportSession::server_handshake_hybrid(
                listener.accept().await.unwrap().0,
                &key,
            )
            .await
            .is_err()
        });
        let mut socket = TcpStream::connect(endpoint).await.unwrap();
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut hello = VERSION.to_vec();
        hello.extend_from_slice(public.as_bytes());
        hello.extend_from_slice(&[0xff; 1184]);
        socket.write_all(&hello).await.unwrap();
        assert!(server.await.unwrap());
    }

    #[tokio::test]
    async fn oversized_frames_and_nonce_exhaustion_refused() {
        let (mut client, _server) = pair().await;
        assert!(client
            .write_frame(&vec![0; MAX_FRAME_LEN + 1])
            .await
            .is_err());
        assert!(client.poisoned);
        let (mut client, mut server) = pair().await;
        server
            .stream
            .write_all(&((MAX_FRAME_LEN + 17) as u32).to_be_bytes())
            .await
            .unwrap();
        assert_eq!(
            client.read_frame().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let (mut client, _server) = pair().await;
        client.send_counter = u64::MAX;
        assert!(client.write_frame(b"x").await.is_err());
    }
}
