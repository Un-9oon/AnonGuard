//! Authenticated Cryptographic Framing for Secure Node & Directory Transport.
//!
//! Replaces raw plaintext HTTP with Ephemeral X25519 Key Agreement and
//! ChaCha20-Poly1305 AEAD streaming frames.
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

/// Maximum allowed plaintext frame size (10 MB).
const MAX_FRAME_LEN: usize = 10 * 1024 * 1024;

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
    peer_verifying_key: Option<ed25519_dalek::VerifyingKey>,
}

impl SecureTransportSession {
    /// Performs a client-side (initiator) ephemeral Diffie-Hellman handshake,
    /// optionally verifying and enforcing a pinned Ed25519 server identity public key.
    pub async fn client_handshake(
        mut stream: TcpStream,
        pinned_key: Option<&ed25519_dalek::VerifyingKey>,
    ) -> io::Result<Self> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // Send client ephemeral public key (32 bytes)
        stream.write_all(client_public.as_bytes()).await?;

        // Read server ephemeral public key (32 bytes)
        let mut server_pub_bytes = [0u8; 32];
        stream.read_exact(&mut server_pub_bytes).await?;
        let server_public = PublicKey::from(server_pub_bytes);

        // Read authentication header byte
        let mut auth_flag = [0u8; 1];
        stream.read_exact(&mut auth_flag).await?;

        let mut peer_verifying_key = None;

        if auth_flag[0] == 1 {
            // Server provided Ed25519 cryptographic identity proof
            let mut server_id_bytes = [0u8; 32];
            stream.read_exact(&mut server_id_bytes).await?;
            let server_verifying_key =
                VerifyingKey::from_bytes(&server_id_bytes).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid server Ed25519 public key in transport handshake",
                    )
                })?;

            let mut sig_bytes = [0u8; 64];
            stream.read_exact(&mut sig_bytes).await?;
            let signature = Signature::from_bytes(&sig_bytes);

            // Verify signature over client_ephemeral_pub || server_ephemeral_pub
            let mut signed_data = Vec::with_capacity(64);
            signed_data.extend_from_slice(client_public.as_bytes());
            signed_data.extend_from_slice(server_public.as_bytes());

            server_verifying_key
                .verify(&signed_data, &signature)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Server Ed25519 handshake signature verification failed (MITM detected)",
                    )
                })?;

            if let Some(pinned) = pinned_key {
                if &server_verifying_key != pinned {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Server Ed25519 key does not match pinned Directory Authority identity",
                    ));
                }
            }

            peer_verifying_key = Some(server_verifying_key);
        } else if pinned_key.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Server is unauthenticated, but pinned Directory Authority identity is required",
            ));
        }

        let shared_secret = client_secret.diffie_hellman(&server_public);

        // Derive client_send and client_recv AEAD keys
        let (send_key, recv_key) = derive_transport_keys(shared_secret.as_bytes(), true);

        let send_cipher = ChaCha20Poly1305::new_from_slice(&send_key)
            .map_err(|e| io::Error::other(format!("AEAD key error: {e}")))?;
        let recv_cipher = ChaCha20Poly1305::new_from_slice(&recv_key)
            .map_err(|e| io::Error::other(format!("AEAD key error: {e}")))?;

        Ok(Self {
            stream,
            send_cipher,
            recv_cipher,
            send_counter: 0,
            recv_counter: 0,
            peer_verifying_key,
        })
    }

    /// Performs a server-side (listener) ephemeral Diffie-Hellman handshake,
    /// optionally signing the exchange using the server's long-term Ed25519 signing key.
    pub async fn server_handshake(
        mut stream: TcpStream,
        signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> io::Result<Self> {
        use ed25519_dalek::Signer;

        // Read client ephemeral public key (32 bytes)
        let mut client_pub_bytes = [0u8; 32];
        stream.read_exact(&mut client_pub_bytes).await?;
        let client_public = PublicKey::from(client_pub_bytes);

        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);

        // Send server ephemeral public key (32 bytes)
        stream.write_all(server_public.as_bytes()).await?;

        if let Some(key) = signing_key {
            // Send auth_flag = 1, verifying key (32 bytes), signature (64 bytes)
            stream.write_all(&[1u8]).await?;
            let vk = key.verifying_key();
            stream.write_all(vk.as_bytes()).await?;

            let mut signed_data = Vec::with_capacity(64);
            signed_data.extend_from_slice(client_public.as_bytes());
            signed_data.extend_from_slice(server_public.as_bytes());
            let sig = key.sign(&signed_data);
            stream.write_all(&sig.to_bytes()).await?;
        } else {
            // Unauthenticated mode
            stream.write_all(&[0u8]).await?;
        }

        let shared_secret = server_secret.diffie_hellman(&client_public);

        // Derive server_send and server_recv AEAD keys (inverted roles)
        let (send_key, recv_key) = derive_transport_keys(shared_secret.as_bytes(), false);

        let send_cipher = ChaCha20Poly1305::new_from_slice(&send_key)
            .map_err(|e| io::Error::other(format!("AEAD key error: {e}")))?;
        let recv_cipher = ChaCha20Poly1305::new_from_slice(&recv_key)
            .map_err(|e| io::Error::other(format!("AEAD key error: {e}")))?;

        Ok(Self {
            stream,
            send_cipher,
            recv_cipher,
            send_counter: 0,
            recv_counter: 0,
            peer_verifying_key: None,
        })
    }

    /// Returns the verified Ed25519 public key of the remote peer (if authenticated).
    pub fn peer_verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        self.peer_verifying_key
    }

    /// Encrypts and writes a length-prefixed AEAD-authenticated frame.
    ///
    /// Wire format: 4-byte BE length of (ciphertext || 16-byte tag) || ciphertext || tag.
    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
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
        self.stream.write_all(&ct_len.to_be_bytes()).await?;
        self.stream.write_all(&ciphertext).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads and decrypts a length-prefixed AEAD-authenticated frame.
    ///
    /// Returns `InvalidData` if authentication fails — the caller must close the connection.
    pub async fn read_frame(&mut self) -> io::Result<Vec<u8>> {
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

        let counter = self.recv_counter;
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or_else(|| io::Error::other("recv nonce counter exhausted — rotate session key"))?;

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

        Ok(plaintext)
    }

    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

fn derive_transport_keys(shared_secret: &[u8; 32], is_client: bool) -> ([u8; 32], [u8; 32]) {
    use hkdf::Hkdf;

    let hk = Hkdf::<sha2::Sha256>::new(None, shared_secret);

    let mut k_c2s = [0u8; 32];
    hk.expand(b"AnonGuard-Client-To-Server-v2-HKDF", &mut k_c2s)
        .expect("HKDF-Expand failed for C2S key");

    let mut k_s2c = [0u8; 32];
    hk.expand(b"AnonGuard-Server-To-Client-v2-HKDF", &mut k_s2c)
        .expect("HKDF-Expand failed for S2C key");

    if is_client {
        (k_c2s, k_s2c)
    } else {
        (k_s2c, k_c2s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_secure_transport_e2e_encryption() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut session = SecureTransportSession::server_handshake(stream, None)
                .await
                .unwrap();
            let incoming = session.read_frame().await.unwrap();
            assert_eq!(incoming.as_slice(), b"SECRET_REGISTRATION_PACKET");

            session
                .write_frame(b"REGISTRATION_CONFIRMED_OK")
                .await
                .unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client_session = SecureTransportSession::client_handshake(client_stream, None)
            .await
            .unwrap();

        client_session
            .write_frame(b"SECRET_REGISTRATION_PACKET")
            .await
            .unwrap();
        let reply = client_session.read_frame().await.unwrap();
        assert_eq!(reply.as_slice(), b"REGISTRATION_CONFIRMED_OK");

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_secure_transport_authenticated_key_pinning() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let auth_signing_key = SigningKey::generate(&mut OsRng);
        let auth_verifying_key = auth_signing_key.verifying_key();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_key_clone = auth_signing_key.clone();
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut session =
                SecureTransportSession::server_handshake(stream, Some(&server_key_clone))
                    .await
                    .unwrap();
            let incoming = session.read_frame().await.unwrap();
            assert_eq!(incoming.as_slice(), b"GET_CONSENSUS");
            session.write_frame(b"SIGNED_CONSENSUS_DATA").await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        // Client connects with pinned authority key
        let mut client_session =
            SecureTransportSession::client_handshake(client_stream, Some(&auth_verifying_key))
                .await
                .unwrap();

        client_session.write_frame(b"GET_CONSENSUS").await.unwrap();
        let reply = client_session.read_frame().await.unwrap();
        assert_eq!(reply.as_slice(), b"SIGNED_CONSENSUS_DATA");

        server_handle.await.unwrap();

        // Test MITM rejection: client expects a different pinned key
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();

        let server_handle2 = tokio::spawn(async move {
            let (stream, _) = listener2.accept().await.unwrap();
            let _ = SecureTransportSession::server_handshake(stream, Some(&auth_signing_key)).await;
        });

        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        let client_stream2 = TcpStream::connect(addr2).await.unwrap();
        let client_res =
            SecureTransportSession::client_handshake(client_stream2, Some(&wrong_key)).await;
        assert!(client_res.is_err());
        server_handle2.await.unwrap();
    }

    /// Verify that bit-flipping a ciphertext frame is rejected by AEAD authentication.
    #[tokio::test]
    async fn test_aead_rejects_tampered_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: complete the handshake, then send a valid-length frame with corrupted ciphertext
        let server_handle = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (stream, _) = listener.accept().await.unwrap();
            // Complete real handshake so client_handshake() succeeds
            let mut session = SecureTransportSession::server_handshake(stream, None)
                .await
                .unwrap();

            // Encrypt a normal frame to get a valid-length ciphertext...
            let msg = b"hello";
            session.write_frame(msg).await.unwrap();

            // ...then extract the underlying stream and send a second frame that is
            // identical-length but completely corrupted bytes, bypassing the AEAD layer
            let mut raw_stream = session.into_inner();
            // Frame 2: same length as a 5-byte plaintext (5 + 16 = 21 bytes ciphertext)
            let ct_len: u32 = 21;
            raw_stream.write_all(&ct_len.to_be_bytes()).await.unwrap();
            raw_stream.write_all(&[0xDE; 21]).await.unwrap();
            raw_stream.flush().await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client_session = SecureTransportSession::client_handshake(client_stream, None)
            .await
            .unwrap();

        // First frame should decrypt correctly
        let first = client_session.read_frame().await.unwrap();
        assert_eq!(first.as_slice(), b"hello");

        // Second frame has corrupted ciphertext — must be rejected with InvalidData
        let result = client_session.read_frame().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        server_handle.await.unwrap();
    }
}
