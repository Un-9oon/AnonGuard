//! Authenticated Cryptographic Framing for Secure Node & Directory Transport.
//!
//! Replaces raw plaintext HTTP with Ephemeral X25519 Key Agreement
//! and ChaCha20 authenticated streaming frames.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct SecureTransportSession {
    stream: TcpStream,
    send_cipher: ChaCha20,
    recv_cipher: ChaCha20,
}

impl SecureTransportSession {
    /// Performs a client-side (initiator) ephemeral Diffie-Hellman handshake.
    pub async fn client_handshake(mut stream: TcpStream) -> io::Result<Self> {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // Send client ephemeral public key (32 bytes)
        stream.write_all(client_public.as_bytes()).await?;

        // Read server ephemeral public key (32 bytes)
        let mut server_pub_bytes = [0u8; 32];
        stream.read_exact(&mut server_pub_bytes).await?;
        let server_public = PublicKey::from(server_pub_bytes);

        let shared_secret = client_secret.diffie_hellman(&server_public);

        // Derive client_send and client_recv keys
        let (send_key, recv_key) = derive_transport_keys(shared_secret.as_bytes(), true);

        let nonce = [0u8; 12];
        let send_cipher = ChaCha20::new(&send_key.into(), &nonce.into());
        let recv_cipher = ChaCha20::new(&recv_key.into(), &nonce.into());

        Ok(Self {
            stream,
            send_cipher,
            recv_cipher,
        })
    }

    /// Performs a server-side (listener) ephemeral Diffie-Hellman handshake.
    pub async fn server_handshake(mut stream: TcpStream) -> io::Result<Self> {
        // Read client ephemeral public key (32 bytes)
        let mut client_pub_bytes = [0u8; 32];
        stream.read_exact(&mut client_pub_bytes).await?;
        let client_public = PublicKey::from(client_pub_bytes);

        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);

        // Send server ephemeral public key (32 bytes)
        stream.write_all(server_public.as_bytes()).await?;

        let shared_secret = server_secret.diffie_hellman(&client_public);

        // Derive server_send and server_recv keys (inverted roles)
        let (send_key, recv_key) = derive_transport_keys(shared_secret.as_bytes(), false);

        let nonce = [0u8; 12];
        let send_cipher = ChaCha20::new(&send_key.into(), &nonce.into());
        let recv_cipher = ChaCha20::new(&recv_key.into(), &nonce.into());

        Ok(Self {
            stream,
            send_cipher,
            recv_cipher,
        })
    }

    /// Encrypts and writes a length-prefixed encrypted frame.
    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let len = payload.len() as u32;
        let mut encrypted = payload.to_vec();
        self.send_cipher.apply_keystream(&mut encrypted);

        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&encrypted).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads and decrypts a length-prefixed encrypted frame.
    pub async fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > 10 * 1024 * 1024 {
            // 10MB sanity frame limit
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Frame too large"));
        }

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        self.recv_cipher.apply_keystream(&mut buf);
        Ok(buf)
    }

    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

fn derive_transport_keys(shared_secret: &[u8; 32], is_client: bool) -> ([u8; 32], [u8; 32]) {
    let mut hasher_a = Sha256::new();
    hasher_a.update(shared_secret);
    hasher_a.update(b"AnonGuard-Client-To-Server-v1");
    let c2s = hasher_a.finalize();

    let mut hasher_b = Sha256::new();
    hasher_b.update(shared_secret);
    hasher_b.update(b"AnonGuard-Server-To-Client-v1");
    let s2c = hasher_b.finalize();

    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    k_c2s.copy_from_slice(&c2s);
    k_s2c.copy_from_slice(&s2c);

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
            let mut session = SecureTransportSession::server_handshake(stream).await.unwrap();
            let incoming = session.read_frame().await.unwrap();
            assert_eq!(incoming.as_slice(), b"SECRET_REGISTRATION_PACKET");

            session.write_frame(b"REGISTRATION_CONFIRMED_OK").await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client_session = SecureTransportSession::client_handshake(client_stream).await.unwrap();

        client_session.write_frame(b"SECRET_REGISTRATION_PACKET").await.unwrap();
        let reply = client_session.read_frame().await.unwrap();
        assert_eq!(reply.as_slice(), b"REGISTRATION_CONFIRMED_OK");

        server_handle.await.unwrap();
    }
}
