//! TLS 1.3 links with directory-pinned Ed25519 identities and mandatory v5 ALPN.
use ed25519_dalek::SigningKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::{io, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
pub const ALPN: &[u8] = b"anonguard/5";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
#[derive(Debug)]
struct IdentityVerifier {
    pinned: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}
impl ServerCertVerifier for IdentityVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (rest, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
            .map_err(|_| rustls::Error::General("Invalid certificate".into()))?;
        let key = parsed.public_key();
        let time = x509_parser::time::ASN1Time::from_timestamp(now.as_secs() as i64)
            .map_err(|_| rustls::Error::General("Invalid time".into()))?;
        if !rest.is_empty()
            || !chain.is_empty()
            || key.algorithm.algorithm.to_id_string() != "1.3.101.112"
            || key.algorithm.parameters.is_some()
            || key.subject_public_key.unused_bits != 0
            || key.subject_public_key.data.as_ref() != self.pinned
            || !parsed.validity().is_valid_at(time)
        {
            return Err(rustls::Error::General(
                "Relay identity or certificate validity mismatch".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
pub fn acceptor(identity: &SigningKey) -> io::Result<TlsAcceptor> {
    // RFC 8410 PKCS#8 Ed25519 private key, from the persisted directory identity.
    let mut bytes = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    bytes.extend_from_slice(&identity.to_bytes());
    let private = PrivatePkcs8KeyDer::from(bytes);
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&private, &rcgen::PKCS_ED25519)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let cert = rcgen::CertificateParams::new(vec!["relay.anonguard.invalid".into()])
        .and_then(|p| p.self_signed(&pair))
        .map_err(|e| io::Error::other(e.to_string()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], private.into())
        .map_err(|e| io::Error::other(e.to_string()))?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
pub async fn connect(
    stream: TcpStream,
    pinned: [u8; 32],
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    if pinned == [0; 32] {
        return Err(invalid("Relay link requires a directory identity pin"));
    }
    // Cells are paced by the session; avoid a second TCP batching policy.
    stream.set_nodelay(true)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(IdentityVerifier {
        pinned,
        provider: provider.clone(),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    let tls = tokio::time::timeout(
        TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(
            ServerName::try_from("relay.anonguard.invalid")
                .map_err(|_| invalid("Invalid server name"))?,
            stream,
        ),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Relay TLS handshake timed out"))??;
    if tls.get_ref().1.alpn_protocol() != Some(ALPN) {
        return Err(invalid("Relay protocol version mismatch"));
    }
    Ok(tls)
}
pub async fn accept<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    acceptor: &TlsAcceptor,
    stream: S,
) -> io::Result<tokio_rustls::server::TlsStream<S>> {
    let tls = tokio::time::timeout(TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Relay TLS handshake timed out"))??;
    if tls.get_ref().1.alpn_protocol() != Some(ALPN) {
        return Err(invalid("Relay protocol version mismatch"));
    }
    Ok(tls)
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    #[tokio::test]
    async fn tls_identity_and_version_are_mandatory() {
        let identity = SigningKey::from_bytes(&[8; 32]);
        for wrong in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let server = acceptor(&identity).unwrap();
            let task = tokio::spawn(async move {
                let (raw, _) = listener.accept().await.unwrap();
                if let Ok(mut secured) = accept(&server, raw).await {
                    secured.write_all(b"protected").await.unwrap();
                }
            });
            let pin = if wrong {
                SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()
            } else {
                identity.verifying_key().to_bytes()
            };
            let connection = connect(TcpStream::connect(endpoint).await.unwrap(), pin).await;
            if wrong {
                assert!(connection.is_err());
            } else {
                let mut secured = connection.unwrap();
                let mut bytes = [0; 9];
                secured.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"protected");
            }
            task.await.unwrap();
        }
    }
    #[tokio::test]
    async fn missing_alpn_is_rejected() {
        let identity = SigningKey::from_bytes(&[11; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = acceptor(&identity).unwrap();
        let task = tokio::spawn(async move {
            let (raw, _) = listener.accept().await.unwrap();
            assert!(accept(&server, raw).await.is_err());
        });
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(IdentityVerifier {
            pinned: identity.verifying_key().to_bytes(),
            provider: provider.clone(),
        });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connection = TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from("relay.anonguard.invalid").unwrap(),
                TcpStream::connect(endpoint).await.unwrap(),
            )
            .await;
        // TLS can finish without ALPN; the application accept path must refuse it.
        drop(connection);
        task.await.unwrap();
    }
}
