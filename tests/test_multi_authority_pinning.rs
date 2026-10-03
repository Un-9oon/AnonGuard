use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

use anonguard::mesh::authority::DirectoryAuthority;
use anonguard::mesh::SecureTransportSession;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[tokio::test]
async fn test_multi_authority_strict_pinning() {
    let _auth_a = DirectoryAuthority::new("auth-A".to_string(), "127.0.0.1:0".to_string());
    let _auth_b = DirectoryAuthority::new("auth-B".to_string(), "127.0.0.1:0".to_string());

    // Set keys
    let key_a_priv = SigningKey::generate(&mut OsRng);
    let key_b_priv = SigningKey::generate(&mut OsRng);

    // Start listeners manually to get random ports for a test
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap().to_string();
    let addr_b = listener_b.local_addr().unwrap().to_string();

    let mut auth_keys: HashMap<String, VerifyingKey> = HashMap::new();
    auth_keys.insert(addr_a.clone(), key_a_priv.verifying_key());
    auth_keys.insert(addr_b.clone(), key_b_priv.verifying_key());

    // Simulate server side for auth A
    let server_a_key = key_a_priv.clone();
    tokio::spawn(async move {
        let (stream, _) = listener_a.accept().await.unwrap();
        let _ = SecureTransportSession::server_handshake(stream, Some(&server_a_key)).await;
    });

    // Simulate server side for auth B (but wait, let's make B maliciously present A's key!)
    let server_b_key_malicious = key_a_priv.clone(); // B is presenting A's key
    tokio::spawn(async move {
        let (stream, _) = listener_b.accept().await.unwrap();
        let _ =
            SecureTransportSession::server_handshake(stream, Some(&server_b_key_malicious)).await;
    });

    sleep(Duration::from_millis(100)).await;

    // Client connects to A (should succeed because key matches)
    let stream_a = tokio::net::TcpStream::connect(&addr_a).await.unwrap();
    let pinned_a = auth_keys.get(&addr_a).copied();
    assert!(pinned_a.is_some());

    let res_a = SecureTransportSession::client_handshake(stream_a, pinned_a.as_ref()).await;
    assert!(
        res_a.is_ok(),
        "Client should successfully handshake with A using A's key"
    );

    // Client connects to B (should FAIL because B presents A's key, but client expects B's key)
    let stream_b = tokio::net::TcpStream::connect(&addr_b).await.unwrap();
    let pinned_b = auth_keys.get(&addr_b).copied();
    assert!(pinned_b.is_some());

    let res_b = SecureTransportSession::client_handshake(stream_b, pinned_b.as_ref()).await;
    assert!(
        res_b.is_err(),
        "Client must REJECT connection to B presenting A's key (cross-authority MITM)"
    );
}
