use anonguard::crypto::identity::SigningKey;
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::time::sleep;

use anonguard::mesh::authority::DirectoryAuthority;
use anonguard::mesh::consensus::RelayDescriptor;
use anonguard::mesh::sybil::{current_timestamp_secs, solve_pow_bounded};

#[tokio::test]
async fn test_gossip_impersonation_rejection() {
    let test_difficulty = 8;

    // Setup two peer authorities
    let mut auth_a = DirectoryAuthority::with_difficulty(
        "auth-A".to_string(),
        "127.0.0.1:19210".to_string(),
        test_difficulty,
    );
    let mut auth_b = DirectoryAuthority::with_difficulty(
        "auth-B".to_string(),
        "127.0.0.1:19211".to_string(),
        test_difficulty,
    );

    auth_a.allow_unauthenticated_registration = true;
    auth_b.allow_unauthenticated_registration = true;

    let key_a = auth_a.verifying_key();
    let key_b = auth_b.verifying_key();

    auth_a.peer_authorities = vec![
        ("127.0.0.1:19210".to_string(), Some(key_a)),
        ("127.0.0.1:19211".to_string(), Some(key_b)),
    ];
    auth_b.peer_authorities = vec![
        ("127.0.0.1:19210".to_string(), Some(key_a)),
        ("127.0.0.1:19211".to_string(), Some(key_b)),
    ];

    let auth_a_clone = auth_a.clone();
    let auth_b_clone = auth_b.clone();

    tokio::spawn(async move {
        let _ = auth_a_clone.run().await;
    });
    tokio::spawn(async move {
        let _ = auth_b_clone.run().await;
    });

    sleep(Duration::from_millis(100)).await;

    // Register a relay directly on Authority A ONLY with Key K1
    let now = current_timestamp_secs();
    let nonce = solve_pow_bounded("relay-target", now, test_difficulty).unwrap();
    let mut desc_k1 = RelayDescriptor::new(
        "relay-target".to_string(),
        "1.1.1.1".to_string(),
        9001,
        [1u8; 32],
        [0u8; 32],
        false,
        nonce,
        now,
    );
    let key_k1 = SigningKey::generate(&mut OsRng);
    desc_k1.sign_with_key(&key_k1);
    auth_a.register_relay(desc_k1.clone()).await.unwrap();

    // Register an impersonator relay on Authority B ONLY with Key K2 and NEWER timestamp
    let now_k2 = now + 10;
    let nonce_k2 = solve_pow_bounded("relay-target", now_k2, test_difficulty).unwrap();
    let mut desc_k2 = RelayDescriptor::new(
        "relay-target".to_string(),
        "2.2.2.2".to_string(),
        9002,
        [2u8; 32],
        [0u8; 32],
        false,
        nonce_k2,
        now_k2,
    );
    let key_k2 = SigningKey::generate(&mut OsRng);
    desc_k2.sign_with_key(&key_k2);
    auth_b.register_relay(desc_k2.clone()).await.unwrap();

    sleep(Duration::from_millis(100)).await;

    // A generates consensus, pulling gossip from B. It should reject desc_k2 because of key mismatch.
    let consensus_a = auth_a.generate_consensus().await;

    // Check that A still has K1, not K2!
    assert!(
        consensus_a.is_err(),
        "Conflicting identities must not obtain a two-authority quorum"
    );
    let raw = tokio::net::TcpStream::connect("127.0.0.1:19210")
        .await
        .unwrap();
    let mut session = anonguard::mesh::SecureTransportSession::client_handshake(raw, Some(&key_a))
        .await
        .unwrap();
    session.write_frame(b"GET_RELAY_LIST").await.unwrap();
    let relays: Vec<RelayDescriptor> =
        serde_json::from_slice(&session.read_document().await.unwrap()).unwrap();
    let final_desc = relays
        .iter()
        .find(|r| r.node_id == "relay-target")
        .expect("A should still have the relay");

    assert_eq!(
        final_desc.identity_pin, desc_k1.identity_pin,
        "A should have retained K1"
    );
    assert_ne!(
        final_desc.identity_pin, desc_k2.identity_pin,
        "A should NOT have updated to K2"
    );
}
