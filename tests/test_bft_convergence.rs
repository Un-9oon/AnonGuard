use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::time::sleep;

use anonguard::mesh::authority::DirectoryAuthority;
use anonguard::mesh::consensus::RelayDescriptor;
use anonguard::mesh::sybil::{current_timestamp_secs, solve_pow_bounded};

#[tokio::test]
async fn test_gossip_convergence_multi_round() {
    let test_difficulty = 8;

    // Setup two peer authorities
    let mut auth_a = DirectoryAuthority::with_difficulty(
        "auth-A".to_string(),
        "127.0.0.1:19200".to_string(),
        test_difficulty,
    );
    let mut auth_b = DirectoryAuthority::with_difficulty(
        "auth-B".to_string(),
        "127.0.0.1:19201".to_string(),
        test_difficulty,
    );

    auth_a.allow_unauthenticated_registration = true;
    auth_b.allow_unauthenticated_registration = true;

    let key_a = auth_a.verifying_key();
    let key_b = auth_b.verifying_key();

    auth_a.peer_authorities = vec![
        ("127.0.0.1:19200".to_string(), Some(key_a)),
        ("127.0.0.1:19201".to_string(), Some(key_b)),
    ];
    auth_b.peer_authorities = vec![
        ("127.0.0.1:19200".to_string(), Some(key_a)),
        ("127.0.0.1:19201".to_string(), Some(key_b)),
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

    // Register a relay directly on Authority A ONLY.
    let now = current_timestamp_secs();
    let nonce = solve_pow_bounded("relay-only-on-A", now, test_difficulty).unwrap();
    let mut desc = RelayDescriptor::new(
        "relay-only-on-A".to_string(),
        "1.1.1.1".to_string(),
        9001,
        [1u8; 32],
        [0u8; 32],
        false,
        nonce,
        now,
    );
    let relay_key = SigningKey::generate(&mut OsRng);
    desc.sign_with_key(&relay_key);

    auth_a.register_relay(desc.clone()).await.unwrap();

    sleep(Duration::from_millis(500)).await;

    // Run 10 rounds of consensus generation (which triggers gossip reconciliation)
    for round in 1..=10 {
        // A generates consensus (meaningless for A, but normal routine)
        let _ = auth_a.generate_consensus().await;
        // B generates consensus, pulling gossip from A
        let consensus_b = auth_b.generate_consensus().await;

        // Assert B has the relay in every round
        let b_has_relay = consensus_b
            .unwrap()
            .relays
            .iter()
            .any(|r| r.node_id == "relay-only-on-A");
        assert!(
            b_has_relay,
            "Round {}: Authority B failed to retain/gossip relay from Authority A!",
            round
        );

        sleep(Duration::from_millis(50)).await;
    }
}
