use anonguard::crypto::identity::SigningKey;
use rand::rngs::OsRng;
use tokio::{net::TcpListener, task::JoinSet};

use anonguard::mesh::authority::DirectoryAuthority;
use anonguard::mesh::consensus::RelayDescriptor;
use anonguard::mesh::sybil::{current_timestamp_secs, solve_pow_bounded};

#[tokio::test]
async fn test_gossip_convergence_multi_round() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .try_init();
    let test_difficulty = 8;
    // Reserve both ephemeral endpoints before starting either server. The
    // listener owns the port throughout startup, without timing-based readiness.
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address_a = listener_a.local_addr().unwrap().to_string();
    let address_b = listener_b.local_addr().unwrap().to_string();

    // Setup two peer authorities
    let mut auth_a = DirectoryAuthority::with_difficulty(
        "auth-A".to_string(),
        address_a.clone(),
        test_difficulty,
    );
    let mut auth_b = DirectoryAuthority::with_difficulty(
        "auth-B".to_string(),
        address_b.clone(),
        test_difficulty,
    );

    auth_a.allow_unauthenticated_registration = true;
    auth_b.allow_unauthenticated_registration = true;

    let key_a = auth_a.verifying_key();
    let key_b = auth_b.verifying_key();

    auth_a.peer_authorities = vec![
        (address_a.clone(), Some(key_a)),
        (address_b.clone(), Some(key_b)),
    ];
    auth_b.peer_authorities = vec![(address_a, Some(key_a)), (address_b, Some(key_b))];

    let auth_a_clone = auth_a.clone();
    let auth_b_clone = auth_b.clone();

    let mut servers = JoinSet::new();
    servers.spawn(async move {
        auth_a_clone.run_listener(listener_a).await.unwrap();
    });
    servers.spawn(async move {
        auth_b_clone.run_listener(listener_b).await.unwrap();
    });

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

    // Run 10 rounds of consensus generation (which triggers gossip reconciliation)
    for round in 1..=10 {
        // Wall-clock epochs can change between A's proposal and B's
        // cross-check. Exact-snapshot verification correctly refuses that
        // transient mismatch; evaluate convergence within one stable epoch.
        // Retry only an observed boundary, never an arbitrary quorum failure.
        let mut successful = false;
        for _attempt in 0..3 {
            let before = current_timestamp_secs() / 300;
            let proposal_a = auth_a.generate_consensus().await;
            let proposal_b = auth_b.generate_consensus().await;
            if current_timestamp_secs() / 300 != before {
                continue;
            }
            proposal_a.unwrap_or_else(|error| panic!("Round {round}, stable epoch: {error}"));
            let consensus_b =
                proposal_b.unwrap_or_else(|error| panic!("Round {round}, stable epoch: {error}"));
            assert!(
                consensus_b
                    .relays
                    .iter()
                    .any(|relay| relay.node_id == "relay-only-on-A"),
                "Round {round}: Authority B failed to retain/gossip relay from Authority A!"
            );
            successful = true;
            break;
        }
        assert!(
            successful,
            "Clock repeatedly changed epochs during round {round}"
        );

        assert!(servers.try_join_next().is_none(), "Authority exited early");
    }
    servers.abort_all();
    while let Some(result) = servers.join_next().await {
        assert!(result.unwrap_err().is_cancelled());
    }
}
