use anonguard::mesh::{ProxyPool, ProxyProtocol};

#[tokio::test]
async fn test_proxy_pool_add_and_rotate() {
    let pool = ProxyPool::new();

    pool.add_proxy("socks5://user:pass@1.1.1.1:1080")
        .await
        .unwrap();
    pool.add_proxy("http://2.2.2.2:8080").await.unwrap();

    assert_eq!(pool.total_count().await, 2);
    assert_eq!(pool.alive_count().await, 2);

    let node1 = pool.get_next().await.unwrap();
    // socks5 should auto-upgrade to socks5h
    assert_eq!(node1.protocol, ProxyProtocol::Socks5h);

    let node2 = pool.get_next().await.unwrap();
    assert_eq!(node2.protocol, ProxyProtocol::Http);

    // Rotate on block
    let rotated = pool.rotate_on_block(&node1.raw_url).await;
    assert!(rotated.is_some());
}

#[tokio::test]
async fn test_proxy_pool_load_from_consensus_quorum() {
    use anonguard::crypto::identity::SigningKey;
    use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    let mut csprng = OsRng;
    let auth1_key = SigningKey::generate(&mut csprng);
    let auth2_key = SigningKey::generate(&mut csprng);
    let auth3_key = SigningKey::generate(&mut csprng);

    let mut trusted_authorities = HashMap::new();
    trusted_authorities.insert("auth-1".to_string(), auth1_key.verifying_key());
    trusted_authorities.insert("auth-2".to_string(), auth2_key.verifying_key());
    trusted_authorities.insert("auth-3".to_string(), auth3_key.verifying_key());

    let relay1_key = SigningKey::generate(&mut csprng);
    let relay2_key = SigningKey::generate(&mut csprng);

    let mut r1 = RelayDescriptor::new(
        "relay-1".to_string(),
        "10.0.0.1".to_string(),
        9050,
        [10u8; 32],
        [0u8; 32],
        false,
        123,
        1000,
    );
    r1.sign_with_key(&relay1_key);

    let mut r2 = RelayDescriptor::new(
        "relay-2".to_string(),
        "10.0.0.2".to_string(),
        9050,
        [20u8; 32],
        [0u8; 32],
        true,
        456,
        1000,
    );
    r2.sign_with_key(&relay2_key);

    let mut doc = ConsensusDocument::new(1000, 3000, vec![r1, r2]);

    // 1. Unsigned consensus fails
    let pool = ProxyPool::new();
    assert!(pool
        .load_from_multi_consensus(&[doc.clone()], &trusted_authorities, 2, 1500)
        .await
        .is_err());

    // 2. 1 signature with threshold 2 fails
    doc.sign_with_authority("auth-1", &auth1_key);
    assert!(pool
        .load_from_multi_consensus(&[doc.clone()], &trusted_authorities, 2, 1500)
        .await
        .is_err());

    // 3. 2 signatures with threshold 2 passes
    doc.sign_with_authority("auth-2", &auth2_key);
    let loaded = pool
        .load_from_multi_consensus(&[doc.clone()], &trusted_authorities, 2, 1500)
        .await
        .unwrap();
    assert_eq!(loaded, 2);
    assert_eq!(pool.total_count().await, 2);

    // 4. Expired document fails
    let pool2 = ProxyPool::new();
    assert!(pool2
        .load_from_multi_consensus(&[doc.clone()], &trusted_authorities, 2, 4000)
        .await
        .is_err());
}

#[tokio::test]
async fn insufficient_relays_never_reduce_requested_hop_count() {
    let pool = ProxyPool::new();
    pool.add_proxy("socks5://1.1.1.1:9050").await.unwrap();
    pool.add_proxy("socks5://2.2.2.2:9050").await.unwrap();
    assert!(pool.get_random_chain(3, 3).await.is_empty());
    assert!(pool
        .get_diverse_onion_chain_with_exit(3, 3, false, false)
        .await
        .is_empty());
    assert!(pool.get_random_chain(3, 2).await.is_empty());
    assert!(pool.get_random_chain(0, 3).await.is_empty());
}

#[tokio::test]
async fn subnet_constraints_must_not_shorten_circuits() {
    let pool = ProxyPool::new();
    for ip in ["10.1.1.1", "10.1.1.2", "10.1.1.3"] {
        pool.add_proxy(&format!("socks5://{ip}:9050"))
            .await
            .unwrap();
    }
    assert!(pool
        .get_diverse_onion_chain_with_exit(3, 3, true, false)
        .await
        .is_empty());
}

#[tokio::test]
async fn expired_loaded_directory_blocks_new_onion_paths() {
    use anonguard::crypto::identity::SigningKey;
    use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
    use rand::rngs::OsRng;
    let auth = SigningKey::generate(&mut OsRng);
    let relay_key = SigningKey::generate(&mut OsRng);
    let mut relay = RelayDescriptor::new(
        "relay".into(),
        "1.1.1.1".into(),
        9050,
        [0; 32],
        [0; 32],
        true,
        0,
        1,
    );
    relay.sign_with_key(&relay_key);
    let mut doc = ConsensusDocument::new(1, 3, vec![relay]);
    doc.sign_with_authority("auth", &auth);
    let keys = std::collections::HashMap::from([("auth".into(), auth.verifying_key())]);
    let pool = ProxyPool::new();
    assert_eq!(
        pool.load_from_multi_consensus(&[doc.clone()], &keys, 1, 2)
            .await
            .unwrap(),
        1
    );
    assert!(pool.get_diverse_onion_chain(1, 1, false).await.is_empty());
    assert!(pool
        .load_from_multi_consensus(&[doc.clone()], &keys, 0, 2)
        .await
        .is_err());
    let mut aliases = keys;
    aliases.insert("alias".into(), auth.verifying_key());
    assert!(pool
        .load_from_multi_consensus(&[doc], &aliases, 2, 2)
        .await
        .is_err());
}

#[tokio::test]
async fn canonical_snapshot_rejects_mixed_views_and_survives_restart() {
    use anonguard::crypto::identity::SigningKey;
    use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
    use rand::rngs::OsRng;
    let auth1 = SigningKey::generate(&mut OsRng);
    let auth2 = SigningKey::generate(&mut OsRng);
    let relay_key = SigningKey::generate(&mut OsRng);
    let now = anonguard::mesh::current_timestamp_secs();
    let mut relay = RelayDescriptor::new(
        "relay".into(),
        "1.1.1.1".into(),
        9050,
        [0; 32],
        [0; 32],
        true,
        0,
        now,
    );
    relay.sign_with_key(&relay_key);
    let mut one = ConsensusDocument::new(now - 10, now + 600, vec![relay.clone()]);
    let mut other = ConsensusDocument::new(now - 9, now + 600, vec![relay.clone()]);
    one.sign_with_authority("a", &auth1);
    other.sign_with_authority("b", &auth2);
    let keys = std::collections::HashMap::from([
        ("a".into(), auth1.verifying_key()),
        ("b".into(), auth2.verifying_key()),
    ]);
    let pool = ProxyPool::new();
    assert!(pool
        .load_from_multi_consensus(&[one.clone(), other], &keys, 2, now)
        .await
        .is_err());
    one.sign_with_authority("b", &auth2);
    let dir = std::env::temp_dir().join(format!(
        "anonguard-snapshot-{:032x}",
        rand::random::<u128>()
    ));
    pool.init_guard_state(dir.join("guards.json"))
        .await
        .unwrap();
    pool.load_from_multi_consensus(&[one.clone()], &keys, 2, now)
        .await
        .unwrap();
    let restarted = ProxyPool::new();
    restarted
        .init_guard_state(dir.join("guards.json"))
        .await
        .unwrap();
    let mut old = ConsensusDocument::new(now - 20, now + 600, vec![relay.clone()]);
    old.sign_with_authority("a", &auth1);
    old.sign_with_authority("b", &auth2);
    assert!(restarted
        .load_from_multi_consensus(&[old], &keys, 2, now)
        .await
        .is_err());
    relay.is_exit = false;
    relay.sign_with_key(&relay_key);
    let mut conflicting = ConsensusDocument::new(now - 10, now + 600, vec![relay]);
    conflicting.sign_with_authority("a", &auth1);
    conflicting.sign_with_authority("b", &auth2);
    assert!(restarted
        .load_from_multi_consensus(&[one.clone(), conflicting.clone()], &keys, 2, now)
        .await
        .is_err());
    assert!(restarted
        .load_from_multi_consensus(&[conflicting], &keys, 2, now)
        .await
        .is_err());
    restarted
        .load_from_multi_consensus(&[one], &keys, 2, now)
        .await
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn entry_failure_cooldown_does_not_revive_an_unavailable_guard() {
    use anonguard::crypto::identity::SigningKey;
    use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
    let authority = SigningKey::from_bytes(&[21; 32]);
    let identity = SigningKey::from_bytes(&[22; 32]);
    let now = anonguard::mesh::current_timestamp_secs();
    let mut relay = RelayDescriptor::new(
        "guard".into(),
        "1.1.1.1".into(),
        9001,
        [0; 32],
        [0; 32],
        false,
        0,
        now,
    );
    relay.sign_with_key(&identity);
    let mut doc = ConsensusDocument::new(now - 1, now + 600, vec![relay]);
    doc.sign_with_authority("a", &authority);
    let keys = std::collections::HashMap::from([("a".into(), authority.verifying_key())]);
    let pool = ProxyPool::new();
    pool.load_from_multi_consensus(&[doc], &keys, 1, now)
        .await
        .unwrap();
    assert_eq!(
        pool.get_diverse_onion_chain_with_exit(1, 1, false, false)
            .await
            .len(),
        1
    );
    pool.note_guard_link_failure(identity.verifying_key().to_bytes())
        .await;
    assert!(pool
        .get_diverse_onion_chain_with_exit(1, 1, false, false)
        .await
        .is_empty());
}

#[tokio::test]
async fn ipv6_directory_endpoint_retains_its_identity_pin() {
    use anonguard::crypto::identity::SigningKey;
    use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
    let authority = SigningKey::from_bytes(&[31; 32]);
    let identity = SigningKey::from_bytes(&[32; 32]);
    let now = anonguard::mesh::current_timestamp_secs();
    let mut relay = RelayDescriptor::new(
        "ipv6".into(),
        "2001:4860:4860::8888".into(),
        9001,
        [0; 32],
        [0; 32],
        false,
        0,
        now,
    );
    relay.sign_with_key(&identity);
    let mut doc = ConsensusDocument::new(now - 1, now + 600, vec![relay]);
    doc.sign_with_authority("a", &authority);
    let pool = ProxyPool::new();
    pool.load_from_multi_consensus(
        &[doc],
        &std::collections::HashMap::from([("a".into(), authority.verifying_key())]),
        1,
        now,
    )
    .await
    .unwrap();
    let chain = pool
        .get_diverse_onion_chain_with_exit(1, 1, false, false)
        .await;
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].host, "2001:4860:4860::8888");
    assert_eq!(
        pool.get_identity_keys(&chain).await,
        vec![identity.verifying_key().to_bytes()]
    );
    assert!(pool.is_mesh_target(&chain[0].host, chain[0].port).await);
}
