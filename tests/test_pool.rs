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
    use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
    use ed25519_dalek::SigningKey;
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
    assert!(pool.load_from_consensus(&doc, &trusted_authorities, 2, 1500).await.is_err());

    // 2. 1 signature with threshold 2 fails
    doc.sign_with_authority("auth-1", &auth1_key);
    assert!(pool.load_from_consensus(&doc, &trusted_authorities, 2, 1500).await.is_err());

    // 3. 2 signatures with threshold 2 passes
    doc.sign_with_authority("auth-2", &auth2_key);
    let loaded = pool.load_from_consensus(&doc, &trusted_authorities, 2, 1500).await.unwrap();
    assert_eq!(loaded, 2);
    assert_eq!(pool.total_count().await, 2);

    // 4. Expired document fails
    let pool2 = ProxyPool::new();
    assert!(pool2.load_from_consensus(&doc, &trusted_authorities, 2, 4000).await.is_err());
}
