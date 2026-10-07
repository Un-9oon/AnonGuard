//! Certified but malformed directories must not partially replace admitted state.
use anonguard::mesh::{ConsensusDocument, ProxyNode, ProxyPool, RelayDescriptor};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::HashMap;

fn relay(id: &str, host: &str, seed: u8, registered: u64) -> RelayDescriptor {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut relay = RelayDescriptor::new(
        id.into(),
        host.into(),
        9001,
        [seed; 32],
        key.verifying_key().to_bytes(),
        true,
        1,
        registered,
    );
    relay.sign_with_key(&key);
    relay
}
fn certificate(
    relays: Vec<RelayDescriptor>,
    after: u64,
    until: u64,
) -> (ConsensusDocument, HashMap<String, VerifyingKey>) {
    let key = SigningKey::from_bytes(&[101; 32]);
    let mut document = ConsensusDocument::new(after, until, relays);
    document.sign_with_authority("authority", &key);
    (
        document,
        HashMap::from([("authority".into(), key.verifying_key())]),
    )
}

#[tokio::test]
async fn malformed_certified_snapshots_preserve_existing_nodes_and_pins() {
    let now = anonguard::mesh::current_timestamp_secs();
    let epoch = now / 300 * 300;
    let baseline = relay("baseline", "8.8.8.8", 41, epoch - 300);
    let pin = baseline.identity_key_ed25519;
    let pool = ProxyPool::new();
    let (document, authorities) = certificate(vec![baseline], epoch - 300, epoch + 600);
    assert_eq!(
        pool.load_from_multi_consensus(&[document], &authorities, 1, now)
            .await
            .unwrap(),
        1
    );
    let mut bad_signature = relay("bad-signature", "1.1.1.1", 42, epoch);
    bad_signature.signature[0] ^= 1;
    let cases = vec![
        vec![],
        vec![bad_signature],
        vec![
            relay("one", "1.1.1.1", 43, epoch),
            relay("two", "1.1.1.1", 44, epoch),
        ],
        vec![
            relay("same-id", "1.1.1.1", 45, epoch),
            relay("same-id", "9.9.9.9", 46, epoch),
        ],
        vec![
            relay("one", "1.1.1.1", 47, epoch),
            relay("two", "9.9.9.9", 47, epoch),
        ],
        vec![
            relay("one", "2001:4860:4860:0:0:0:0:8888", 48, epoch),
            relay("two", "2001:4860:4860::8888", 49, epoch),
        ],
    ];
    let node = ProxyNode::parse("socks5://8.8.8.8:9001").unwrap();
    for relays in cases {
        let (bad, _) = certificate(relays, epoch, epoch + 600);
        assert!(
            bad.verify_quorum(&authorities, 1, now),
            "The directory certificate itself must be valid"
        );
        assert!(pool
            .load_from_multi_consensus(&[bad], &authorities, 1, now)
            .await
            .is_err());
        assert_eq!(pool.total_count().await, 1);
        assert!(pool.is_mesh_target("8.8.8.8", 9001).await);
        assert_eq!(
            pool.get_identity_keys(std::slice::from_ref(&node)).await,
            vec![pin]
        );
    }
}

#[tokio::test]
async fn expired_directory_is_unusable_through_every_selection_api() {
    let now = anonguard::mesh::current_timestamp_secs();
    let pool = ProxyPool::new();
    let (document, authorities) = certificate(
        vec![relay("old", "8.8.8.8", 51, now - 600)],
        now - 600,
        now - 1,
    );
    pool.load_from_multi_consensus(&[document], &authorities, 1, now - 2)
        .await
        .unwrap();
    let node = ProxyNode::parse("socks5://8.8.8.8:9001").unwrap();
    assert!(!pool.is_mesh_target("8.8.8.8", 9001).await);
    assert_eq!(pool.get_identity_keys(&[node]).await, vec![[0; 32]]);
    assert!(pool.get_diverse_onion_chain(1, 1, true).await.is_empty());
    assert!(
        pool.get_next().await.is_none(),
        "Round-robin selection bypassed directory expiry"
    );
    assert!(
        pool.get_random_chain(1, 1).await.is_empty(),
        "Random selection bypassed directory expiry"
    );
}

#[tokio::test]
async fn uncatalogued_proxy_selection_stays_bounded_and_cannot_create_exits() {
    let pool = ProxyPool::new();
    assert!(pool.get_next().await.is_none());
    for host in ["8.8.8.8", "1.1.1.1", "9.9.9.9"] {
        pool.add_proxy(&format!("socks5://{host}:9001"))
            .await
            .unwrap();
    }
    let mut selected = std::collections::HashSet::new();
    for _ in 0..3 {
        selected.insert(pool.get_next().await.unwrap().host);
    }
    assert_eq!(selected.len(), 3);
    for _ in 0..16 {
        let chain = pool.get_random_chain(2, 3).await;
        assert!((2..=3).contains(&chain.len()));
        assert_eq!(
            chain
                .iter()
                .map(|node| &node.host)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            chain.len()
        );
    }
    for bounds in [(0, 3), (3, 2), (4, 4)] {
        assert!(pool.get_random_chain(bounds.0, bounds.1).await.is_empty());
    }
    assert!(pool.get_diverse_onion_chain(3, 3, true).await.is_empty());
}
