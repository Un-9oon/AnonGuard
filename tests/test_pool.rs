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
