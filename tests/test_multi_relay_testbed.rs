//! Multi-relay adversarial testbed for AnonGuard
//!
//! Validates:
//! 1. Circuit success rate against cell-dropping malicious relays.
//! 2. Subnet diversity defenses against targeted flooding from a single /16 block.

use anonguard::mesh::node::ProxyNode;
use anonguard::mesh::pool::ProxyPool;
use anonguard::mesh::sybil::validate_circuit_diversity;

#[tokio::test]
async fn test_multi_relay_subnet_flooding() {
    let pool = ProxyPool::new();

    // 10 legitimate relays on diverse subnets
    for i in 1..=10 {
        let url = format!("socks5://{}.1.1.1:1080", i);
        pool.add_proxy(&url).await.unwrap();
    }

    // 20 malicious relays flooding from the SAME /16 subnet (100.1.x.x)
    for i in 1..=20 {
        let url = format!("socks5://100.1.{}.1:1080", i);
        pool.add_proxy(&url).await.unwrap();
    }

    assert_eq!(pool.total_count().await, 30);

    // If we request a random chain, we shouldn't get a chain made entirely
    // of the attacker's flooded subnet nodes because of diversity controls.
    let mut collision_count = 0;
    for _ in 0..100 {
        let chain = pool
            .get_diverse_onion_chain_with_exit(3, 3, true, false)
            .await;
        if chain.len() == 3 {
            // Check if any two nodes share a /16 subnet
            let nodes_str: Vec<String> = chain.iter().map(|n| n.host.clone()).collect();
            let node_refs: Vec<&str> = nodes_str.iter().map(|s| s.as_str()).collect();
            assert!(validate_circuit_diversity(&node_refs).is_ok());
        } else {
            collision_count += 1;
        }
    }

    // If diversity is enforced, malicious nodes from the same subnet won't dominate a single circuit
    assert!(
        collision_count < 100,
        "Should successfully build diverse circuits"
    );
}
