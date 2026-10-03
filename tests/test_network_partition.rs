use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

use anonguard::mesh::authority::DirectoryAuthority;

/// Network Partition Simulation showing that a split-brain does NOT result in
/// conflicting consensus documents being signed, since quorum (2f+1) cannot be reached.
#[tokio::test]
async fn test_network_partition_no_split_brain() {
    let test_difficulty = 8;

    // N=4 authorities. f=1. Quorum requires 2f+1 = 3 signatures.
    // We simulate a 2 vs 2 split.

    let mut auths = Vec::new();
    let mut addrs = Vec::new();
    let mut pinned_keys = HashMap::new();

    for i in 0..4 {
        let addr = format!("127.0.0.1:{}", 19100 + i);
        addrs.push(addr.clone());
        let mut auth = DirectoryAuthority::with_difficulty(
            format!("auth-{}", i),
            addr.clone(),
            test_difficulty,
        );
        auth.allow_unauthenticated_registration = false;
        pinned_keys.insert(addr, auth.verifying_key());
        auths.push(auth);
    }

    // Give all authorities the full peer list so N=4, f=1, quorum=3
    let all_peers: Vec<(String, Option<ed25519_dalek::VerifyingKey>)> = addrs
        .iter()
        .map(|addr| (addr.clone(), Some(*pinned_keys.get(addr).unwrap())))
        .collect();

    for auth in auths.iter_mut() {
        auth.peer_authorities = all_peers.clone();
    }

    // Spawn only first 2 authorities (Partition 1)
    // The other 2 are unreachable (simulating a network partition)
    for auth in auths.iter().take(2) {
        let auth = auth.clone();
        tokio::spawn(async move {
            let _ = auth.run().await;
        });
    }

    sleep(Duration::from_millis(100)).await;

    // In Partition 1, auth 0 tries to generate consensus
    // It will reconcile with auth 1. It only has 2 signatures (from 0 and 1).
    // The quorum requirement is 2f+1 = 3. Since 2 < 3, it should fail.
    let consensus_p1 = auths[0].generate_consensus().await;
    assert!(
        consensus_p1.is_err(),
        "Partition 1 reached split-brain quorum! This breaks BFT."
    );
}
