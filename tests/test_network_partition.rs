use std::time::Duration;
use tokio::time::sleep;
use std::collections::HashMap;

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
        auth.allow_unauthenticated_registration = true;
        pinned_keys.insert(addr, auth.verifying_key());
        auths.push(auth);
    }
    
    // Simulate Partition 1: auth 0 and 1 only know about each other
    let partition_1 = vec![addrs[0].clone(), addrs[1].clone()];
    for i in 0..2 {
        let mut peers = Vec::new();
        for addr in &partition_1 {
            let key = pinned_keys.get(addr).unwrap().clone();
            peers.push((addr.clone(), Some(key)));
        }
        auths[i].peer_authorities = peers;
    }
    
    // Simulate Partition 2: auth 2 and 3 only know about each other
    let partition_2 = vec![addrs[2].clone(), addrs[3].clone()];
    for i in 2..4 {
        let mut peers = Vec::new();
        for addr in &partition_2 {
            let key = pinned_keys.get(addr).unwrap().clone();
            peers.push((addr.clone(), Some(key)));
        }
        auths[i].peer_authorities = peers;
    }
    
    // Spawn all 4 authorities
    for i in 0..4 {
        let auth = auths[i].clone();
        tokio::spawn(async move {
            let _ = auth.run().await;
        });
    }
    
    sleep(Duration::from_millis(100)).await;
    
    // In Partition 1, auth 0 tries to generate consensus
    // It will reconcile with auth 1. It only has 2 signatures (from 0 and 1).
    // The quorum requirement is 2f+1 = 3. Since 2 < 3, it should either panic (if strictly enforced to succeed in tests)
    // or return a document with < 3 signatures, which clients will reject.
    // In our system, generate_consensus() returns a ConsensusDocument. We must assert its signature count.
    let consensus_p1 = auths[0].generate_consensus().await;
    assert!(consensus_p1.signatures.len() < 3, "Partition 1 reached split-brain quorum! This breaks BFT.");
    assert_eq!(consensus_p1.signatures.len(), 2, "Expected exactly 2 signatures in partition 1");

    // In Partition 2, auth 2 tries to generate consensus
    let consensus_p2 = auths[2].generate_consensus().await;
    assert!(consensus_p2.signatures.len() < 3, "Partition 2 reached split-brain quorum! This breaks BFT.");
    assert_eq!(consensus_p2.signatures.len(), 2, "Expected exactly 2 signatures in partition 2");
    
    // Thus, no client will ever accept consensus_p1 or consensus_p2, meaning no split-brain
    // can successfully trick the network.
}
