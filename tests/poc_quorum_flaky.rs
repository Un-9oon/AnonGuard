//! Review PoC: does the daemon's fetch->merge-by-digest->verify_quorum flow reach 2-of-2 in practice?
use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
use anonguard::mesh::sybil::{current_timestamp_secs, solve_pow_bounded};
use anonguard::mesh::{DirectoryAuthority, SecureTransportSession};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

async fn fetch(addr: &str, vk: &VerifyingKey) -> ConsensusDocument {
    let s = TcpStream::connect(addr).await.unwrap();
    let mut sess = SecureTransportSession::client_handshake(s, Some(vk))
        .await
        .unwrap();
    sess.write_frame(b"GET_CONSENSUS").await.unwrap();
    serde_json::from_slice(&sess.read_frame().await.unwrap()).unwrap()
}

#[tokio::test]
async fn poc_quorum_depends_on_wall_clock_second() {
    let now = current_timestamp_secs();
    let rk = SigningKey::generate(&mut OsRng);
    let nonce = solve_pow_bounded("relay-a", now, 8).unwrap();
    let mut d = RelayDescriptor::new(
        "relay-a".into(),
        "1.2.3.4".into(),
        9001,
        [7; 32],
        [0; 32],
        true,
        nonce,
        now,
    );
    d.sign_with_key(&rk);

    let a1 = Arc::new(DirectoryAuthority::with_difficulty(
        "auth-1".into(),
        "127.0.0.1:19301".into(),
        8,
    ));
    let a2 = Arc::new(DirectoryAuthority::with_difficulty(
        "auth-2".into(),
        "127.0.0.1:19302".into(),
        8,
    ));
    a1.register_relay(d.clone()).await.unwrap();
    a2.register_relay(d.clone()).await.unwrap();
    let (v1, v2) = (a1.verifying_key(), a2.verifying_key());
    for a in [a1.clone(), a2.clone()] {
        tokio::spawn(async move {
            let _ = a.run().await;
        });
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut trusted = HashMap::new();
    trusted.insert("auth-1".to_string(), v1);
    trusted.insert("auth-2".to_string(), v2);

    for gap_ms in [0u64, 300, 700] {
        let mut ok = 0;
        let n = 20;
        for i in 0..n {
            tokio::time::sleep(Duration::from_millis(37 * (i as u64 % 27) + 11)).await;
            let mut m = fetch("127.0.0.1:19301", &v1).await;
            tokio::time::sleep(Duration::from_millis(gap_ms)).await;
            let other = fetch("127.0.0.1:19302", &v2).await;
            m.merge_signatures_from(&other);
            if m.verify_quorum(&trusted, 2, current_timestamp_secs()) {
                ok += 1;
            }
        }
        println!("gap between the two authority fetches = {gap_ms:>3} ms -> 2-of-2 quorum reached in {ok}/{n} rounds");
    }
}
