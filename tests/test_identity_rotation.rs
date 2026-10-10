//! Administrative authority replacement must preserve quorum and rollback state.
//! These cases rehearse existing pin replacement, not an in-band revocation protocol.
use anonguard::crypto::identity::SigningKey;
use anonguard::mesh::{ConsensusDocument, ProxyPool, RelayDescriptor};
use std::{collections::HashMap, path::PathBuf, time::Duration};

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("ag-rotation-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn directory(epoch: u64, until: u64) -> ConsensusDocument {
    let key = SigningKey::from_bytes(&[71; 32]);
    let mut relay = RelayDescriptor::new(
        "relay".into(),
        "1.1.1.1".into(),
        9001,
        [1; 32],
        key.verifying_key().to_bytes(),
        true,
        1,
        epoch,
    );
    relay.sign_with_key(&key);
    ConsensusDocument::new(epoch, until, vec![relay])
}
fn sign(mut doc: ConsensusDocument, keys: &[SigningKey], indices: &[usize]) -> ConsensusDocument {
    for &index in indices {
        doc.sign_with_authority(&format!("a{index}"), &keys[index]);
    }
    doc
}
fn pins(keys: &[SigningKey]) -> HashMap<String, anonguard::crypto::identity::VerifyingKey> {
    keys.iter()
        .enumerate()
        .map(|(i, key)| (format!("a{i}"), key.verifying_key()))
        .collect()
}

#[tokio::test]
async fn replaced_authority_pin_rejects_old_key_without_lowering_quorum_or_resetting_epoch() {
    let workspace = Workspace::new();
    let state = workspace.0.join("guards.json");
    let old: Vec<_> = (11..15)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let mut new = old.clone();
    new[0] = SigningKey::from_bytes(&[33; 32]);
    let now = anonguard::mesh::current_timestamp_secs();
    let before = sign(directory(now - 20, now + 600), &old, &[0, 1, 2]);
    let pool = ProxyPool::new();
    pool.init_guard_state(state.clone()).await.unwrap();
    pool.load_from_multi_consensus(std::slice::from_ref(&before), &pins(&old), 3, now)
        .await
        .unwrap();

    // Two current authorities plus the removed key cannot make the old threshold.
    let obsolete = sign(directory(now - 10, now + 600), &old, &[0, 1, 2]);
    assert!(obsolete.verify_quorum(&pins(&old), 3, now));
    assert!(!obsolete.verify_quorum(&pins(&new), 3, now));
    assert!(pool
        .load_from_multi_consensus(&[obsolete], &pins(&new), 3, now)
        .await
        .is_err());
    assert_eq!(pool.total_count().await, 1);
    let replacement = sign(directory(now - 10, now + 600), &new, &[0, 1, 2]);
    pool.load_from_multi_consensus(&[replacement], &pins(&new), 3, now)
        .await
        .unwrap();

    let restarted = ProxyPool::new();
    restarted.init_guard_state(state).await.unwrap();
    // A valid certificate by three unchanged authorities is still rejected if stale.
    let stale = sign(directory(now - 20, now + 600), &new, &[1, 2, 3]);
    assert!(stale.verify_quorum(&pins(&new), 3, now));
    assert!(restarted
        .load_from_multi_consensus(&[stale], &pins(&new), 3, now)
        .await
        .unwrap_err()
        .contains("rollback"));
    assert_eq!(restarted.total_count().await, 0);
}

#[tokio::test]
async fn replacement_key_cannot_reuse_old_authority_vote_journal() {
    let workspace = Workspace::new();
    let key_path = workspace.0.join("authority.key");
    let old = anonguard::core::storage::load_or_create_signing_key(&key_path).unwrap();
    let now = anonguard::mesh::current_timestamp_secs();
    let mut vote = directory(now - 1, now + 600);
    vote.sign_with_authority("a0", &old);
    let journal = key_path.with_extension("votes.json");
    anonguard::core::storage::atomic_write(&journal, &serde_json::to_vec(&vec![vote]).unwrap())
        .unwrap();
    let original = std::fs::read(&journal).unwrap();
    let replacement = SigningKey::from_bytes(&[33; 32]);
    anonguard::core::storage::atomic_write(&key_path, &replacement.to_bytes()).unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"))
            .args([
                "--authority",
                "--authority-id",
                "a0",
                "--listen",
                "127.0.0.1:0",
                "--identity-key-path",
            ])
            .arg(&key_path)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("Mismatched journal started an authority")
    .unwrap();
    assert!(!output.status.success());
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(logs.contains("vote state failed authentication"), "{logs}");
    assert_eq!(std::fs::read(&journal).unwrap(), original);
    assert_eq!(
        std::fs::read(&key_path).unwrap(),
        replacement.to_bytes().as_slice()
    );
}

#[tokio::test]
async fn oversized_proxy_input_preserves_preexisting_pool() {
    let workspace = Workspace::new();
    let path = workspace.0.join("pool.txt");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(1024 * 1024 + 1).unwrap();
    let pool = ProxyPool::new();
    pool.add_proxy("socks5://9.9.9.9:9001").await.unwrap();
    assert!(pool.load_file(path).await.is_err());
    assert_eq!(pool.total_count().await, 1);
    assert_eq!(pool.get_next().await.unwrap().host, "9.9.9.9");
}
