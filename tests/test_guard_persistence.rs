struct TestDirectory(std::path::PathBuf);
impl TestDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("anonguard-guards-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

use anonguard::mesh::guards::GuardState;

#[test]
fn guard_identity_pins_survive_replacement_and_restart() {
    let directory = TestDirectory::new();
    let path = directory.path().join("nested/guards.json");
    let mut state = GuardState::new();
    state.guards = vec!["guard-a".into(), "guard-b".into()];
    state.identities.insert("guard-a".into(), [17; 32]);
    state.identities.insert("guard-b".into(), [29; 32]);
    state.save_checked(&path).unwrap();
    let restarted = GuardState::load_checked(&path).unwrap();
    assert_eq!(restarted.guards, state.guards);
    assert_eq!(restarted.identities, state.identities);
    state.guards.remove(1);
    state.identities.remove("guard-b");
    state.save_checked(&path).unwrap();
    let restarted = GuardState::load_checked(&path).unwrap();
    assert_eq!(restarted.guards, vec!["guard-a"]);
    assert_eq!(restarted.identities, state.identities);
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn guard_corruption_and_io_failure_are_not_treated_as_fresh_state() {
    let directory = TestDirectory::new();
    let path = directory.path().join("guards.json");
    assert!(GuardState::load_checked(&path).unwrap().guards.is_empty());
    std::fs::write(&path, b"{truncated").unwrap();
    assert!(GuardState::load_checked(&path).is_err());
    assert!(GuardState::load_checked(directory.path()).is_err());
    let blocked = path.join("guards.json");
    assert!(GuardState::new().save_checked(&blocked).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"{truncated");
}

#[test]
fn failed_atomic_replacement_cleans_temp_files() {
    let directory = TestDirectory::new();
    let occupied = directory.path().join("destination");
    std::fs::create_dir(&occupied).unwrap();
    std::fs::write(occupied.join("existing"), b"preserve").unwrap();
    assert!(GuardState::new().save_checked(&occupied).is_err());
    assert_eq!(
        std::fs::read(occupied.join("existing")).unwrap(),
        b"preserve"
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

async fn seed_directory(authority: &anonguard::mesh::authority::DirectoryAuthority, exit: bool) {
    use anonguard::mesh::{consensus::RelayDescriptor, sybil::current_timestamp_secs};
    for i in 0..3 {
        let key = anonguard::crypto::identity::SigningKey::from_bytes(&[40 + i; 32]);
        let mut relay = RelayDescriptor::new(
            format!("seed-{i}"),
            format!("{}.1.1.1", i + 1),
            9001,
            [i; 32],
            key.verifying_key().to_bytes(),
            exit && i == 2,
            1,
            current_timestamp_secs() - 1,
        );
        relay.sign_with_key(&key);
        authority.register_relay(relay).await.unwrap();
    }
}

#[tokio::test]
async fn authority_restart_retains_its_signed_snapshot() {
    use anonguard::mesh::{
        authority::DirectoryAuthority, consensus::RelayDescriptor, sybil::current_timestamp_secs,
    };
    let directory = TestDirectory::new();
    let path = directory.path().join("authority.key");
    let authority =
        DirectoryAuthority::with_persistent_key("authority".into(), "127.0.0.1:0".into(), 0, &path);
    seed_directory(&authority, true).await;
    let first = authority.generate_consensus().await.unwrap();
    drop(authority);
    let restarted =
        DirectoryAuthority::with_persistent_key("authority".into(), "127.0.0.1:0".into(), 0, &path);
    let key = anonguard::crypto::identity::SigningKey::from_bytes(&[37; 32]);
    let now = current_timestamp_secs();
    let mut relay = RelayDescriptor::new(
        "relay".into(),
        "127.0.0.1".into(),
        9001,
        [1; 32],
        key.verifying_key().to_bytes(),
        false,
        0,
        now,
    );
    relay.sign_with_key(&key);
    restarted.register_relay(relay).await.unwrap();
    let second = restarted.generate_consensus().await.unwrap();
    if second.valid_after == first.valid_after {
        assert_eq!(second.compute_digest(), first.compute_digest());
        assert_eq!(second.signatures, first.signatures);
        assert_eq!(second.relays.len(), 3);
    }
    let pinned = std::collections::HashMap::from([("authority".into(), restarted.verifying_key())]);
    assert!(second.verify_quorum(&pinned, 1, current_timestamp_secs()));
    let persisted: Vec<anonguard::mesh::consensus::ConsensusDocument> =
        serde_json::from_slice(&std::fs::read(path.with_extension("votes.json")).unwrap()).unwrap();
    assert!(persisted
        .iter()
        .any(|doc| doc.compute_digest() == first.compute_digest()));
}

#[tokio::test]
async fn authority_does_not_issue_a_vote_when_persistence_fails() {
    use anonguard::mesh::authority::DirectoryAuthority;
    let directory = TestDirectory::new();
    let path = directory.path().join("authority.key");
    let authority =
        DirectoryAuthority::with_persistent_key("authority".into(), "127.0.0.1:0".into(), 0, &path);
    seed_directory(&authority, true).await;
    let votes = path.with_extension("votes.json");
    std::fs::create_dir(&votes).unwrap();
    assert!(authority
        .generate_consensus()
        .await
        .unwrap_err()
        .contains("Cannot persist authority vote"));
    std::fs::remove_dir(&votes).unwrap();
    let snapshot = authority.generate_consensus().await.unwrap();
    let persisted: Vec<anonguard::mesh::consensus::ConsensusDocument> =
        serde_json::from_slice(&std::fs::read(votes).unwrap()).unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].compute_digest(), snapshot.compute_digest());
}

#[tokio::test]
async fn authority_rejects_clock_rollback_after_restart() {
    use anonguard::mesh::{
        authority::DirectoryAuthority, consensus::ConsensusDocument, sybil::current_timestamp_secs,
    };
    let directory = TestDirectory::new();
    let path = directory.path().join("authority.key");
    let key = anonguard::core::storage::load_or_create_signing_key(&path).unwrap();
    let future_epoch = (current_timestamp_secs() / 300) * 300 + 600;
    let mut future = ConsensusDocument::new(future_epoch, future_epoch + 600, vec![]);
    future.sign_with_authority("authority", &key);
    std::fs::write(
        path.with_extension("votes.json"),
        serde_json::to_vec(&vec![future]).unwrap(),
    )
    .unwrap();
    let authority =
        DirectoryAuthority::with_persistent_key("authority".into(), "127.0.0.1:0".into(), 0, &path);
    assert!(authority
        .generate_consensus()
        .await
        .unwrap_err()
        .contains("clock rollback"));
}

#[tokio::test]
async fn production_bootstrap_does_not_freeze_an_unusable_partial_directory() {
    use anonguard::mesh::{
        authority::DirectoryAuthority, consensus::RelayDescriptor, sybil::current_timestamp_secs,
    };
    let directory = TestDirectory::new();
    let path = directory.path().join("authority.key");
    let authority =
        DirectoryAuthority::with_persistent_key("authority".into(), "127.0.0.1:0".into(), 0, &path);
    assert!(authority
        .generate_consensus()
        .await
        .unwrap_err()
        .contains("voting deferred"));
    seed_directory(&authority, false).await;
    assert!(authority
        .generate_consensus()
        .await
        .unwrap_err()
        .contains("voting deferred"));
    assert!(!path.with_extension("votes.json").exists());
    let key = anonguard::crypto::identity::SigningKey::from_bytes(&[42; 32]);
    let mut exit = RelayDescriptor::new(
        "seed-2".into(),
        "3.1.1.1".into(),
        9001,
        [2; 32],
        key.verifying_key().to_bytes(),
        true,
        2,
        current_timestamp_secs(),
    );
    exit.sign_with_key(&key);
    authority.register_relay(exit).await.unwrap();
    let snapshot = authority.generate_consensus().await.unwrap();
    assert_eq!(snapshot.relays.len(), 3);
    assert!(snapshot.relays.iter().any(|relay| relay.is_exit));
    assert!(path.with_extension("votes.json").exists());
}
