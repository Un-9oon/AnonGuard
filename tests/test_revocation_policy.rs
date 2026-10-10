//! Quorum retirement cannot be weakened by aliases, rollback or local-file errors.
use anonguard::crypto::identity::{SigningKey, VerifyingKey};
use anonguard::{
    core::{
        revocation::{load_and_commit, RevocationPolicy},
        storage,
    },
    mesh::{ConsensusDocument, DirectoryAuthority, ProxyPool, RelayDescriptor},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("ag-retirement-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn authorities() -> (Vec<SigningKey>, HashMap<String, VerifyingKey>) {
    let keys: Vec<_> = (1..=4)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let pins = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (format!("a{i}"), k.verifying_key()))
        .collect();
    (keys, pins)
}
fn signed(generation: u64, retired: Vec<[u8; 32]>) -> RevocationPolicy {
    let (keys, pins) = authorities();
    let mut policy = RevocationPolicy::new(generation, &pins, retired);
    for (i, key) in keys.iter().enumerate().take(3) {
        policy.sign(&format!("a{i}"), key).unwrap();
    }
    policy
}
fn public(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn write(path: &std::path::Path, policy: &RevocationPolicy) {
    storage::atomic_write(path, &serde_json::to_vec(policy).unwrap()).unwrap();
}

#[test]
fn signatures_bind_generation_identity_set_and_authority_set() {
    let (_, pins) = authorities();
    let policy = signed(1, vec![public(50)]);
    assert!(policy.verify(&pins, 3).is_ok());
    for case in 0..5 {
        let mut altered = policy.clone();
        match case {
            0 => altered.generation += 1,
            1 => altered.revoked[0] = public(51),
            2 => altered.authority_set[0] ^= 1,
            3 => altered.signatures.truncate(2),
            _ => altered.signatures[0].signature_bytes[0] ^= 1,
        }
        assert!(altered.verify(&pins, 3).is_err());
    }
    for quorum in [0, 1, 2, 5] {
        assert!(policy.verify(&pins, quorum).is_err());
    }
    let mut aliases = pins.clone();
    aliases.insert("alias".into(), pins["a0"]);
    assert!(policy.verify(&aliases, 4).is_err());
    let mut duplicate_votes = policy.clone();
    duplicate_votes.signatures = vec![policy.signatures[0].clone(); 3];
    assert!(duplicate_votes.verify(&pins, 3).is_err());
    let mut malformed = policy;
    malformed.revoked.push(malformed.revoked[0]);
    assert!(malformed.verify(&pins, 3).is_err());
}

#[test]
fn restart_rejects_policy_omission_rollback_equivocation_and_resurrection() {
    let workspace = Workspace::new();
    let input = workspace.0.join("policy.json");
    let journal = workspace.0.join("accepted.json");
    let (_, pins) = authorities();
    assert!(load_and_commit(None, &journal, &pins, 3)
        .unwrap()
        .is_empty());
    let current = signed(2, vec![public(50)]);
    write(&input, &current);
    assert_eq!(
        load_and_commit(Some(&input), &journal, &pins, 3).unwrap(),
        HashSet::from([public(50)])
    );
    let original = std::fs::read(&journal).unwrap();
    assert!(load_and_commit(None, &journal, &pins, 3).is_err());
    for bad in [
        signed(1, vec![public(50)]),
        signed(2, vec![public(51)]),
        signed(3, vec![]),
    ] {
        write(&input, &bad);
        assert!(load_and_commit(Some(&input), &journal, &pins, 3).is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), original);
    }
    write(&input, &current);
    assert!(load_and_commit(Some(&input), &journal, &pins, 3).is_ok());
    write(&input, &signed(3, vec![public(50), public(51)]));
    assert_eq!(
        load_and_commit(Some(&input), &journal, &pins, 3)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn invalid_policy_or_failed_persistence_never_enrolls_or_overwrites_state() {
    let workspace = Workspace::new();
    let input = workspace.0.join("policy.json");
    let journal = workspace.0.join("accepted.json");
    let (_, pins) = authorities();
    let mut invalid = signed(1, vec![]);
    invalid.signatures.clear();
    write(&input, &invalid);
    assert!(load_and_commit(Some(&input), &journal, &pins, 3).is_err());
    assert!(!journal.exists());
    write(&input, &signed(1, vec![]));
    std::fs::create_dir(&journal).unwrap();
    assert!(load_and_commit(Some(&input), &journal, &pins, 3).is_err());
    assert!(journal.is_dir());
}

#[test]
fn interrupted_enrollment_cannot_silently_start_without_a_policy() {
    let workspace = Workspace::new();
    let journal = workspace.0.join("accepted.json");
    let input = workspace.0.join("policy.json");
    let (_, pins) = authorities();
    write(&input, &signed(1, vec![]));
    let lock = journal.with_extension("lock");
    std::fs::write(&lock, b"interrupted enrollment").unwrap();
    assert!(load_and_commit(None, &journal, &pins, 3).is_err());
    assert!(load_and_commit(Some(&input), &journal, &pins, 3).is_err());
    assert_eq!(std::fs::read(&lock).unwrap(), b"interrupted enrollment");
    assert!(!journal.exists());
}

fn key_arguments() -> String {
    let (_, keys) = authorities();
    (0..4)
        .map(|i| format!("a{i}:{}", hex::encode(keys[&format!("a{i}")].as_bytes())))
        .collect::<Vec<_>>()
        .join(",")
}

async fn invoke(binary: &str, args: &[String]) -> std::process::Output {
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new(binary)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("Offline ceremony or refused startup exceeded deadline")
    .unwrap()
}

#[tokio::test]
async fn offline_cli_ceremony_binds_signer_and_refuses_key_creation_and_overwrite() {
    let workspace = Workspace::new();
    let binary = env!("CARGO_BIN_EXE_anonguard-identity-policy");
    let (keys, pins) = authorities();
    let template = workspace.0.join("unsigned.json");
    let create = vec![
        "create".into(),
        "--generation".into(),
        "1".into(),
        "--authority-keys".into(),
        key_arguments(),
        "--retire".into(),
        hex::encode(public(50)),
        "--output".into(),
        template.display().to_string(),
    ];
    assert!(invoke(binary, &create).await.status.success());
    let original = std::fs::read(&template).unwrap();
    assert!(!invoke(binary, &create).await.status.success());
    assert_eq!(std::fs::read(&template).unwrap(), original);
    let mut input = template;
    for (i, key) in keys.iter().enumerate().take(3) {
        let path = workspace.0.join(format!("a{i}.key"));
        storage::atomic_write(&path, &key.to_bytes()).unwrap();
        let output = workspace.0.join(format!("signed-{i}.json"));
        let args = vec![
            "sign".into(),
            "--input".into(),
            input.display().to_string(),
            "--authority-id".into(),
            format!("a{i}"),
            "--identity-key-path".into(),
            path.display().to_string(),
            "--authority-keys".into(),
            key_arguments(),
            "--output".into(),
            output.display().to_string(),
        ];
        assert!(invoke(binary, &args).await.status.success());
        input = output;
    }
    let policy: RevocationPolicy = serde_json::from_slice(&std::fs::read(&input).unwrap()).unwrap();
    assert!(policy.verify(&pins, 3).is_ok());
    let missing = workspace.0.join("missing.key");
    let output = workspace.0.join("never-created.json");
    let args = vec![
        "sign".into(),
        "--input".into(),
        input.display().to_string(),
        "--authority-id".into(),
        "a3".into(),
        "--identity-key-path".into(),
        missing.display().to_string(),
        "--authority-keys".into(),
        key_arguments(),
        "--output".into(),
        output.display().to_string(),
    ];
    assert!(!invoke(binary, &args).await.status.success());
    assert!(!missing.exists());
    assert!(!output.exists());
    storage::atomic_write(&missing, &keys[0].to_bytes()).unwrap();
    assert!(!invoke(binary, &args).await.status.success());
    assert!(!output.exists());
}

#[tokio::test]
async fn cli_rejects_retired_local_identity_and_policy_omission_before_listening() {
    let workspace = Workspace::new();
    let local = workspace.0.join("local.key");
    let guards = workspace.0.join("guards.json");
    let policy = workspace.0.join("policy.json");
    storage::atomic_write(&local, &SigningKey::from_bytes(&[50; 32]).to_bytes()).unwrap();
    write(&policy, &signed(1, vec![public(50)]));
    let mut args = vec![
        "--onion".into(),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--identity-key-path".into(),
        local.display().to_string(),
        "--guard-state-path".into(),
        guards.display().to_string(),
        "--authorities".into(),
        "a0@127.0.0.1:9100,a1@127.0.0.1:9101,a2@127.0.0.1:9102,a3@127.0.0.1:9103".into(),
        "--authority-keys".into(),
        key_arguments(),
        "--quorum-threshold".into(),
        "3".into(),
    ];
    let enrolled = [
        args.clone(),
        vec!["--revocation-policy".into(), policy.display().to_string()],
    ]
    .concat();
    let binary = env!("CARGO_BIN_EXE_anonguard-daemon");
    let first = invoke(binary, &enrolled).await;
    assert!(!first.status.success());
    assert!(String::from_utf8_lossy(&first.stderr).contains("Local routing identity is retired"));
    // Fixing the local identity must not permit omission of the enrolled policy.
    storage::atomic_write(&local, &SigningKey::from_bytes(&[51; 32]).to_bytes()).unwrap();
    let omitted = invoke(binary, &args).await;
    assert!(!omitted.status.success());
    assert!(String::from_utf8_lossy(&omitted.stderr)
        .contains("requires its signed identity retirement policy"));
    args.extend([
        "--revocation-policy".into(),
        policy.display().to_string(),
        "--proxy".into(),
        "socks5://127.0.0.1:9001".into(),
    ]);
    assert!(!invoke(binary, &args).await.status.success());
}

fn relay(seed: u8, now: u64) -> RelayDescriptor {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut relay = RelayDescriptor::new(
        format!("r{seed}"),
        format!("{seed}.1.1.1"),
        9001,
        [1; 32],
        key.verifying_key().to_bytes(),
        true,
        1,
        now - 1,
    );
    relay.sign_with_key(&key);
    relay
}

#[tokio::test]
async fn retired_relay_is_rejected_at_authority_and_removed_from_verified_pool() {
    let now = anonguard::mesh::current_timestamp_secs();
    let retired = relay(50, now);
    let live = relay(51, now);
    let denied = HashSet::from([retired.identity_pin]);
    let authority = DirectoryAuthority::with_difficulty("a".into(), "127.0.0.1:0".into(), 0)
        .with_revoked_identities(denied.clone());
    assert!(authority
        .register_relay(retired.clone())
        .await
        .unwrap_err()
        .contains("retired"));
    authority.register_relay(live.clone()).await.unwrap();
    assert_eq!(authority.reconcile_relays().await, vec![live.clone()]);
    let (keys, pins) = authorities();
    let mut doc = ConsensusDocument::new(now - 1, now + 600, vec![retired.clone(), live.clone()]);
    for (i, key) in keys.iter().enumerate().take(3) {
        doc.sign_with_authority(&format!("a{i}"), key);
    }
    let pool = ProxyPool::with_revoked_identities(denied);
    assert_eq!(
        pool.load_from_multi_consensus(&[doc], &pins, 3, now)
            .await
            .unwrap(),
        1
    );
    assert!(!pool.is_mesh_target(&retired.host, retired.port).await);
    assert!(pool.is_mesh_target(&live.host, live.port).await);
}

#[tokio::test]
async fn authenticated_peer_gossip_cannot_reintroduce_a_retired_relay() {
    let now = anonguard::mesh::current_timestamp_secs();
    let retired = relay(50, now);
    let peer_key = SigningKey::from_bytes(&[90; 32]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut authority = DirectoryAuthority::with_difficulty("a".into(), "127.0.0.1:0".into(), 0)
        .with_revoked_identities(HashSet::from([retired.identity_pin]));
    authority.peer_authorities = vec![(
        listener.local_addr().unwrap().to_string(),
        Some(peer_key.verifying_key()),
    )];
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut session =
            anonguard::mesh::SecureTransportSession::server_handshake(socket, Some(&peer_key))
                .await
                .unwrap();
        assert_eq!(session.read_frame().await.unwrap(), b"GET_RELAY_LIST");
        session
            .write_document(&serde_json::to_vec(&vec![retired]).unwrap())
            .await
            .unwrap();
    });
    assert!(authority.reconcile_relays().await.is_empty());
    peer.await.unwrap();
}

#[test]
fn authority_replacement_requires_a_higher_policy_generation_and_preserves_retirements() {
    let workspace = Workspace::new();
    let input = workspace.0.join("policy.json");
    let journal = workspace.0.join("accepted.json");
    let (mut keys, old_pins) = authorities();
    write(&input, &signed(1, vec![public(50)]));
    load_and_commit(Some(&input), &journal, &old_pins, 3).unwrap();
    keys[0] = SigningKey::from_bytes(&[90; 32]);
    let new_pins: HashMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| (format!("a{i}"), key.verifying_key()))
        .collect();
    for generation in [1, 2] {
        let mut policy = RevocationPolicy::new(generation, &new_pins, vec![public(50), public(1)]);
        for (i, key) in keys.iter().enumerate().take(3) {
            policy.sign(&format!("a{i}"), key).unwrap();
        }
        write(&input, &policy);
        let result = load_and_commit(Some(&input), &journal, &new_pins, 3);
        if generation == 1 {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().len(), 2);
        }
    }
}

#[tokio::test]
async fn frozen_retired_vote_is_never_rewritten_or_served_as_current() {
    let workspace = Workspace::new();
    let key_path = workspace.0.join("authority.key");
    let authority =
        DirectoryAuthority::with_persistent_key("a".into(), "127.0.0.1:0".into(), 0, &key_path);
    let now = anonguard::mesh::current_timestamp_secs();
    for seed in 50..53 {
        authority.register_relay(relay(seed, now)).await.unwrap();
    }
    let vote = authority.generate_consensus().await.unwrap();
    drop(authority);
    let journal = key_path.with_extension("votes.json");
    let original = std::fs::read(&journal).unwrap();
    let restarted =
        DirectoryAuthority::with_persistent_key("a".into(), "127.0.0.1:0".into(), 0, &key_path)
            .with_revoked_identities(HashSet::from([public(50)]));
    assert!(restarted.generate_consensus().await.is_err());
    assert_eq!(std::fs::read(&journal).unwrap(), original);
    assert!(vote.relays.iter().any(|r| r.identity_pin == public(50)));
}
