//! Invalid authority configuration must fail before any role listens or writes keys.
use ed25519_dalek::SigningKey;
use std::{path::PathBuf, time::Duration};
use tokio::process::Command;

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("ag-cli-config-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
async fn invoke(args: Vec<String>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"));
    command.args(args).kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(3), command.output())
        .await
        .expect("Invalid configuration started a daemon instead of failing")
        .unwrap()
}

#[tokio::test]
async fn all_roles_reject_invalid_authority_records_before_key_publication() {
    let workspace = Workspace::new();
    let key_path = workspace.0.join("identity.key");
    let a = public(91);
    let b = public(92);
    let c = public(93);
    let single = "a@127.0.0.1:9000".to_string();
    let triple = "a@127.0.0.1:9000,b@127.0.0.1:9001,c@127.0.0.1:9002".to_string();
    let pins = format!("a:{a},b:{b},c:{c}");
    let too_many = (0..17)
        .map(|index| format!("a{index}@127.0.0.1:{}", 9100 + index))
        .collect::<Vec<_>>()
        .join(",");
    let long_id = "n".repeat(129);
    let cases = vec![
        (
            single.clone(),
            "missing-colon".into(),
            1,
            "expected id:64_HEX_KEY",
        ),
        (
            single.clone(),
            format!(":{a}"),
            1,
            "identifier must not be empty",
        ),
        (
            single.clone(),
            "a:invalid".into(),
            1,
            "Invalid authority key hex",
        ),
        (
            single.clone(),
            format!("a:{a},a:{b}"),
            1,
            "Duplicate authority key identifier",
        ),
        (too_many, format!("a:{a}"), 1, "At most 16"),
        (triple.clone(), pins.clone(), 2, "exceed two thirds"),
        (triple, pins, 4, "exceeds the number of trusted"),
        (
            "127.0.0.1:9000".into(),
            format!("a:{a}"),
            1,
            "identity@address",
        ),
        (
            "@127.0.0.1:9000".into(),
            format!("a:{a}"),
            1,
            "Empty authority identity or address",
        ),
        (
            "a@".into(),
            format!("a:{a}"),
            1,
            "Empty authority identity or address",
        ),
        (
            single.clone(),
            format!("other:{a}"),
            1,
            "matching pinned key",
        ),
        (
            "a@127.0.0.1:9000,a@127.0.0.1:9001".into(),
            format!("127.0.0.1:9000:{a},127.0.0.1:9001:{b}"),
            2,
            "Duplicate authority endpoint identity",
        ),
        (
            "a@127.0.0.1:9000,b@127.0.0.1:9000".into(),
            format!("a:{a},b:{b}"),
            2,
            "distinct addresses",
        ),
        (
            single.clone(),
            format!("a:{}", "00".repeat(32)),
            1,
            "Invalid or duplicate directory identity pin",
        ),
        (
            "a@127.0.0.1:9000 bad".into(),
            format!("a:{a}"),
            1,
            "distinct addresses",
        ),
        (
            format!("{long_id}@127.0.0.1:9000"),
            format!("{long_id}:{a}"),
            1,
            "distinct addresses",
        ),
        (single, format!("a:{a}"), 0, "positive quorum threshold"),
    ];
    for (endpoints, pins, quorum, expected) in cases {
        let output = invoke(vec![
            "--authority".into(),
            "--listen".into(),
            "127.0.0.1:0".into(),
            "--identity-key-path".into(),
            key_path.display().to_string(),
            "--authorities".into(),
            endpoints,
            "--authority-keys".into(),
            pins,
            "--quorum-threshold".into(),
            quorum.to_string(),
        ])
        .await;
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "Invalid authority configuration was accepted"
        );
        assert!(error.contains(expected), "Expected {expected}; got {error}");
        assert!(
            !key_path.exists(),
            "Invalid configuration published a new identity"
        );
    }
}

#[tokio::test]
async fn authority_refuses_a_bootstrap_pin_that_disagrees_with_its_existing_identity() {
    let workspace = Workspace::new();
    let key_path = workspace.0.join("identity.key");
    anonguard::core::storage::load_or_create_signing_key(&key_path).unwrap();
    let original = std::fs::read(&key_path).unwrap();
    let output = invoke(vec![
        "--authority".into(),
        "--authority-id".into(),
        "a".into(),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--identity-key-path".into(),
        key_path.display().to_string(),
        "--authorities".into(),
        "a@127.0.0.1:9000".into(),
        "--authority-keys".into(),
        format!("a:{}", public(94)),
    ])
    .await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("does not match its configured bootstrap pin"));
    assert_eq!(std::fs::read(&key_path).unwrap(), original);
}

#[tokio::test]
async fn status_distinguishes_file_presence_without_claiming_live_daemon_health() {
    let workspace = Workspace::new();
    let key_path = workspace.0.join("identity.key");
    for present in [false, true] {
        if present {
            anonguard::core::storage::load_or_create_signing_key(&key_path).unwrap();
        }
        let output = invoke(vec![
            "--status".into(),
            "--identity-key-path".into(),
            key_path.display().to_string(),
        ])
        .await;
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains(if present {
            "Identity: PRESENT"
        } else {
            "Identity: MISSING"
        }));
        assert!(text.contains("daemon health not checked"));
        assert_eq!(key_path.exists(), present);
    }
}
