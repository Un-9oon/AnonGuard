use std::{fs, process::Command};

struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn directory() -> Directory {
    let path = std::env::temp_dir().join(format!("anonguard-init-{:032x}", rand::random::<u128>()));
    fs::create_dir(&path).unwrap();
    Directory(path)
}
#[test]
fn initialization_prints_matching_pin_and_preserves_existing_identity() {
    let dir = directory();
    let path = dir.0.join("identity.key");
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = occupied.local_addr().unwrap().to_string();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"))
            .args(["--initialize-identity", "--identity-key-path"])
            .arg(&path)
            .args(["--listen", &endpoint])
            .output()
            .unwrap()
    };
    let first = invoke();
    assert!(first.status.success(), "{:?}", first);
    let bytes = fs::read(&path).unwrap();
    let public = hex::encode(
        anonguard::core::storage::read_identity_key(&path)
            .unwrap()
            .verifying_key()
            .to_bytes(),
    );
    let doc: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(doc["public_key_hybrid_pin"], public);
    assert_eq!(doc.as_object().unwrap().len(), 4);
    let second = invoke();
    assert!(second.status.success());
    assert_eq!(second.stdout, first.stdout);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn initialization_rejects_corruption_and_role_conflicts_without_replacing_key() {
    let dir = directory();
    let path = dir.0.join("identity.key");
    fs::write(&path, b"corrupt").unwrap();
    for extra in [None, Some("--authority"), Some("--relay")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"));
        command
            .args(["--initialize-identity", "--identity-key-path"])
            .arg(&path);
        if let Some(flag) = extra {
            command.arg(flag);
        }
        let result = command.output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(fs::read(&path).unwrap(), b"corrupt");
    }
    let result = Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"))
        .arg("--initialize-identity")
        .output()
        .unwrap();
    assert!(!result.status.success());
}
