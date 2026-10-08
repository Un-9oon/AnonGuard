//! Explicit proxy configuration must load completely or leave the pool unchanged.
use anonguard::mesh::{ProxyPool, ProxyProtocol};
use std::{path::PathBuf, time::Duration};
use tokio::process::Command;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("ag-proxy-file-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[tokio::test]
async fn read_errors_do_not_silently_accept_a_partial_proxy_file() {
    let directory = Directory::new();
    let path = directory.0.join("pool.txt");
    let pool = ProxyPool::new();
    pool.add_proxy("http://9.9.9.9:8080").await.unwrap();
    std::fs::write(
        &path,
        b"socks5://1.1.1.1:1080\n\xff\nsocks5://2.2.2.2:1080\n",
    )
    .unwrap();
    assert!(
        pool.load_file(&path).await.is_err(),
        "Invalid UTF-8 silently truncated the configured pool"
    );
    assert_eq!(pool.total_count().await, 1);
    assert_eq!(pool.get_next().await.unwrap().host, "9.9.9.9");
    assert!(pool.load_file(directory.0.join("missing")).await.is_err());
    assert_eq!(pool.total_count().await, 1);
}
#[tokio::test]
async fn malformed_entries_reject_the_whole_file_without_exposing_credentials() {
    let directory = Directory::new();
    let path = directory.0.join("pool.txt");
    let pool = ProxyPool::new();
    pool.add_proxy("http://9.9.9.9:8080").await.unwrap();
    std::fs::write(
        &path,
        "socks5://1.1.1.1:1080\nftp://private-user:private-password@2.2.2.2\n",
    )
    .unwrap();
    let error = pool.load_file(&path).await.unwrap_err();
    assert!(error.contains("line 2"));
    assert!(!error.contains("private-user"));
    assert!(!error.contains("private-password"));
    assert_eq!(pool.total_count().await, 1);
}
#[tokio::test]
async fn complete_file_deduplicates_endpoints_and_preserves_remote_dns_and_addressing() {
    let directory = Directory::new();
    let path = directory.0.join("pool.txt");
    std::fs::write(&path,"# comment\n\n1.1.1.1:8080\nhttps://[2001:db8::1]\nsocks4://2.2.2.2\nsocks5://3.3.3.3\nhttp://user:pass@1.1.1.1:8080\n").unwrap();
    let pool = ProxyPool::new();
    assert_eq!(pool.load_file(&path).await.unwrap(), 4);
    assert_eq!(pool.total_count().await, 4);
    let mut nodes = std::collections::HashMap::new();
    for _ in 0..4 {
        let node = pool.get_next().await.unwrap();
        assert!(!node.is_exit);
        nodes.insert(node.host.clone(), node);
    }
    assert_eq!(nodes["1.1.1.1"].username.as_deref(), Some("user"));
    assert_eq!(nodes["2001:db8::1"].protocol, ProxyProtocol::Https);
    assert_eq!(nodes["2001:db8::1"].port, 443);
    assert_eq!(nodes["2.2.2.2"].protocol, ProxyProtocol::Socks4a);
    assert_eq!(nodes["2.2.2.2"].port, 1080);
    assert_eq!(nodes["3.3.3.3"].protocol, ProxyProtocol::Socks5h);
}
#[tokio::test]
async fn cli_rejects_bad_explicit_pool_and_inline_proxy_before_starting_a_gateway() {
    let directory = Directory::new();
    let malformed = directory.0.join("pool.txt");
    std::fs::write(&malformed, b"socks5://1.1.1.1:1080\n\xff\n").unwrap();
    for extra in [
        vec![
            "--pool".to_string(),
            directory.0.join("missing").display().to_string(),
        ],
        vec!["--pool".to_string(), malformed.display().to_string()],
        vec![
            "--proxy".to_string(),
            "ftp://private-user:private-password@2.2.2.2".to_string(),
        ],
    ] {
        let expected = if extra[0] == "--pool" {
            "Configured proxy file rejected"
        } else {
            "Invalid --proxy endpoint"
        };
        let output = tokio::time::timeout(
            Duration::from_secs(3),
            Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"))
                .args(["--listen", "127.0.0.1:0", "--identity-key-path"])
                .arg(directory.0.join("identity.key"))
                .arg("--guard-state-path")
                .arg(directory.0.join("guards.json"))
                .args(extra)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("Invalid explicit proxy configuration started a daemon")
        .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "Unexpected startup failure: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for text in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(text).contains("private-password"));
        }
    }
}
