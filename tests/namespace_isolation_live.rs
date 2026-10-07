#![cfg(target_os = "linux")]
//! Run explicitly as root in an isolated CI runner with iproute2, nftables and python3.
use anonguard::kernel::{
    netns::{start_isolation, NetnsConfig},
    KillSwitchController,
};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};
struct Cleanup(NetnsConfig, std::path::PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.remove_namespace();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}
#[tokio::test]
#[ignore = "requires root and network namespace capabilities"]
async fn application_namespace_has_proxy_access_and_no_external_route_after_crash() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = [0; 64];
                while let Ok(n) = stream.read(&mut bytes).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let name = format!("ag-test-{:016x}", rand::random::<u64>());
    let dir = std::env::temp_dir().join(&name);
    std::fs::create_dir_all(&dir).unwrap();
    let config = NetnsConfig::new(&name, "127.0.0.1", port);
    let _cleanup = Cleanup(NetnsConfig::new(&name, "127.0.0.1", port), dir.clone());
    let handle = start_isolation(
        &config,
        &dir.join("proxy.sock"),
        KillSwitchController::new(),
        Path::new(env!("CARGO_BIN_EXE_anonguard-daemon")),
    )
    .unwrap();
    let positive=format!("import socket; s=socket.create_connection(('127.0.0.1',{port}),2); s.sendall(b'namespace-test'); assert s.makefile('rb').read(14)==b'namespace-test'");
    let mut ready = false;
    for _ in 0..30 {
        let result = Command::new("ip")
            .args(["netns", "exec", &name, "python3", "-c", &positive])
            .output()
            .await
            .unwrap();
        if result.status.success() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "Namespace proxy never became ready");
    let negative="import socket\nfor family, target in [(socket.AF_INET,('1.1.1.1',443)),(socket.AF_INET6,('2606:4700:4700::1111',443))]:\n s=socket.socket(family,socket.SOCK_STREAM); s.settimeout(1)\n try: s.connect(target)\n except OSError: pass\n else: raise AssertionError('direct network connection escaped namespace')\n";
    let result = Command::new("ip")
        .args(["netns", "exec", &name, "python3", "-c", negative])
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    drop(handle);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let result = Command::new("ip")
        .args(["netns", "exec", &name, "python3", "-c", negative])
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "Direct route appeared after proxy crash"
    );
    echo.abort();
}
