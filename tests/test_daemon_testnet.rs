#![cfg(target_os = "linux")]
//! Local CLI testnet: four pinned authorities, three relays, and a real gateway.
//! This is deployment-path regression coverage, not independent anonymity evidence.
use anonguard::core::config::AuthorityEndpoint;
use anonguard::mesh::{PinnedDirectoryClient, ProxyPool};
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct Testnet {
    directory: PathBuf,
    daemons: Vec<Child>,
}
impl Testnet {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("ag-daemon-net-{:032x}", rand::random::<u128>()));
        fs::create_dir(&directory).unwrap();
        Self {
            directory,
            daemons: vec![],
        }
    }
    fn start(
        &mut self,
        name: &str,
        address: SocketAddr,
        authority_args: &[String],
        extra: &[&str],
    ) {
        let role = self.directory.join(name);
        fs::create_dir_all(&role).unwrap();
        let output = fs::File::create(role.join("daemon.log")).unwrap();
        let mut args = vec![
            "--listen".into(),
            address.to_string(),
            "--identity-key-path".into(),
            role.join("identity.key").display().to_string(),
            "--guard-state-path".into(),
            role.join("guards.json").display().to_string(),
        ];
        args.extend_from_slice(authority_args);
        args.extend(extra.iter().map(|s| s.to_string()));
        self.daemons.push(
            Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"))
                .args(args)
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        );
    }
    fn interrupt(daemon: &mut Child) -> std::io::Result<()> {
        if daemon.try_wait()?.is_none() {
            let result = Command::new("/bin/kill")
                .args(["-INT", &daemon.id().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if !result.success() {
                return Err(std::io::Error::other("Could not interrupt test daemon"));
            }
        }
        Ok(())
    }
    fn stop_gracefully(&mut self, index: usize) {
        let daemon = &mut self.daemons[index];
        Self::interrupt(daemon).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = daemon.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "Daemon failed during graceful shutdown: {status}"
                );
                return;
            }
            assert!(Instant::now() < deadline, "Daemon did not stop on SIGINT");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn diagnostics(&self) -> String {
        fs::read_dir(&self.directory)
            .unwrap()
            .filter_map(|entry| {
                let role = entry.ok()?.path();
                let log = fs::read_to_string(role.join("daemon.log")).ok()?;
                Some(format!(
                    "{}:\n{}",
                    role.display(),
                    log.chars()
                        .rev()
                        .take(2000)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect::<String>()
                ))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
impl Drop for Testnet {
    fn drop(&mut self) {
        // Preserve normal shutdown behavior for surviving processes. The relay
        // loss scenario still uses an abrupt kill, independently of this cleanup.
        for daemon in &mut self.daemons {
            let _ = Self::interrupt(daemon);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        for daemon in &mut self.daemons {
            while matches!(daemon.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}
async fn ready(address: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Daemon listener did not start");
}

#[tokio::test]
async fn pinned_cli_testnet_bootstraps_transfers_and_closes_after_relay_loss() {
    tokio::time::timeout(Duration::from_secs(90), exercise())
        .await
        .expect("CLI testnet exceeded its bounded lifetime");
}

async fn exercise() {
    let mut testnet = Testnet::new();
    let mut reserved = Vec::new();
    for ip in [
        "127.0.0.1",
        "127.0.0.1",
        "127.0.0.1",
        "127.0.0.1",
        "127.1.0.1",
        "127.2.0.1",
        "127.3.0.1",
        "127.0.0.1",
    ] {
        reserved.push(Some(std::net::TcpListener::bind((ip, 0)).unwrap()));
    }
    let addresses: Vec<_> = reserved
        .iter()
        .map(|socket| socket.as_ref().unwrap().local_addr().unwrap())
        .collect();
    let endpoints: Vec<_> = (0..4)
        .map(|i| {
            let role = testnet.directory.join(format!("authority-{i}"));
            let key =
                anonguard::core::storage::load_or_create_signing_key(&role.join("identity.key"))
                    .unwrap();
            AuthorityEndpoint {
                identity: format!("a{i}"),
                address: addresses[i].to_string(),
                public_key: key.verifying_key().to_bytes(),
            }
        })
        .collect();
    let authority_args = vec![
        "--authorities".into(),
        endpoints
            .iter()
            .map(|e| format!("{}@{}", e.identity, e.address))
            .collect::<Vec<_>>()
            .join(","),
        "--authority-keys".into(),
        endpoints
            .iter()
            .map(|e| format!("{}:{}", e.identity, hex::encode(e.public_key)))
            .collect::<Vec<_>>()
            .join(","),
        "--quorum-threshold".into(),
        "3".into(),
        "--pow-difficulty".into(),
        "0".into(),
    ];
    for i in 0..4 {
        drop(reserved[i].take());
        let identity = format!("a{i}");
        testnet.start(
            &format!("authority-{i}"),
            addresses[i],
            &authority_args,
            &["--authority", "--authority-id", &identity],
        );
        ready(addresses[i]).await;
    }
    for i in 0..3 {
        drop(reserved[4 + i].take());
        let mut extra = vec![
            "--relay",
            "--allow-private-exit",
            "--i-know-this-is-insecure",
        ];
        if i == 2 {
            extra.push("--is-exit");
        }
        testnet.start(
            &format!("relay-{i}"),
            addresses[4 + i],
            &authority_args,
            &extra,
        );
        ready(addresses[4 + i]).await;
    }
    let verifier = PinnedDirectoryClient::new(endpoints, 3).unwrap();
    let pool = ProxyPool::new();
    let admitted = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if verifier.refresh(&pool).await == Ok(3) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        admitted.is_ok(),
        "Bootstrap failed:\n{}",
        testnet.diagnostics()
    );
    drop(reserved[7].take());
    testnet.start("gateway", addresses[7], &authority_args, &["--onion"]);
    ready(addresses[7]).await;
    // Every circuit participant must admit a directory, not just the gateway.
    // Relays can reject an early refresh while registrations are still arriving.
    let states: Vec<_> = ["gateway", "relay-0", "relay-1", "relay-2"]
        .iter()
        .map(|role| testnet.directory.join(role).join("guards.consensus.json"))
        .collect();
    let loaded = tokio::time::timeout(Duration::from_secs(30), async {
        while states.iter().any(|state| !state.exists()) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(
        loaded.is_ok(),
        "Circuit participants did not admit the directory:\n{}",
        testnet.diagnostics()
    );

    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = destination.local_addr().unwrap();
    let (arrived, receiving) = tokio::sync::oneshot::channel();
    let destination_task = tokio::spawn(async move {
        let (mut first, _) = destination.accept().await.unwrap();
        let mut body = Vec::new();
        first.read_to_end(&mut body).await.unwrap();
        assert_eq!(body.len(), 128 * 1024);
        for byte in &mut body {
            *byte ^= 0xa5;
        }
        first.write_all(&body).await.unwrap();
        first.shutdown().await.unwrap();
        let (mut second, _) = destination.accept().await.unwrap();
        let mut marker = [0; 16];
        second.read_exact(&mut marker).await.unwrap();
        assert_eq!(marker, [9; 16]);
        arrived.send(()).unwrap();
        assert_eq!(
            second.read(&mut marker).await.unwrap(),
            0,
            "Exit retained the destination after circuit loss"
        );
    });
    let connect = |gateway| async move {
        anonguard::gateway::chain::socks5_connect_through(
            TcpStream::connect(gateway).await.unwrap(),
            "127.0.0.1",
            address.port(),
            false,
        )
        .await
    };
    let mut tunnel = connect(addresses[7])
        .await
        .unwrap_or_else(|error| panic!("Circuit failed: {error}\n{}", testnet.diagnostics()));
    let request: Vec<_> = (0..128 * 1024)
        .map(|i| ((i * 131 + 17) % 256) as u8)
        .collect();
    tunnel.write_all(&request).await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(25), tunnel.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        response,
        request
            .into_iter()
            .map(|byte| byte ^ 0xa5)
            .collect::<Vec<_>>()
    );
    let mut active = connect(addresses[7]).await.unwrap();
    active.write_all(&[9; 16]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), receiving)
        .await
        .unwrap()
        .unwrap();
    testnet.daemons[5].kill().unwrap();
    testnet.daemons[5].wait().unwrap();
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(10), active.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "Application stream survived a lost circuit"
    );
    tokio::time::timeout(Duration::from_secs(10), destination_task)
        .await
        .unwrap()
        .unwrap();
    // A live, unfinished SOCKS session must close on graceful daemon shutdown.
    let mut waiting = TcpStream::connect(addresses[7]).await.unwrap();
    waiting.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0; 2];
    waiting.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0]);
    testnet.stop_gracefully(7);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), waiting.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "Graceful gateway shutdown retained a client connection"
    );
}
