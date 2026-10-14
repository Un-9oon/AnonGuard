//! Regression: plaintext legacy registration cannot reach the authenticated tracker.
use anonguard::mesh::tracker::TrackerServer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
#[tokio::test]
async fn plaintext_tracker_commands_are_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tracker = TrackerServer::with_difficulty(address.to_string(), 0);
    let task = tokio::spawn(async move { tracker.run_listener(listener).await.unwrap() });
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"REGISTER_REVERSE node token 0 0\n")
        .await
        .unwrap();
    let mut response = [0; 128];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut response),
    )
    .await
    .unwrap();
    if let Ok(size) = result {
        assert!(!String::from_utf8_lossy(&response[..size]).contains("REGISTERED"));
    }
    task.abort();
}

/// Exercises both gateway callers, including buffered TLS handoff and refill.
#[cfg(unix)]
#[tokio::test]
async fn reverse_gateway_transfers_and_refills_with_private_capability() {
    use anonguard::{
        core::{storage, GuardConfig},
        crypto::identity::SigningKey,
        gateway::{chain::socks5_connect_through, GatewayServer},
        kernel::KillSwitchController,
        mesh::ProxyPool,
        onion::link,
    };
    use std::sync::Arc;
    use std::time::Duration;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tracker = TrackerServer::with_difficulty(address.to_string(), 0);
    let pin = tracker.identity_pin();
    let tracker_task = tokio::spawn(async move { tracker.run_listener(listener).await.unwrap() });
    let token = "a".repeat(64);
    let token_path =
        std::env::temp_dir().join(format!("ag-reverse-token-{:032x}", rand::random::<u128>()));
    storage::atomic_write(&token_path, token.as_bytes()).unwrap();
    let config = GuardConfig {
        tracker_identity_pin: Some(pin),
        reverse_token_file: Some(token_path.clone()),
        pow_difficulty: 0,
        allow_open_socks5: true,
        allow_private_exit: true,
        ..Default::default()
    };
    let gateway = GatewayServer::new(
        config,
        ProxyPool::new(),
        KillSwitchController::new(),
        Arc::new(SigningKey::generate(&mut rand::rngs::OsRng)),
    );
    let endpoint = address.to_string();
    let relay_task = tokio::spawn(async move {
        gateway
            .run_reverse_relay(&endpoint, "ownednode")
            .await
            .unwrap()
    });
    // The real pooled client must produce three distinct accepted PoW nonces.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut query = link::connect_tracker(TcpStream::connect(address).await.unwrap(), pin)
                .await
                .unwrap();
            anonguard::mesh::tracker::write_control(&mut query, "NODES")
                .await
                .unwrap();
            if anonguard::mesh::tracker::read_control(&mut query)
                .await
                .unwrap()
                == "ownednode"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        for _ in 0..4 {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            socket.write_all(b"pong").await.unwrap();
        }
    });
    // Four visits consume the initial pool and require successful replenishment.
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(350)).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = link::connect_tracker(TcpStream::connect(address).await.unwrap(), pin)
                .await
                .unwrap();
            anonguard::mesh::tracker::write_control(
                &mut stream,
                &format!("CONNECT_REVERSE ownednode {token}"),
            )
            .await
            .unwrap();
            assert_eq!(
                anonguard::mesh::tracker::read_control(&mut stream)
                    .await
                    .unwrap(),
                "OK"
            );
            let mut stream = socks5_connect_through(stream, "127.0.0.1", port, true)
                .await
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            stream.flush().await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"pong");
            stream.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }
    echo.await.unwrap();
    relay_task.abort();
    tracker_task.abort();
    let _ = relay_task.await;
    let _ = tracker_task.await;
    std::fs::remove_file(token_path).unwrap();
}
