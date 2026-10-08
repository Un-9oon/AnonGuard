#[path = "support/pt.rs"]
mod pt;
// Opt-in interoperability test against the actual obfs4 implementation.
use anonguard::onion::{link, transport};
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
#[ignore = "requires ANONGUARD_OBFS4PROXY pointing to a trusted real obfs4proxy binary"]
async fn real_obfs4_preserves_pinned_anonguard_tls() {
    let binary = std::fs::canonicalize(
        std::env::var("ANONGUARD_OBFS4PROXY").expect("provide transport binary"),
    )
    .unwrap();
    struct State(std::path::PathBuf);
    impl Drop for State {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let state = State(
        std::env::temp_dir().join(format!("anonguard-obfs4-{:032x}", rand::random::<u128>())),
    );
    std::fs::create_dir(&state.0).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let server_state = state.0.join("server");
    let client_state = state.0.join("client");
    std::fs::create_dir(&server_state).unwrap();
    std::fs::create_dir(&client_state).unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge = reservation.local_addr().unwrap();
    drop(reservation);
    let (mut server, announcement) = pt::launch(
        &binary,
        &server_state,
        &[
            ("TOR_PT_SERVER_TRANSPORTS", "obfs4".into()),
            ("TOR_PT_SERVER_BINDADDR", format!("obfs4-{bridge}")),
            ("TOR_PT_ORPORT", backend.local_addr().unwrap().to_string()),
        ],
        "SMETHOD obfs4 ",
    )
    .await;
    let fields: Vec<_> = announcement.split_whitespace().collect();
    assert_eq!(fields[2].parse::<std::net::SocketAddr>().unwrap(), bridge);
    let mut arguments = BTreeMap::new();
    for pair in fields
        .iter()
        .find_map(|field| field.strip_prefix("ARGS:"))
        .expect("obfs4 server arguments")
        .split(',')
    {
        let (key, value) = pair.split_once('=').unwrap();
        arguments.insert(key.to_owned(), value.to_owned());
    }
    let (mut client, method) = pt::launch(
        &binary,
        &client_state,
        &[("TOR_PT_CLIENT_TRANSPORTS", "obfs4".into())],
        "CMETHOD obfs4 ",
    )
    .await;
    let fields: Vec<_> = method.split_whitespace().collect();
    assert_eq!(fields[2], "socks5");
    let proxy = fields[3].parse().unwrap();
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pin = key.verifying_key().to_bytes();
    let acceptor = link::acceptor(&key).unwrap();
    let backend_task = tokio::spawn(async move {
        let (stream, _) = backend.accept().await.unwrap();
        let mut stream = link::accept(&acceptor, stream).await.unwrap();
        let mut request = [0; 18];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ANONGUARD-OBFS4-OK");
        stream.write_all(&request).await.unwrap();
    });
    let stream = transport::connect(proxy, bridge, &arguments).await.unwrap();
    let mut authenticated = link::connect(stream, pin).await.unwrap();
    authenticated
        .write_all(b"ANONGUARD-OBFS4-OK")
        .await
        .unwrap();
    let mut response = [0; 18];
    tokio::time::timeout(
        Duration::from_secs(10),
        authenticated.read_exact(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response, b"ANONGUARD-OBFS4-OK");
    backend_task.await.unwrap();
    client.kill().await.unwrap();
    server.kill().await.unwrap();
}
