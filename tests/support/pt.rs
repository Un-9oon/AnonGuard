use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
};
pub async fn launch(
    binary: &Path,
    state: &Path,
    values: &[(&str, String)],
    prefix: &str,
) -> (Child, String) {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_STATE_LOCATION", state)
        .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (key, value) in values {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("launch real transport");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let method = tokio::time::timeout(Duration::from_secs(10), async {
        let mut found = None;
        let mut version = false;
        for _ in 0..64 {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("transport startup EOF");
            assert!(line.len() <= 4096, "oversized startup message");
            if line == "VERSION 1" {
                version = true;
            }
            if line.starts_with(prefix) {
                found = Some(line.clone());
            }
            assert!(!line.contains("ERROR"), "transport startup failed");
            if line == "CMETHODS DONE" || line == "SMETHODS DONE" {
                assert!(version, "transport did not negotiate v1");
                return found.expect("requested method unavailable");
            }
        }
        panic!("too many transport startup messages");
    })
    .await
    .expect("transport startup timeout");
    // Keep stdout drained during the fixture so diagnostics cannot block forwarding.
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    (child, method)
}

pub async fn server_binding(
    binary: &Path,
    state: &Path,
    backend: std::net::SocketAddr,
    identity: [u8; 32],
    proxy: std::net::SocketAddr,
) -> (Child, anonguard::onion::transport::BridgeTransport) {
    let reservation = tokio::net::TcpListener::bind((backend.ip(), 0))
        .await
        .unwrap();
    let bridge = reservation.local_addr().unwrap();
    drop(reservation);
    let (server, announcement) = launch(
        binary,
        state,
        &[
            ("TOR_PT_SERVER_TRANSPORTS", "obfs4".into()),
            ("TOR_PT_SERVER_BINDADDR", format!("obfs4-{bridge}")),
            ("TOR_PT_ORPORT", backend.to_string()),
        ],
        "SMETHOD obfs4 ",
    )
    .await;
    let mut arguments = std::collections::BTreeMap::new();
    for pair in announcement
        .split_whitespace()
        .find_map(|field| field.strip_prefix("ARGS:"))
        .unwrap()
        .split(',')
    {
        let (key, value) = pair.split_once('=').unwrap();
        arguments.insert(key.to_owned(), value.to_owned());
    }
    (
        server,
        anonguard::onion::transport::BridgeTransport {
            identity,
            proxy,
            bridge,
            arguments,
        },
    )
}
