use anonguard::{
    mesh::tracker::{read_control, write_control, TrackerServer},
    onion::link,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
async fn setup() -> (std::net::SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tracker = TrackerServer::with_difficulty(address.to_string(), 0);
    let pin = tracker.identity_pin();
    let task = tokio::spawn(async move { tracker.run_listener(listener).await.unwrap() });
    (address, pin, task)
}
async fn connect(
    address: std::net::SocketAddr,
    pin: [u8; 32],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    link::connect_tracker(TcpStream::connect(address).await.unwrap(), pin)
        .await
        .unwrap()
}
async fn register(
    address: std::net::SocketAddr,
    pin: [u8; 32],
    node: &str,
    token: &str,
    nonce: u64,
) -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    let mut stream = connect(address, pin).await;
    write_control(
        &mut stream,
        &format!(
            "REGISTER_REVERSE {node} {token} {} {nonce}",
            anonguard::mesh::sybil::current_timestamp_secs()
        ),
    )
    .await
    .unwrap();
    let response = read_control(&mut stream).await.unwrap();
    (stream, response)
}
#[tokio::test]
async fn pins_tokens_and_framing_are_required() {
    let (address, pin, task) = setup().await;
    assert!(
        link::connect_tracker(TcpStream::connect(address).await.unwrap(), [1; 32])
            .await
            .is_err()
    );
    assert!(
        link::connect(TcpStream::connect(address).await.unwrap(), pin)
            .await
            .is_err()
    );
    let mut stream = connect(address, pin).await;
    write_control(&mut stream, "REGISTER_REVERSE node 0 1")
        .await
        .unwrap();
    assert_eq!(
        read_control(&mut stream).await.unwrap(),
        "ERROR_INVALID_COMMAND"
    );
    let token = "a".repeat(64);
    let (_registered, reply) = register(address, pin, "node", &token, 1).await;
    assert_eq!(reply, "REGISTERED");
    let (_, reply) = register(address, pin, "node", &"b".repeat(64), 2).await;
    assert_eq!(reply, "ERROR_UNAUTHORIZED");
    write_control(&mut connect(address, pin).await, &"x".repeat(32769))
        .await
        .unwrap_err();
    task.abort();
}
#[tokio::test]
async fn closed_registrations_release_slots_and_tokens() {
    let (address, pin, task) = setup().await;
    let token = "a".repeat(64);
    for nonce in 0..12 {
        let (mut stream, reply) = register(address, pin, "node", &token, nonce).await;
        assert_eq!(reply, "REGISTERED");
        if nonce % 2 == 0 {
            stream.shutdown().await.unwrap();
        }
        drop(stream);
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    }
    let (_stream, reply) = register(address, pin, "node", &"b".repeat(64), 100).await;
    assert_eq!(reply, "REGISTERED");
    task.abort();
}
#[tokio::test]
async fn per_node_limit_preserves_handoff_and_bidirectional_data() {
    let (address, pin, task) = setup().await;
    let token = "a".repeat(64);
    let mut streams = Vec::new();
    for nonce in 0..3 {
        let (s, r) = register(address, pin, "node", &token, nonce).await;
        assert_eq!(r, "REGISTERED");
        streams.push(s);
    }
    let (_, r) = register(address, pin, "node", &token, 9).await;
    assert_eq!(r, "ERROR_BUSY");
    let mut client = connect(address, pin).await;
    write_control(&mut client, &format!("CONNECT_REVERSE node {token}"))
        .await
        .unwrap();
    let mut relay = streams.pop().unwrap();
    assert_eq!(read_control(&mut relay).await.unwrap(), "READY");
    assert_eq!(read_control(&mut client).await.unwrap(), "OK");
    client.write_all(b"request").await.unwrap();
    client.flush().await.unwrap();
    let mut bytes = [0; 7];
    relay.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"request");
    relay.write_all(b"reply").await.unwrap();
    relay.flush().await.unwrap();
    let mut bytes = [0; 5];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"reply");
    task.abort();
    let _ = task.await;
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut bytes))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
}
#[tokio::test]
async fn expired_registrations_release_slots() {
    let (address, pin, task) = setup().await;
    let (mut stream, reply) = register(address, pin, "expires", &"a".repeat(64), 1).await;
    assert_eq!(reply, "REGISTERED");
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    let mut byte = [0];
    let result = stream.read(&mut byte).await;
    assert!(result.is_err() || result.unwrap() == 0);
    tokio::time::resume();
    let (_stream, reply) = register(address, pin, "expires", &"b".repeat(64), 2).await;
    assert_eq!(reply, "REGISTERED");
    task.abort();
}
#[tokio::test]
async fn global_waiting_limit_reserves_capacity_for_consumers() {
    let (address, pin, task) = setup().await;
    let token = "a".repeat(64);
    let mut streams = Vec::new();
    for index in 0..128 {
        let (stream, reply) = register(address, pin, &format!("node{index:0124}"), &token, 0).await;
        assert_eq!(reply, "REGISTERED");
        streams.push(stream);
    }
    let (_, reply) = register(address, pin, "overflow", &token, 0).await;
    assert_eq!(reply, "ERROR_BUSY");
    let mut discovery = connect(address, pin).await;
    write_control(&mut discovery, "NODES").await.unwrap();
    let listing = read_control(&mut discovery).await.unwrap();
    assert_eq!(listing.lines().count(), 128);
    assert!(listing.len() > 4096);
    assert!(!listing.contains(&token));
    let mut client = connect(address, pin).await;
    write_control(
        &mut client,
        &format!("CONNECT_REVERSE node{:0124} {token}", 127),
    )
    .await
    .unwrap();
    let mut relay = streams.pop().unwrap();
    assert_eq!(read_control(&mut relay).await.unwrap(), "READY");
    assert_eq!(read_control(&mut client).await.unwrap(), "OK");
    task.abort();
}
#[tokio::test]
async fn malformed_wire_length_and_early_payload_are_refused() {
    let (address, pin, task) = setup().await;
    let mut stream = connect(address, pin).await;
    stream.write_u32(u32::MAX).await.unwrap();
    stream.flush().await.unwrap();
    let mut byte = [0];
    let result = stream.read(&mut byte).await;
    assert!(result.is_err() || result.unwrap() == 0);
    let (mut stream, reply) = register(address, pin, "early", &"a".repeat(64), 1).await;
    assert_eq!(reply, "REGISTERED");
    stream
        .write_all(b"unexpected tunnel payload")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let result = stream.read(&mut byte).await;
    assert!(result.is_err() || result.unwrap() == 0);
    let (_stream, reply) = register(address, pin, "early", &"b".repeat(64), 2).await;
    assert_eq!(reply, "REGISTERED");
    task.abort();
}
