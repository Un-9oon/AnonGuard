use anonguard::{
    mesh::tracker::{read_control, write_control, TrackerServer},
    onion::link,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
fn node_key(label: &str) -> anonguard::crypto::identity::SigningKey {
    use sha2::{Digest, Sha256};
    anonguard::crypto::identity::SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
}
fn node_id(label: &str) -> String {
    hex::encode(node_key(label).verifying_key().to_bytes())
}
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
    let identity = node_key(node);
    register_key(address, pin, &identity, token, nonce).await
}
async fn register_key(
    address: std::net::SocketAddr,
    pin: [u8; 32],
    identity: &anonguard::crypto::identity::SigningKey,
    token: &str,
    nonce: u64,
) -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    let mut stream = connect(address, pin).await;
    let response = anonguard::mesh::tracker::register_reverse(
        &mut stream,
        identity,
        token,
        anonguard::mesh::sybil::current_timestamp_secs(),
        nonce,
    )
    .await
    .unwrap();
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
    write_control(
        &mut client,
        &format!("CONNECT_REVERSE {} {token}", node_id("node")),
    )
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
    // Fixture key generation is not part of the waiting-slot lifetime contract.
    // Prepare it before opening the first of 128 short-lived registrations.
    let identities: Vec<_> = (0..128)
        .map(|index| node_key(&format!("node{index:0124}")))
        .collect();
    let (address, pin, task) = setup().await;
    let token = "a".repeat(64);
    let mut streams = Vec::new();
    for identity in &identities {
        let (stream, reply) = register_key(address, pin, identity, &token, 0).await;
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
        &format!(
            "CONNECT_REVERSE {} {token}",
            node_id(&format!("node{:0124}", 127))
        ),
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

#[tokio::test]
async fn stalled_handshakes_are_bounded_and_release_admission() {
    use anonguard::mesh::tracker::MAX_TRACKER_HANDSHAKES_PER_SOURCE;
    use std::time::Duration;
    let (address, pin, task) = setup().await;
    let mut stalled = Vec::new();
    for _ in 0..MAX_TRACKER_HANDSHAKES_PER_SOURCE {
        stalled.push(TcpStream::connect(address).await.unwrap());
    }
    // A command-level response is impossible: these sockets never send TLS.
    // Let the listener admit the bounded prefix before probing the next socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut excess = TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(2), excess.read(&mut byte))
        .await
        .expect("Excess handshake was queued rather than refused");
    assert!(closed.is_err() || closed.unwrap() == 0);
    // Another loopback source must still complete authenticated TLS while the
    // first source has exhausted its source-group slots.
    let alternate = tokio::net::TcpSocket::new_v4().unwrap();
    alternate.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let other = alternate.connect(address).await.unwrap();
    let protected = tokio::time::timeout(Duration::from_secs(3), link::connect_tracker(other, pin))
        .await
        .unwrap()
        .unwrap();
    drop(protected);
    drop(stalled);
    // Failed TLS handshakes must return both admission permits.
    let recovered = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let stream = TcpStream::connect(address).await.unwrap();
            if let Ok(stream) = link::connect_tracker(stream, pin).await {
                break stream;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Handshake permits leaked after peer EOF");
    drop(recovered);
    task.abort();
}

#[tokio::test]
async fn registration_ownership_rejects_impersonation_tampering_and_replay() {
    let (address, pin, task) = setup().await;
    let owner = node_key("victim");
    let attacker = node_key("attacker");
    let node = node_id("victim");
    let token = "a".repeat(64);
    let now = anonguard::mesh::sybil::current_timestamp_secs();
    let command = format!("REGISTER_REVERSE {node} {token} {now} 17");
    let mut prior_proof = String::new();
    for attack in 0..7 {
        let mut stream = connect(address, pin).await;
        write_control(&mut stream, &command).await.unwrap();
        let response = read_control(&mut stream).await.unwrap();
        let mut challenge = hex::decode(response.strip_prefix("AUTH_CHALLENGE ").unwrap()).unwrap();
        let mut exporter = [0; 32];
        stream
            .get_ref()
            .1
            .export_keying_material(
                &mut exporter,
                b"AnonGuard-tracker-registration-v2",
                Some(&challenge),
            )
            .unwrap();
        if attack == 1 {
            challenge[0] ^= 1;
        }
        let signed_command = if attack == 2 {
            command.replace(&token, &"b".repeat(64))
        } else {
            command.clone()
        };
        let mut message = b"AnonGuard-tracker-registration-v2\0".to_vec();
        message.extend_from_slice(&(signed_command.len() as u32).to_be_bytes());
        message.extend_from_slice(signed_command.as_bytes());
        message.extend_from_slice(&challenge);
        message.extend_from_slice(&exporter);
        let mut proof = if attack == 0 {
            attacker.sign(&message)
        } else {
            owner.sign(&message)
        }
        .to_bytes();
        if attack == 3 {
            prior_proof = hex::encode(&proof);
            // Leave this correctly signed proof unused, to replay on a different TLS channel.
            drop(stream);
            continue;
        }
        if attack == 5 {
            proof[anonguard::crypto::hybrid_identity::PUBLIC_KEY_SIZE + 8] ^= 1;
        }
        if attack == 6 {
            *proof.last_mut().unwrap() ^= 1;
        }
        let encoded = if attack == 4 {
            prior_proof.clone()
        } else {
            hex::encode(proof)
        };
        write_control(&mut stream, &encoded).await.unwrap();
        assert_eq!(
            read_control(&mut stream).await.unwrap(),
            "ERROR_UNAUTHORIZED",
            "attack {attack}"
        );
    }
    // A failed impersonation must not consume the legitimate owner's PoW nonce
    // or create a first-claim capability entry.
    let (mut registered, response) = register(address, pin, "victim", &token, 17).await;
    assert_eq!(response, "REGISTERED");
    let mut consumer = connect(address, pin).await;
    write_control(&mut consumer, &format!("CONNECT_REVERSE {node} {token}"))
        .await
        .unwrap();
    assert_eq!(read_control(&mut registered).await.unwrap(), "READY");
    assert_eq!(read_control(&mut consumer).await.unwrap(), "OK");
    task.abort();
}
