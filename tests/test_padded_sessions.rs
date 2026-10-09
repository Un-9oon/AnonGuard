use anonguard::{
    core::state_machine::GuardedSocket,
    gateway::server::{
        handle_onion_relay_connection, negotiate_padded_session, negotiate_telescopic_hops,
    },
    mesh::{ProxyNode, ProxyPool},
    onion::session::{start_client, Profile},
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn one_authenticated_circuit_multiplexes_independent_half_closed_streams() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let mut destinations = Vec::new();
        let mut echoes = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            destinations.push(listener.local_addr().unwrap());
            echoes.push(tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut input = Vec::new();
                socket.read_to_end(&mut input).await.unwrap();
                socket.write_all(&input).await.unwrap();
            }));
        }
        let mut chain = Vec::new();
        let mut pins = Vec::new();
        let mut relays = Vec::new();
        for _ in 0..3 {
            let key = SigningKey::generate(&mut OsRng);
            pins.push(key.verifying_key().to_bytes());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            chain.push(
                ProxyNode::parse(&format!("socks5://{}", listener.local_addr().unwrap())).unwrap(),
            );
            relays.push(tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let stop = Arc::new(AtomicBool::new(false));
                let socket = GuardedSocket::new(socket, stop.clone())
                    .begin_verification()
                    .mark_verified();
                handle_onion_relay_connection(
                    socket,
                    stop,
                    None,
                    Some(anonguard::kernel::ExitPolicy::new(true)),
                    &key,
                    true,
                    ProxyPool::new(),
                )
                .await
            }));
        }
        let socket = TcpStream::connect((chain[0].host.as_str(), chain[0].port))
            .await
            .unwrap();
        let mut socket = anonguard::onion::link::connect(socket, pins[0])
            .await
            .unwrap();
        let mut circuit = negotiate_telescopic_hops(&mut socket, 47, &chain, &pins)
            .await
            .unwrap();
        negotiate_padded_session(&mut socket, &mut circuit, Profile::Strict)
            .await
            .unwrap();
        let socket = GuardedSocket::new(socket, Arc::new(AtomicBool::new(false)))
            .begin_verification()
            .mark_verified();
        let (handle, session) = start_client(socket, circuit, Profile::Strict);
        assert!(handle.open("127.0.0.1".into(), 22).await.is_err());
        assert!(handle.open("x".repeat(256), 443).await.is_err());
        assert!(
            !handle.is_closed(),
            "Refused/malformed destination must not kill other streams"
        );
        let mut jobs = Vec::new();
        for (index, address) in destinations.into_iter().enumerate() {
            let handle = handle.clone();
            jobs.push(tokio::spawn(async move {
                let mut socket = handle
                    .open("127.0.0.1".into(), address.port())
                    .await
                    .unwrap();
                let message = vec![index as u8 + 1; if index == 0 { 128 * 1024 } else { 100 }];
                socket.write_all(&message).await.unwrap();
                socket.shutdown().await.unwrap();
                let mut response = Vec::new();
                socket.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, message);
            }));
        }
        for job in jobs {
            job.await.unwrap();
        }
        for echo in echoes {
            echo.await.unwrap();
        }
        assert!(
            !handle.is_closed(),
            "An individual stream must not close its shared session"
        );
        session.abort();
        let _ = session.await;
        for relay in relays {
            relay.abort();
            let _ = relay.await;
        }
    })
    .await
    .expect("Session/flow-control deadline");
}

#[test]
fn profiles_reject_ambiguous_or_unbounded_negotiation() {
    for profile in [
        Profile::Balanced,
        Profile::Strict,
        Profile::Rmt,
        Profile::Poisson,
    ] {
        assert_eq!(Profile::decode(&profile.encode()).unwrap(), profile);
    }
    for payload in [
        &[][..],
        &[1][..],
        &[0, 1][..],
        &[1, 0][..],
        &[1, 5][..],
        &[1, 1, 0][..],
    ] {
        assert!(Profile::decode(payload).is_err());
    }
}

#[tokio::test]
async fn authenticated_exit_cannot_downgrade_the_requested_profile() {
    use anonguard::onion::{
        cell::{CellCommand, OnionCell, ONION_CELL_SIZE},
        circuit::{perform_client_relay_handshake, OnionCircuit, RelayCircuitHop},
    };
    for payload in [&[1, 1][..], &[1, 2, 0][..]] {
        let (client_keys, relay_keys) = perform_client_relay_handshake().unwrap();
        let mut circuit = OnionCircuit::new(89);
        circuit.add_hop(client_keys).unwrap();
        let mut hop = RelayCircuitHop::new(89, relay_keys, 0);
        let (mut client, mut server) = tokio::io::duplex(8192);
        let payload = payload.to_vec();
        let peer = tokio::spawn(async move {
            let mut wire = [0; ONION_CELL_SIZE];
            server.read_exact(&mut wire).await.unwrap();
            hop.peel_forward(&mut wire).unwrap();
            let request = OnionCell::parse(&wire).unwrap();
            assert_eq!(request.command, CellCommand::Session);
            let response =
                OnionCell::new(89, 0, CellCommand::SessionAccepted, 0, &payload).unwrap();
            let mut wire = response.serialize();
            hop.wrap_backward_originate(&mut wire).unwrap();
            server.write_all(&wire).await.unwrap();
        });
        assert!(
            negotiate_padded_session(&mut client, &mut circuit, Profile::Strict)
                .await
                .is_err()
        );
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn local_context_labels_are_length_framed_and_optional() {
    async fn label(username: &[u8], password: &[u8]) -> [u8; 32] {
        let (mut local, mut server) = tokio::io::duplex(1024);
        let job = tokio::spawn(async move {
            anonguard::gateway::chain::read_socks5_request_context(&mut server, true)
                .await
                .unwrap()
        });
        local.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut reply = [0; 2];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);
        local.write_all(&[1, username.len() as u8]).await.unwrap();
        local.write_all(username).await.unwrap();
        local.write_all(&[password.len() as u8]).await.unwrap();
        local.write_all(password).await.unwrap();
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);
        local
            .write_all(&[5, 1, 0, 1, 8, 8, 8, 8, 1, 187])
            .await
            .unwrap();
        let (host, port, context) = job.await.unwrap();
        assert_eq!((host.as_str(), port), ("8.8.8.8", 443));
        context.unwrap()
    }
    assert_eq!(label(b"ab", b"c").await, label(b"ab", b"c").await);
    assert_ne!(label(b"ab", b"c").await, label(b"a", b"bc").await);
}
