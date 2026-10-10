use anonguard::crypto::identity::SigningKey;
use anonguard::{
    core::state_machine::GuardedSocket,
    gateway::server::{build_telescopic_circuit, handle_onion_relay_connection},
    mesh::{ProxyNode, ProxyPool},
    morphing::{JitterEngine, RmtEnsemble, RmtTimingEngine},
    onion::{
        cell::{CellCommand, OnionCell, ONION_CELL_SIZE},
        circuit::MAX_HOPS,
    },
};
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
async fn variable_depth_authenticated_roundtrips() {
    for (depth, streaming) in [
        (3, false),
        (4, false),
        (MAX_HOPS, false),
        (3, true),
        (MAX_HOPS, true),
    ] {
        tokio::time::timeout(Duration::from_secs(30), async {
            let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = destination.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut socket, _) = destination.accept().await.unwrap();
                let mut bytes = [0; 17];
                socket.read_exact(&mut bytes).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
            });
            let mut chain = Vec::new();
            let mut pins = Vec::new();
            let mut workers = Vec::new();
            for _index in 0..depth {
                let key = SigningKey::generate(&mut OsRng);
                pins.push(key.verifying_key().to_bytes());
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                chain.push(
                    ProxyNode::parse(&format!("socks5://{}", listener.local_addr().unwrap()))
                        .unwrap(),
                );
                workers.push(tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let stop = Arc::new(AtomicBool::new(false));
                    let socket = GuardedSocket::new(socket, stop.clone())
                        .begin_verification()
                        .mark_verified();
                    let jitter = Some(JitterEngine::Rmt(RmtTimingEngine::new(
                        RmtEnsemble::GUE,
                        1.5,
                        1024,
                    )));
                    handle_onion_relay_connection(
                        socket,
                        stop,
                        jitter,
                        Some(anonguard::kernel::ExitPolicy::new(true)),
                        &key,
                        true, // Lab-only: permit loopback EXTEND without a directory fixture.
                        ProxyPool::new(),
                    )
                    .await
                }));
            }
            let raw = TcpStream::connect((chain[0].host.as_str(), chain[0].port))
                .await
                .unwrap();
            let mut stream = anonguard::onion::link::connect(raw, pins[0]).await.unwrap();
            let mut circuit = build_telescopic_circuit(
                &mut stream,
                71,
                &chain,
                &pins,
                "127.0.0.1",
                target.port(),
            )
            .await
            .unwrap();
            assert_eq!(circuit.hop_count(), depth);
            let message = b"multihop verified";
            if streaming {
                // Exercise the actual client RMT cell scheduler and upload half-close.
                let (mut application, local) = tokio::io::duplex(4096);
                let stop = Arc::new(AtomicBool::new(false));
                let mut local = GuardedSocket::new(local, stop.clone())
                    .begin_verification()
                    .mark_verified();
                let mut upstream = GuardedSocket::new(stream, stop)
                    .begin_verification()
                    .mark_verified();
                let transfer = tokio::spawn(async move {
                    anonguard::gateway::server::stream_onion_circuit(
                        &mut local,
                        &mut upstream,
                        circuit,
                        Some(JitterEngine::Rmt(RmtTimingEngine::new(
                            RmtEnsemble::GOE,
                            20.0,
                            1024,
                        ))),
                    )
                    .await
                });
                application.write_all(message).await.unwrap();
                application.shutdown().await.unwrap();
                let mut response = Vec::new();
                application.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, message);
                transfer
                    .await
                    .unwrap()
                    .unwrap_or_else(|error| panic!("streaming depth {depth}: {error}"));
            } else {
                let mut cell = OnionCell::new(71, 0, CellCommand::Data, 1, message).unwrap();
                stream
                    .write_all(&circuit.wrap_forward(&mut cell).unwrap())
                    .await
                    .unwrap();
                loop {
                    let mut wire = [0; ONION_CELL_SIZE];
                    stream.read_exact(&mut wire).await.unwrap();
                    let (origin, response) = circuit.unwrap_backward(&mut wire).unwrap();
                    assert_eq!(origin, depth - 1);
                    if response.command == CellCommand::Data {
                        assert_eq!(&response.payload[..response.length as usize], message);
                        break;
                    }
                }
                drop(stream);
            }
            echo.await.unwrap();
            for worker in workers {
                worker.abort();
                let _ = worker.await;
            }
        })
        .await
        .expect("multi-hop deadline");
    }
}

#[test]
fn experimental_rmt_intervals_are_bounded_and_nonconstant() {
    for ensemble in [RmtEnsemble::GOE, RmtEnsemble::GUE] {
        let engine = JitterEngine::Rmt(RmtTimingEngine::new(ensemble, 20.0, 1024));
        let values: Vec<_> = (0..256).map(|_| engine.onion_interval()).collect();
        assert!(values
            .iter()
            .all(|value| (Duration::from_millis(5)..=Duration::from_millis(100)).contains(value)));
        assert!(values.windows(2).any(|pair| pair[0] != pair[1]));
    }
}

#[tokio::test]
async fn excess_depth_and_missing_pins_refuse_before_io() {
    let (mut stream, _) = tokio::io::duplex(2048);
    let node = ProxyNode::parse("socks5://8.8.8.8:9443").unwrap();
    for depth in [2, MAX_HOPS + 1] {
        assert!(build_telescopic_circuit(
            &mut stream,
            1,
            &vec![node.clone(); depth],
            &vec![[1; 32]; depth],
            "example.com",
            443
        )
        .await
        .is_err());
    }
    assert!(
        build_telescopic_circuit(&mut stream, 1, &vec![node; 3], &[], "example.com", 443)
            .await
            .is_err()
    );
}

async fn certified_pool(non_exits: usize, exits: usize, same_middle_prefix: bool) -> ProxyPool {
    use anonguard::mesh::consensus::{ConsensusDocument, RelayDescriptor};
    let authority = SigningKey::from_bytes(&[201; 32]);
    let now = anonguard::mesh::sybil::current_timestamp_secs();
    let relays = (0..non_exits + exits)
        .map(|index| {
            let key = SigningKey::from_bytes(&[index as u8 + 1; 32]);
            let prefix = if same_middle_prefix && index < non_exits {
                11
            } else {
                index + 11
            };
            let mut relay = RelayDescriptor::new(
                format!("relay-{index}"),
                format!("{prefix}.1.0.{}", index + 1),
                9443,
                [0; 32],
                [0; 32],
                index >= non_exits,
                0,
                now,
            );
            relay.sign_with_key(&key);
            relay
        })
        .collect();
    let mut doc = ConsensusDocument::new(now - 1, now + 600, relays);
    doc.sign_with_authority("authority", &authority);
    let pool = ProxyPool::new();
    pool.load_from_multi_consensus(
        &[doc],
        &std::collections::HashMap::from([("authority".into(), authority.verifying_key())]),
        1,
        now,
    )
    .await
    .unwrap();
    pool
}

#[tokio::test]
async fn randomized_paths_preserve_guard_roles_uniqueness_and_capacity() {
    let pool = certified_pool(8, 2, false).await;
    let mut guard = None;
    let mut lengths = std::collections::HashSet::new();
    for _ in 0..64 {
        let path = pool.get_diverse_onion_chain(3, 8, true).await;
        assert!((3..=8).contains(&path.len()));
        assert!(path.last().unwrap().is_exit);
        assert!(path[..path.len() - 1].iter().all(|hop| !hop.is_exit));
        let endpoints: std::collections::HashSet<_> =
            path.iter().map(|hop| (&hop.host, hop.port)).collect();
        assert_eq!(endpoints.len(), path.len());
        let entry = path[0].host.clone();
        if let Some(previous) = &guard {
            assert_eq!(previous, &entry);
        } else {
            guard = Some(entry);
        }
        lengths.insert(path.len());
    }
    assert!(lengths.len() > 1);
    assert!(pool.get_diverse_onion_chain(3, 9, true).await.is_empty());
    let small = certified_pool(2, 6, false).await;
    for _ in 0..10 {
        assert_eq!(small.get_diverse_onion_chain(3, 8, true).await.len(), 3);
    }
    let colliding = certified_pool(4, 2, true).await;
    assert!(colliding
        .get_diverse_onion_chain(3, 8, true)
        .await
        .is_empty());
}

#[tokio::test]
async fn private_bridge_paths_use_variable_certified_downstream_hops() {
    let pool = certified_pool(8, 2, false).await;
    let binding = anonguard::onion::transport::BridgeTransport {
        identity: SigningKey::from_bytes(&[101; 32])
            .verifying_key()
            .to_bytes(),
        proxy: "127.0.0.1:31000".parse().unwrap(),
        bridge: "9.9.9.9:443".parse().unwrap(),
        arguments: std::collections::BTreeMap::from([("cert".into(), "fixture".into())]),
    };
    for _ in 0..16 {
        let path = pool
            .get_private_bridge_chain_with_bounds(std::slice::from_ref(&binding), true, 3, 8)
            .await;
        assert!((3..=8).contains(&path.len()));
        assert_eq!(path[0].host, "9.9.9.9");
        assert!(path.last().unwrap().is_exit);
        assert!(path[1..path.len() - 1].iter().all(|hop| !hop.is_exit));
        let pins = pool.get_identity_keys(&path).await;
        assert!(pins[1..].iter().all(|pin| *pin != [0; 32]));
    }
    let mut changed = binding.clone();
    changed.identity = SigningKey::from_bytes(&[102; 32])
        .verifying_key()
        .to_bytes();
    assert!(pool
        .get_private_bridge_chain_with_bounds(&[changed], true, 3, 8)
        .await
        .is_empty());
}

#[test]
fn cli_rejects_unsafe_or_inverted_hop_bounds() {
    for (minimum, maximum, expected) in [
        ("2", "8", "invalid value"),
        ("3", "9", "invalid value"),
        ("5", "3", "must not exceed"),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"))
            .args([
                "--onion",
                "--proxy",
                "socks5://1.1.1.1:9050",
                "--min-hops",
                minimum,
                "--max-hops",
                maximum,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}
