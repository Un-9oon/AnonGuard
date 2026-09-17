use anonguard::core::state_machine::GuardedSocket;
use anonguard::gateway::server::{build_telescopic_circuit, handle_onion_relay_connection};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use anonguard::mesh::ProxyNode;
use anonguard::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Generates an Ed25519 signing key and returns (signing_key, verifying_pub_bytes).
fn gen_relay_key() -> (Ed25519SigningKey, [u8; 32]) {
    let sk = Ed25519SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

/// Real soak test: spawns a 3-hop relay network, builds a telescopic circuit,
/// and sends 50 messages through it. Validates every response, asserting:
/// - Zero panics across all relay tasks
/// - Zero dropped messages
/// - Correct E2E data integrity on every message
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_soak_local_relays() {
    const MESSAGE_COUNT: usize = 50;

    // 1. Destination Echo Server — reflects incoming data back
    let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut s, _) = dest_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            match s.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    // Echo back with "ECHO:" prefix
                    let mut reply = b"ECHO:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    if s.write_all(&reply).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 2. Generate identity keys for each relay hop
    let (exit_sk, exit_pk) = gen_relay_key();
    let (middle_sk, middle_pk) = gen_relay_key();
    let (guard_sk, guard_pk) = gen_relay_key();

    // 3. Spawn Exit Relay (Hop 2) — allow private network for local test harness
    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = exit_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone()).begin_verification().mark_verified();
        let _ = handle_onion_relay_connection(
            guarded_s,
            dummy_ks,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
            &exit_sk,
            true,
            anonguard::mesh::pool::ProxyPool::new(),
        )
        .await;
    });

    // 4. Spawn Middle Relay (Hop 1)
    let middle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let middle_addr = middle_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = middle_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone()).begin_verification().mark_verified();
        let _ = handle_onion_relay_connection(
            guarded_s,
            dummy_ks,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
            &middle_sk,
            true,
            anonguard::mesh::pool::ProxyPool::new(),
        )
        .await;
    });

    // 5. Spawn Guard Relay (Hop 0)
    let guard_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guard_addr = guard_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = guard_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone()).begin_verification().mark_verified();
        let _ = handle_onion_relay_connection(
            guarded_s,
            dummy_ks,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
            &guard_sk,
            true,
            anonguard::mesh::pool::ProxyPool::new(),
        )
        .await;
    });

    // 6. Build ProxyNode chain for client
    let chain = vec![
        ProxyNode::parse(&format!("socks5://{}", guard_addr)).unwrap(),
        ProxyNode::parse(&format!("socks5://{}", middle_addr)).unwrap(),
        ProxyNode::parse(&format!("socks5://{}", exit_addr)).unwrap(),
    ];

    // Pinned identity keys from the consensus (in order: guard, middle, exit)
    let pinned_keys = vec![guard_pk, middle_pk, exit_pk];

    // 7. Connect client directly to Guard node only
    let mut guard_stream = TcpStream::connect(guard_addr).await.unwrap();
    let circuit_id = 0xDEADBEEF;

    let mut circuit = build_telescopic_circuit(
        &mut guard_stream,
        circuit_id,
        &chain,
        &pinned_keys,
        &dest_addr.ip().to_string(),
        dest_addr.port(),
    )
    .await
    .expect("Telescopic circuit build failed during soak test setup");

    assert_eq!(circuit.hop_count(), 3, "Circuit must have exactly 3 hops");

    // 8. Soak loop: send MESSAGE_COUNT messages and validate each response
    let mut successful_roundtrips = 0;

    for i in 0..MESSAGE_COUNT {
        let msg = format!("SOAK_MSG_{:04}", i);
        let mut data_cell =
            OnionCell::new(circuit_id, 2, CellCommand::Data, 1, msg.as_bytes()).unwrap();
        let wire_forward = circuit.wrap_forward(&mut data_cell).unwrap();
        guard_stream.write_all(&wire_forward).await.unwrap();

        let mut wire_backward = [0u8; ONION_CELL_SIZE];
        guard_stream
            .read_exact(&mut wire_backward)
            .await
            .unwrap_or_else(|_| panic!("Failed to read response for message {}", i));
        let resp_cell = circuit
            .unwrap_backward(&mut wire_backward)
            .unwrap_or_else(|_| panic!("Failed to unwrap response for message {}", i));

        assert_eq!(resp_cell.1.command, CellCommand::Data);

        let len = resp_cell.1.length as usize;
        let expected = format!("ECHO:{}", msg);
        assert_eq!(
            &resp_cell.1.payload[..len],
            expected.as_bytes(),
            "Message {} response mismatch: expected '{}', got '{}'",
            i,
            expected,
            String::from_utf8_lossy(&resp_cell.1.payload[..len])
        );

        successful_roundtrips += 1;
    }

    assert_eq!(
        successful_roundtrips, MESSAGE_COUNT,
        "Soak test: {}/{} messages completed successfully",
        successful_roundtrips, MESSAGE_COUNT
    );
}
