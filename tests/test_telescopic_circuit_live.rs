use anonguard::core::state_machine::GuardedSocket;
use anonguard::gateway::server::{build_telescopic_circuit, handle_onion_relay_connection};
use anonguard::mesh::ProxyNode;
use anonguard::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::rngs::OsRng;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Generates an Ed25519 signing key and returns (signing_key, verifying_pub_bytes).
fn gen_relay_key() -> (Ed25519SigningKey, [u8; 32]) {
    let sk = Ed25519SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

#[tokio::test]
async fn test_live_inband_telescopic_circuit_e2e() {
    // 1. Destination Echo Server
    let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut s, _) = dest_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"GET /onion-test HTTP/1.1\r\n\r\n");
        s.write_all(b"HTTP/1.1 200 OK\r\n\r\nONION_E2E_VERIFIED")
            .await
            .unwrap();
    });

    // 2. Generate identity keys for each relay hop
    let (exit_sk, exit_pk) = gen_relay_key();
    let (middle_sk, middle_pk) = gen_relay_key();
    let (guard_sk, guard_pk) = gen_relay_key();

    // 3. Spawn Hop 2 (Exit) - allow private network for local test harness
    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = exit_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone())
            .begin_verification()
            .mark_verified();
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

    // 4. Spawn Hop 1 (Middle)
    let middle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let middle_addr = middle_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = middle_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone())
            .begin_verification()
            .mark_verified();
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

    // 5. Spawn Hop 0 (Guard)
    let guard_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guard_addr = guard_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = guard_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone())
            .begin_verification()
            .mark_verified();
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
    let circuit_id = 0x1a2b3c4d;

    let mut circuit = build_telescopic_circuit(
        &mut guard_stream,
        circuit_id,
        &chain,
        &pinned_keys,
        &dest_addr.ip().to_string(),
        dest_addr.port(),
    )
    .await
    .expect("Telescopic circuit build and exit relay connection failed");

    assert_eq!(circuit.hop_count(), 3);

    // 8. Client sends encrypted Data cell through the 3-hop circuit
    let req_data = b"GET /onion-test HTTP/1.1\r\n\r\n";
    let mut data_cell = OnionCell::new(circuit_id, 2, CellCommand::Data, 1, req_data).unwrap();
    let wire_forward = circuit.wrap_forward(&mut data_cell).unwrap();
    guard_stream.write_all(&wire_forward).await.unwrap();

    // 9. Client reads response cell from the circuit
    let mut wire_backward = [0u8; ONION_CELL_SIZE];
    guard_stream.read_exact(&mut wire_backward).await.unwrap();
    let resp_cell = circuit.unwrap_backward(&mut wire_backward).unwrap();

    assert_eq!(resp_cell.1.command, CellCommand::Data);
    let len = resp_cell.1.length as usize;
    assert_eq!(
        &resp_cell.1.payload[..len],
        b"HTTP/1.1 200 OK\r\n\r\nONION_E2E_VERIFIED"
    );
}

#[tokio::test]
async fn test_exit_policy_blocks_ssrf_live() {
    let (exit_sk, exit_pk) = gen_relay_key();

    // Exit node spawned with default ExitPolicy (blocking loopback/private/metadata)
    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = exit_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone())
            .begin_verification()
            .mark_verified();
        let _ = handle_onion_relay_connection(
            guarded_s,
            dummy_ks,
            None,
            Some(anonguard::kernel::ExitPolicy::default()),
            &exit_sk,
            true,
            anonguard::mesh::pool::ProxyPool::new(),
        )
        .await;
    });

    let chain = vec![ProxyNode::parse(&format!("socks5://{}", exit_addr)).unwrap()];
    let pinned_keys = vec![exit_pk];
    let mut guard_stream = TcpStream::connect(exit_addr).await.unwrap();
    let circuit_id = 0x99887766;

    // Attempting to bridge to loopback (127.0.0.1) must be rejected by default exit policy
    let res = build_telescopic_circuit(
        &mut guard_stream,
        circuit_id,
        &chain,
        &pinned_keys,
        "127.0.0.1",
        8080,
    )
    .await;
    assert!(
        res.is_err(),
        "Exit node should reject connecting to 127.0.0.1 under default exit policy"
    );
}

#[tokio::test]
async fn test_exit_policy_blocks_dns_rebinding_hostname_live() {
    let (exit_sk, exit_pk) = gen_relay_key();

    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = exit_listener.accept().await.unwrap();
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone())
            .begin_verification()
            .mark_verified();
        let _ = handle_onion_relay_connection(
            guarded_s,
            dummy_ks,
            None,
            Some(anonguard::kernel::ExitPolicy::default()),
            &exit_sk,
            true,
            anonguard::mesh::pool::ProxyPool::new(),
        )
        .await;
    });

    let chain = vec![ProxyNode::parse(&format!("socks5://{}", exit_addr)).unwrap()];
    let pinned_keys = vec![exit_pk];
    let mut guard_stream = TcpStream::connect(exit_addr).await.unwrap();
    let circuit_id = 0x88776655;

    // Attempting to bridge to "127.0.0.1.nip.io" (a hostname NOT on the string blocklist
    // that resolves via DNS to 127.0.0.1) must pass string validation but get detected
    // and rejected by resolve_and_connect's resolved-IP inspection.
    let res = build_telescopic_circuit(
        &mut guard_stream,
        circuit_id,
        &chain,
        &pinned_keys,
        "127.0.0.1.nip.io",
        8080,
    )
    .await;
    assert!(
        res.is_err(),
        "Exit node should reject connecting to '127.0.0.1.nip.io' resolving to 127.0.0.1 under default exit policy"
    );
}

/// Security regression test: a rogue relay presenting the wrong identity key must be rejected.
/// This test simulates an active MITM: the relay uses `relay_sk` but we pin `wrong_pk`.
#[tokio::test]
async fn test_mitm_identity_key_mismatch_is_rejected() {
    let (relay_sk, _correct_pk) = gen_relay_key();
    let (_wrong_sk, wrong_pk) = gen_relay_key(); // Different key — MITM or misconfiguration

    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = relay_listener.accept().await.unwrap();
        // Relay signs with relay_sk (legitimate)
        let dummy_ks = Arc::new(AtomicBool::new(false));
        let guarded_s = GuardedSocket::new(s, dummy_ks.clone())
            .begin_verification()
            .mark_verified();
        let _ = handle_onion_relay_connection(
            guarded_s,
            dummy_ks,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
            &relay_sk,
            true,
            anonguard::mesh::pool::ProxyPool::new(),
        )
        .await;
    });

    let chain = vec![ProxyNode::parse(&format!("socks5://{}", relay_addr)).unwrap()];
    // Client pins wrong_pk — should detect the mismatch and reject
    let pinned_keys = vec![wrong_pk];
    let mut stream = TcpStream::connect(relay_addr).await.unwrap();

    let res = build_telescopic_circuit(
        &mut stream,
        0xdeadbeef,
        &chain,
        &pinned_keys,
        "example.com",
        80,
    )
    .await;

    let err_msg = match res {
        Err(e) => e.to_string(),
        Ok(_) => panic!(
            "Client must reject a relay whose identity key does not match the pinned consensus key"
        ),
    };
    assert!(
        err_msg.contains("identity key does not match") || err_msg.contains("MITM"),
        "Error message must indicate identity key mismatch, got: {err_msg}"
    );
}
