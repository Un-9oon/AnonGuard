use anonguard::gateway::server::{build_telescopic_circuit, handle_onion_relay_connection};
use anonguard::mesh::ProxyNode;
use anonguard::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

    // 2. Spawn Hop 2 (Exit) - allow private network for local test harness
    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = exit_listener.accept().await.unwrap();
        let _ = handle_onion_relay_connection(
            s,
            None,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
        )
        .await;
    });

    // 3. Spawn Hop 1 (Middle)
    let middle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let middle_addr = middle_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = middle_listener.accept().await.unwrap();
        let _ = handle_onion_relay_connection(
            s,
            None,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
        )
        .await;
    });

    // 4. Spawn Hop 0 (Guard)
    let guard_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guard_addr = guard_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = guard_listener.accept().await.unwrap();
        let _ = handle_onion_relay_connection(
            s,
            None,
            None,
            Some(anonguard::kernel::ExitPolicy::new(true)),
        )
        .await;
    });

    // 5. Build ProxyNode chain for client
    let chain = vec![
        ProxyNode::parse(&format!("socks5://{}", guard_addr)).unwrap(),
        ProxyNode::parse(&format!("socks5://{}", middle_addr)).unwrap(),
        ProxyNode::parse(&format!("socks5://{}", exit_addr)).unwrap(),
    ];

    // 6. Connect client directly to Guard node only
    let mut guard_stream = TcpStream::connect(guard_addr).await.unwrap();
    let circuit_id = 0x1a2b3c4d;

    let (mut circuit, exit_mac) = build_telescopic_circuit(
        &mut guard_stream,
        circuit_id,
        &chain,
        &dest_addr.ip().to_string(),
        dest_addr.port(),
    )
    .await
    .expect("Telescopic circuit build and exit relay connection failed");

    assert_eq!(circuit.hop_count(), 3);

    // 7. Client sends encrypted Data cell through the 3-hop circuit
    let req_data = b"GET /onion-test HTTP/1.1\r\n\r\n";
    let data_cell =
        OnionCell::new(circuit_id, 2, CellCommand::Data, 1, req_data, &exit_mac).unwrap();
    let wire_forward = circuit.wrap_forward(&data_cell);
    guard_stream.write_all(&wire_forward).await.unwrap();

    // 8. Client reads response cell from the circuit
    let mut wire_backward = [0u8; ONION_CELL_SIZE];
    guard_stream.read_exact(&mut wire_backward).await.unwrap();
    let resp_cell = circuit.unwrap_backward(&mut wire_backward).unwrap();

    assert!(resp_cell.is_mac_valid(&exit_mac));
    assert_eq!(resp_cell.command, CellCommand::Data);
    let len = resp_cell.length as usize;
    assert_eq!(
        &resp_cell.payload[..len],
        b"HTTP/1.1 200 OK\r\n\r\nONION_E2E_VERIFIED"
    );
}

#[tokio::test]
async fn test_exit_policy_blocks_ssrf_live() {
    // Exit node spawned with default ExitPolicy (blocking loopback/private/metadata)
    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = exit_listener.accept().await.unwrap();
        let _ = handle_onion_relay_connection(
            s,
            None,
            None,
            Some(anonguard::kernel::ExitPolicy::default()),
        )
        .await;
    });

    let chain = vec![ProxyNode::parse(&format!("socks5://{}", exit_addr)).unwrap()];
    let mut guard_stream = TcpStream::connect(exit_addr).await.unwrap();
    let circuit_id = 0x99887766;

    // Attempting to bridge to loopback (127.0.0.1) must be rejected by default exit policy
    let res =
        build_telescopic_circuit(&mut guard_stream, circuit_id, &chain, "127.0.0.1", 8080).await;
    assert!(
        res.is_err(),
        "Exit node should reject connecting to 127.0.0.1 under default exit policy"
    );
}

#[tokio::test]
async fn test_exit_policy_blocks_dns_rebinding_hostname_live() {
    // Exit node spawned with default ExitPolicy (blocking loopback/private/metadata)
    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = exit_listener.accept().await.unwrap();
        let _ = handle_onion_relay_connection(
            s,
            None,
            None,
            Some(anonguard::kernel::ExitPolicy::default()),
        )
        .await;
    });

    let chain = vec![ProxyNode::parse(&format!("socks5://{}", exit_addr)).unwrap()];
    let mut guard_stream = TcpStream::connect(exit_addr).await.unwrap();
    let circuit_id = 0x88776655;

    // Attempting to bridge to "127.0.0.1.nip.io" (a hostname NOT on the string blocklist
    // that resolves via DNS to 127.0.0.1) must pass string validation but get detected
    // and rejected by resolve_and_connect's resolved-IP inspection.
    let res = build_telescopic_circuit(
        &mut guard_stream,
        circuit_id,
        &chain,
        "127.0.0.1.nip.io",
        8080,
    )
    .await;
    assert!(
        res.is_err(),
        "Exit node should reject connecting to '127.0.0.1.nip.io' resolving to 127.0.0.1 under default exit policy"
    );
}
