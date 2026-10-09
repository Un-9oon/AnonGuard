use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

use anonguard::mesh::sybil::{current_timestamp_secs, solve_pow_bounded, verify_pow};
use anonguard::mesh::tracker::TrackerServer;

#[tokio::test]
async fn test_tracker_re_registration_auth() {
    let test_difficulty = 8;
    let port = 40999;
    let addr_str = format!("127.0.0.1:{}", port);
    let tracker = TrackerServer::with_difficulty(addr_str.clone(), test_difficulty);

    // Start tracker
    let tracker_arc = std::sync::Arc::new(tracker);
    let _tracker_clone = tracker_arc.clone();
    tokio::spawn(async move {
        tracker_arc.run().await.unwrap();
    });

    sleep(Duration::from_millis(100)).await;

    let node_id = "test-node-x";
    let token_t = "secret-token-t";
    let now = current_timestamp_secs();

    // Solve PoW for first registration
    let nonce1 = solve_pow_bounded(node_id, now, test_difficulty).unwrap();

    // (a) Register node X with token T
    let mut stream1 = TcpStream::connect(&addr_str).await.unwrap();
    let reg1 = format!(
        "REGISTER_REVERSE {} {} {} {}\n",
        node_id, token_t, now, nonce1
    );
    stream1.write_all(reg1.as_bytes()).await.unwrap();

    // Wait for registration to process
    sleep(Duration::from_millis(50)).await;

    // (b) Attempt to register node X again with a DIFFERENT token (and new PoW since nonces can't be replayed)
    let now2 = now;
    // The replay registry keys on (node_id, nonce), not timestamp. Solving
    // from zero at different timestamps can return the same nonce and test
    // replay refusal instead of token authentication. Use disjoint valid proofs.
    let nonce2 = ((nonce1 + 1)..10_000_000)
        .find(|nonce| verify_pow(node_id, now2, *nonce, test_difficulty, now))
        .expect("fresh second proof");

    let mut stream2 = TcpStream::connect(&addr_str).await.unwrap();
    // Use an empty token here! The tracker space-separated parsing will parse empty token if we format it differently,
    // wait, parts.len() >= 5 check: if we omit token, parts.len() == 4, token becomes "".
    let reg2 = format!("REGISTER_REVERSE {} {} {}\n", node_id, now2, nonce2);
    stream2.write_all(reg2.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    println!("Reading from stream2");
    let n = stream2.read(&mut buf).await.unwrap();
    println!("Read from stream2: {}", n);
    let response = String::from_utf8_lossy(&buf[..n]);

    // (c) Assert the second attempt is rejected
    assert!(
        response.contains("ERROR_AUTH_TOKEN_MISMATCH"),
        "Second attempt with empty token should be rejected, got: {}",
        response
    );

    // Also try with a DIFFERENT non-empty token
    let now3 = now;
    println!("Solving PoW 3");
    let nonce3 = ((nonce2 + 1)..10_000_000)
        .find(|nonce| verify_pow(node_id, now3, *nonce, test_difficulty, now))
        .expect("fresh third proof");
    println!("Connecting stream3");
    let mut stream3 = TcpStream::connect(&addr_str).await.unwrap();
    let reg3 = format!(
        "REGISTER_REVERSE {} {} {} {}\n",
        node_id, "wrong-token", now3, nonce3
    );
    stream3.write_all(reg3.as_bytes()).await.unwrap();
    println!("Reading from stream3");
    let n = stream3.read(&mut buf).await.unwrap();
    println!("Read from stream3: {}", n);
    let response3 = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response3.contains("ERROR_AUTH_TOKEN_MISMATCH"),
        "Second attempt with wrong token should be rejected, got: {}",
        response3
    );

    // And confirm CONNECT_REVERSE for X still receives the stream pushed by token T (stream1)
    println!("Connecting client");
    let mut client = TcpStream::connect(&addr_str).await.unwrap();
    let connect_cmd = format!("CONNECT_REVERSE {} {}\n", node_id, token_t);
    client.write_all(connect_cmd.as_bytes()).await.unwrap();

    println!("Reading from client");
    let n = client.read(&mut buf).await.unwrap();
    println!("Read from client: {}", n);
    let response_client = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response_client.contains("OK"),
        "Legitimate client should connect successfully, got: {}",
        response_client
    );
    println!("Test complete!");
}
