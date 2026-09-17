use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_tracker_registration_end_to_end() {
    let tracker_port = 40987;
    let tracker_addr = format!("127.0.0.1:{}", tracker_port);
    let pow_difficulty = 10;

    let tracker =
        anonguard::mesh::TrackerServer::with_difficulty(tracker_addr.clone(), pow_difficulty);
    tokio::spawn(async move {
        tracker.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let my_listen = "127.0.0.1:9050";
    let node_id = format!("relay-{}", my_listen);
    let now = anonguard::mesh::sybil::current_timestamp_secs();
    let nonce = anonguard::mesh::sybil::solve_pow(&node_id, now, pow_difficulty);
    let line = format!(
        "REGISTER_REVERSE {} {} {} {}\n",
        node_id, my_listen, now, nonce
    );

    let mut stream = TcpStream::connect(&tracker_addr)
        .await
        .expect("Failed to connect to tracker");
    stream
        .write_all(line.as_bytes())
        .await
        .expect("Failed to write to tracker");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut query_stream = TcpStream::connect(&tracker_addr)
        .await
        .expect("Failed to connect to query");
    let get_req = "GET /nodes HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    query_stream
        .write_all(get_req.as_bytes())
        .await
        .expect("Failed to write GET");

    let mut response = String::new();
    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        query_stream.read_to_string(&mut response),
    )
    .await;

    assert!(
        response.contains(&node_id),
        "Tracker response did not contain registered node_id"
    );
    assert!(
        response.contains(my_listen),
        "Tracker response did not contain registered listen addr"
    );
}
