use anonguard::morphing::{PacketPadder, PoissonJitter};
use std::time::Duration;

#[test]
fn test_packet_padding_and_unpadding() {
    let padder = PacketPadder::new(512);
    let original = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    let padded = padder.pad(original);
    assert_eq!(padded.len() % 512, 0);
    assert!(padded.len() >= 512);

    let unpadded = padder.unpad(&padded).unwrap();
    assert_eq!(unpadded, original);
}

#[test]
fn test_poisson_jitter_bounds() {
    let jitter = PoissonJitter::new(0.1, 10.0, 50.0);

    for _ in 0..50 {
        let delay = jitter.sample_delay();
        assert!(delay >= Duration::from_millis(10));
        assert!(delay <= Duration::from_millis(50));
    }
}

#[tokio::test]
async fn test_poisson_jitter_small_buffers() {
    use anonguard::morphing::{morph_bidirectional_guarded, JitterEngine};
    use tokio::io::AsyncReadExt;

    // Test buffer sizes including sub-50 byte chunks (which previously triggered gen_range panics)
    let test_sizes = [1, 5, 23, 49, 50, 51, 128, 1024];

    for &size in &test_sizes {
        let (mut client_a, mut server_a) = tokio::io::duplex(4096);
        let (mut client_b, mut server_b) = tokio::io::duplex(4096);

        let jitter = JitterEngine::Poisson(PoissonJitter::new(0.5, 1.0, 5.0));

        let morph_task = tokio::spawn(async move {
            morph_bidirectional_guarded(&mut server_a, &mut server_b, Some(jitter), None).await
        });

        let payload = vec![0x42u8; size];
        let payload_clone = payload.clone();

        let client_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client_a.write_all(&payload_clone).await.unwrap();
            let _ = client_a.shutdown().await;

            let mut received = Vec::new();
            client_b.read_to_end(&mut received).await.unwrap();
            let _ = client_b.shutdown().await;
            received
        });

        let received = client_task.await.unwrap();
        assert_eq!(received, payload, "Payload mismatch for size {}", size);
        let _ = morph_task.await;
    }
}
