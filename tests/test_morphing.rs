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
