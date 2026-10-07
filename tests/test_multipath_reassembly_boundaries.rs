//! Bounds and progress contracts for the research reassembler; no gateway mode is enabled.
use anonguard::onion::multipath;
fn packet(sequence: u64, data: &[u8]) -> Vec<u8> {
    [sequence.to_be_bytes().as_slice(), data].concat()
}
#[test]
fn full_buffer_allows_gap_closure_and_drains() {
    let mut receiver = multipath::MultiPathReassembler::default();
    for sequence in 1..=10_000 {
        assert_eq!(receiver.receive(&packet(sequence, b"queued")), None);
    }
    assert_eq!(receiver.receive(&packet(10_001, b"rejected")), None);
    assert_eq!(
        receiver.receive(&packet(0, b"start")),
        Some(b"start".to_vec())
    );
    for _ in 1..=10_000 {
        assert_eq!(receiver.pop_next_buffered(), Some(b"queued".to_vec()));
    }
    assert_eq!(receiver.pop_next_buffered(), None);
    assert_eq!(
        receiver.receive(&packet(10_001, b"after-drain")),
        Some(b"after-drain".to_vec())
    );
}
#[test]
fn duplicate_buffered_packets_preserve_first_payload() {
    let mut receiver = multipath::MultiPathReassembler::default();
    assert_eq!(receiver.receive(&packet(1, b"first")), None);
    assert_eq!(receiver.receive(&packet(1, b"replacement")), None);
    assert_eq!(
        receiver.receive(&packet(0, b"start")),
        Some(b"start".to_vec())
    );
    assert_eq!(
        receiver.receive(&packet(1, b"second-replacement")),
        Some(b"first".to_vec())
    );
    assert_eq!(receiver.pop_next_buffered(), None);
    assert_eq!(receiver.receive(&packet(1, b"replay")), None);
}
#[test]
fn rejects_packets_larger_than_a_cell_without_advancing() {
    let mut receiver = multipath::MultiPathReassembler::default();
    assert!(receiver.receive(&packet(0, &vec![0; 2048])).is_none());
    assert_eq!(
        receiver.receive(&packet(0, b"valid")),
        Some(b"valid".to_vec())
    );
    assert_eq!(receiver.receive(&[0; 7]), None);
    assert_eq!(receiver.receive(&packet(u64::MAX, b"far-future")), None);
}

#[test]
fn slicing_refuses_short_outputs_and_oversized_cells_without_consuming_sequence() {
    let mut slicer = multipath::MultiPathSlicer::default();
    let mut short = [0x77; 7];
    assert!(slicer.slice(b"", &mut short).is_err());
    assert_eq!(short, [0x77; 7]);
    let mut output = vec![0x77; 2048];
    assert!(slicer.slice(&vec![0; 1980], &mut output).is_err());
    assert!(output.iter().all(|byte| *byte == 0x77));
    let length = slicer.slice(b"valid", &mut output).unwrap();
    assert_eq!(&output[..length], packet(0, b"valid"));
}
