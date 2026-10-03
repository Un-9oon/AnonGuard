#![no_main]
use libfuzzer_sys::fuzz_target;
use anonguard::onion::multipath::MultiPathReassembler;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes as multipath payload frames.
    // Each frame is at least 8 bytes (the multipath sequence header).
    // The fuzzer will explore:
    //  - payloads shorter than 8 bytes (should return None, no panic)
    //  - arbitrary sequence numbers (replay, gap, future)
    //  - sequences that push MAX_SEQ_GAP and MAX_BUFFERED_ENTRIES bounds
    let mut reassembler = MultiPathReassembler::new();

    // Split the fuzz input into variable-length chunks and feed each as a separate frame.
    // This exercises both in-order delivery and out-of-order buffering.
    let mut offset = 0;
    while offset < data.len() {
        // Use the first byte (if available) as the chunk length hint (1..=64 bytes)
        let chunk_len = if offset < data.len() {
            ((data[offset] as usize) % 64) + 1
        } else {
            break;
        };
        let end = (offset + chunk_len).min(data.len());
        let frame = &data[offset..end];
        let _ = reassembler.receive(frame);
        let _ = reassembler.pop_next_buffered();
        offset = end;
    }
});
