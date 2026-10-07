#![no_main]
use anonguard::onion::cell::{OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; ONION_CELL_SIZE];
    let n = data.len().min(ONION_CELL_SIZE);
    buf[..n].copy_from_slice(&data[..n]);
    let _ = OnionCell::parse(&buf);
    // Reach valid-header parsing from short inputs while retaining arbitrary
    // command and length coverage in the raw parse above.
    buf[8] = data.first().copied().unwrap_or(7) % 11;
    buf[11..13].copy_from_slice(&(data.len().min(PAYLOAD_SIZE) as u16).to_be_bytes());
    let _ = OnionCell::parse(&buf);
});
