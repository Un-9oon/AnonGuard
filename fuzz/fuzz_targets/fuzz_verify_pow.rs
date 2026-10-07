#![no_main]

use anonguard::mesh::sybil::verify_pow;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 28 {
        return;
    }

    // Extract structured fields from fuzz input
    let timestamp = u64::from_be_bytes(data[0..8].try_into().unwrap());
    let nonce = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let difficulty = u32::from_be_bytes(data[16..20].try_into().unwrap());
    let current_time = u64::from_be_bytes(data[20..28].try_into().unwrap());

    let node_id = if let Ok(s) = std::str::from_utf8(&data[28..]) {
        s
    } else {
        "fuzz_node"
    };

    // verify_pow must never panic, regardless of input.
    let _ = verify_pow(node_id, timestamp, nonce, difficulty, current_time);
});
