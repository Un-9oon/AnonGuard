#![no_main]

use libfuzzer_sys::fuzz_target;
use anonguard::onion::circuit::decode_extend_payload;

fuzz_target!(|data: &[u8]| {
    // decode_extend_payload must never panic, regardless of input.
    // It should return Err for malformed data.
    let _ = decode_extend_payload(data);
});
