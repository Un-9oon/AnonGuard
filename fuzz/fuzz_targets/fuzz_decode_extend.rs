#![no_main]

use anonguard::onion::circuit::decode_extend_payload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // decode_extend_payload must never panic, regardless of input.
    // It should return Err for malformed data.
    let _ = decode_extend_payload(data);
});
