#![no_main]

use anonguard::onion::circuit::decode_relay_target;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // decode_relay_target must never panic, regardless of input.
    let _ = decode_relay_target(data);
});
