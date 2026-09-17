#![no_main]

use libfuzzer_sys::fuzz_target;
use anonguard::onion::cell::ONION_CELL_SIZE;
use anonguard::onion::circuit::RelayCircuitHop;

fuzz_target!(|data: &[u8]| {
    if data.len() < ONION_CELL_SIZE {
        return;
    }

    // Use a fixed key set — the fuzzer exercises the parsing/crypto paths,
    // not key generation.
    let forward_key = [0x41u8; 32];
    let backward_key = [0x42u8; 32];
    let mac_key = [0x43u8; 32];

    let mut hop = RelayCircuitHop::new(0xdeadbeef, forward_key, backward_key, mac_key);

    let mut buf = [0u8; ONION_CELL_SIZE];
    buf.copy_from_slice(&data[..ONION_CELL_SIZE]);

    // peel_forward must never panic, regardless of input.
    let _ = hop.peel_forward(&mut buf);
});
