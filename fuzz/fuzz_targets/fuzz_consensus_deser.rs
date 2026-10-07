#![no_main]

use anonguard::mesh::consensus::ConsensusDocument;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Deserialization from untrusted input must never panic.
    let _ = serde_json::from_slice::<ConsensusDocument>(data);
});
