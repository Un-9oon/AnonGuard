#![no_main]

use libfuzzer_sys::fuzz_target;
use anonguard::mesh::consensus::ConsensusDocument;

fuzz_target!(|data: &[u8]| {
    // Deserialization from untrusted input must never panic.
    let _ = serde_json::from_slice::<ConsensusDocument>(data);
});
