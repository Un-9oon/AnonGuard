#![no_main]

use anonguard::onion::cell::{OnionCell, ONION_CELL_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() == ONION_CELL_SIZE {
        let mut buf = [0u8; ONION_CELL_SIZE];
        buf.copy_from_slice(data);
        let _ = OnionCell::parse(&buf);
    }
});
