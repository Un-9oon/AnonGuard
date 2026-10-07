#![no_main]
use anonguard::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
use anonguard::onion::circuit::{derive_hop_keys, OnionCircuit, RelayCircuitHop};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cid = 0xdeadbeef;
    let secret = [0x41; 64];
    let mut client = OnionCircuit::new(cid);
    client.add_hop(derive_hop_keys(&secret).unwrap()).unwrap();
    let command = CellCommand::from_u8(data.first().copied().unwrap_or(7) % 10 + 1).unwrap();
    let mut cell =
        OnionCell::new(cid, 0, command, 1, &data[..data.len().min(PAYLOAD_SIZE)]).unwrap();
    let wire = client.wrap_forward(&mut cell).unwrap();
    let mut hop = RelayCircuitHop::new(cid, derive_hop_keys(&secret).unwrap(), 0);
    let mut valid = wire;
    let _ = hop.peel_forward(&mut valid);
    let mut replay = wire;
    let _ = hop.peel_forward(&mut replay);

    // Exercise malformed and tampered input without waiting for an empty corpus
    // to discover a complete 2048-byte cell or forge an authentication tag.
    let mut arbitrary = [0u8; ONION_CELL_SIZE];
    let n = data.len().min(ONION_CELL_SIZE);
    arbitrary[..n].copy_from_slice(&data[..n]);
    arbitrary[..4].copy_from_slice(&cid.to_be_bytes());
    let mut hop = RelayCircuitHop::new(cid, derive_hop_keys(&secret).unwrap(), 0);
    let _ = hop.peel_forward(&mut arbitrary);
    if let Some(byte) = data.first() {
        let index = data.len() % ONION_CELL_SIZE;
        let mut mutated = wire;
        mutated[index] ^= byte.wrapping_add(1);
        let mut hop = RelayCircuitHop::new(cid, derive_hop_keys(&secret).unwrap(), 0);
        let _ = hop.peel_forward(&mut mutated);
    }
});
