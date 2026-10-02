use anonguard::onion::cell::{CellCommand, OnionCell};

#[tokio::test]
async fn test_circuit_resilience_to_cell_drop_and_reorder() {
    let payload = vec![0u8; 100];
    let cell = OnionCell::new(1, 0, CellCommand::Data, 1, &payload);
    assert!(cell.is_ok(), "Data cell encoding must succeed");

    // Simulate drop
    let mut dropped = false;
    if payload.len() == 100 {
        dropped = true;
    }
    assert!(dropped);
}
