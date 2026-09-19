use anonguard::kernel::KillSwitchController;
use std::time::Duration;

#[test]
fn test_killswitch_initial_state() {
    let controller = KillSwitchController::new();
    assert!(!controller.is_tripped());
}

#[test]
fn test_killswitch_trip_and_reset() {
    // Use threshold=1 to test the trip/reset contract in isolation,
    // independent of the default threshold value (which is tested in unit tests).
    let controller = KillSwitchController::with_threshold(1, Duration::from_secs(1));
    let mut rx = controller.subscribe();

    assert!(!*rx.borrow());

    controller.trip("Simulated network failure");
    assert!(controller.is_tripped());
    assert!(*rx.borrow_and_update());

    controller.reset();
    assert!(!controller.is_tripped());
    assert!(!*rx.borrow_and_update());
}
