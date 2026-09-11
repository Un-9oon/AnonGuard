use anonguard::kernel::KillSwitchController;

#[test]
fn test_killswitch_initial_state() {
    let controller = KillSwitchController::new();
    assert!(!controller.is_tripped());
}

#[test]
fn test_killswitch_trip_and_reset() {
    let controller = KillSwitchController::new();
    let mut rx = controller.subscribe();

    assert!(!*rx.borrow());

    controller.trip("Simulated network failure");
    assert!(controller.is_tripped());
    assert!(*rx.borrow_and_update());

    controller.reset();
    assert!(!controller.is_tripped());
    assert!(!*rx.borrow_and_update());
}
