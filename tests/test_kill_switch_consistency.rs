//! Completed reset/trip races must leave the atomic guard and notifier consistent.
use anonguard::kernel::KillSwitchController;
use std::sync::{Arc, Barrier};
use std::time::Duration;

#[test]
fn concurrent_reset_and_trip_have_one_consistent_final_state() {
    let controller = KillSwitchController::with_threshold(1, Duration::from_secs(1));
    let observer = controller.subscribe();
    let barrier = Arc::new(Barrier::new(3));
    let tripping = controller.clone();
    let trip_barrier = barrier.clone();
    let trip = std::thread::spawn(move || {
        for _ in 0..10_000 {
            trip_barrier.wait();
            tripping.trip("concurrent reset regression");
            trip_barrier.wait();
        }
    });
    let resetting = controller.clone();
    let reset_barrier = barrier.clone();
    let reset = std::thread::spawn(move || {
        for _ in 0..10_000 {
            reset_barrier.wait();
            resetting.reset();
            reset_barrier.wait();
        }
    });
    let mut consistent = true;
    for _ in 0..10_000 {
        barrier.wait();
        barrier.wait();
        // Both calls completed; workers wait for us before the next round.
        consistent &= controller.is_tripped() == *observer.borrow();
    }
    trip.join().unwrap();
    reset.join().unwrap();
    assert!(
        consistent,
        "Kill-switch atomic state disagreed with its completed notification"
    );
}
