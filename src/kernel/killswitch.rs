//! Sub-millisecond atomic fail-closed kill switch controller.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Clone)]
pub struct KillSwitchController {
    tripped: Arc<AtomicBool>,
    notifier_tx: Arc<watch::Sender<bool>>,
    notifier_rx: watch::Receiver<bool>,
    failures: Arc<Mutex<Vec<Instant>>>,
    /// Number of failures that must occur within `window` before the switch trips.
    trip_threshold: usize,
    /// Sliding time window over which failures are counted.
    window: Duration,
}

impl KillSwitchController {
    /// Creates a controller with the default trip threshold (5 failures per 1-second window).
    pub fn new() -> Self {
        Self::with_threshold(5, Duration::from_secs(1))
    }

    /// Creates a controller with a custom trip threshold and counting window.
    ///
    /// **Tradeoff**: a lower threshold is more sensitive to transient failures and produces
    /// more false-positive trips; a higher threshold gives a larger window in which leaks
    /// could occur before fail-closed engages.
    pub fn with_threshold(trip_threshold: usize, window: Duration) -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            tripped: Arc::new(AtomicBool::new(false)),
            notifier_tx: Arc::new(tx),
            notifier_rx: rx,
            failures: Arc::new(Mutex::new(Vec::new())),
            trip_threshold,
            window,
        }
    }

    /// Checks if the kill switch has been activated.
    #[inline(always)]
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    /// Returns the raw atomic handle for zero-overhead socket verification.
    pub fn atomic_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.tripped)
    }

    /// Immediately triggers the kill switch, broadcasting cancellation to all active workers.
    ///
    /// Uses poison-recovering lock access rather than `.unwrap()` because this is a
    /// fail-closed security path. An unrelated panic in another thread that happens to
    /// hold this lock must NOT permanently disable the kill switch — losing the ability
    /// to trip it is worse than operating on state that was mid-update when the panic
    /// occurred.
    pub fn trip(&self, reason: &str) {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();

        failures.retain(|&t| now.duration_since(t) < self.window);
        failures.push(now);

        if failures.len() >= self.trip_threshold {
            if !self.tripped.swap(true, Ordering::SeqCst) {
                tracing::error!(
                    reason = reason,
                    trip_threshold = self.trip_threshold,
                    "[AnonGuard KillSwitch] TRIPPED! Enforcing strict fail-closed drop."
                );
                let _ = self.notifier_tx.send(true);
            }
        } else {
            tracing::warn!(
                reason = reason,
                failures = failures.len(),
                trip_threshold = self.trip_threshold,
                "KillSwitch warning: connection failure recorded, but under threshold."
            );
        }
    }

    /// Resets the kill switch after fresh verified re-initialization.
    ///
    /// Uses poison-recovering lock access for the same reason as `trip()`: a poisoned
    /// mutex must not prevent the operator from resetting the controller.
    pub fn reset(&self) {
        self.tripped.store(false, Ordering::SeqCst);
        self.failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let _ = self.notifier_tx.send(false);
    }

    /// Subscribes to kill-switch state transitions.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.notifier_rx.clone()
    }
}

impl Default for KillSwitchController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for G2: mutex poisoning must not disable the kill switch.
    ///
    /// Without the `unwrap_or_else(|p| p.into_inner())` fix this test panics on the
    /// `.trip()` call with "PoisonError" because the previous thread panicked while
    /// holding the lock. With the fix, the controller remains functional.
    #[test]
    fn test_mutex_poisoning_does_not_disable_kill_switch() {
        let ks = KillSwitchController::new();
        let ks_clone = ks.clone();

        // Poison the mutex: grab the lock and panic inside it.
        let result = std::panic::catch_unwind(move || {
            let _guard = ks_clone.failures.lock().unwrap();
            panic!("deliberate panic to poison the mutex");
        });
        assert!(
            result.is_err(),
            "the catch_unwind should have caught a panic"
        );

        // After poisoning, trip/reset/is_tripped must not themselves panic.
        // We call trip 5 times (within the same instant window) so it actually fires.
        for _ in 0..5 {
            ks.trip("poison-test");
        }
        assert!(
            ks.is_tripped(),
            "kill switch must be tripped after 5 rapid failures"
        );

        ks.reset();
        assert!(!ks.is_tripped(), "kill switch must be clear after reset");
    }

    /// Test for G3: a controller with trip_threshold=2 must trip after exactly 2 failures,
    /// not 5, and the default (5) behavior must be unchanged.
    #[test]
    fn test_custom_threshold_trips_early() {
        // Custom threshold: trip on 2 failures/sec
        let ks = KillSwitchController::with_threshold(2, Duration::from_secs(1));
        assert!(!ks.is_tripped());
        ks.trip("test-1");
        assert!(
            !ks.is_tripped(),
            "should not trip on 1st failure (threshold=2)"
        );
        ks.trip("test-2");
        assert!(ks.is_tripped(), "must trip on 2nd failure (threshold=2)");

        // Default threshold (5): must NOT trip on fewer than 5.
        let ks5 = KillSwitchController::new(); // default: 5/sec
        for i in 0..4 {
            ks5.trip(&format!("test-{i}"));
        }
        assert!(
            !ks5.is_tripped(),
            "default controller must not trip before 5th failure"
        );
        ks5.trip("test-5");
        assert!(
            ks5.is_tripped(),
            "default controller must trip on 5th failure"
        );
    }
}
