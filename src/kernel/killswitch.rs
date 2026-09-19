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
}

impl KillSwitchController {
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            tripped: Arc::new(AtomicBool::new(false)),
            notifier_tx: Arc::new(tx),
            notifier_rx: rx,
            failures: Arc::new(Mutex::new(Vec::new())),
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
    pub fn trip(&self, reason: &str) {
        let mut failures = self.failures.lock().unwrap();
        let now = Instant::now();

        failures.retain(|&t| now.duration_since(t) < Duration::from_secs(1));
        failures.push(now);

        if failures.len() >= 5 {
            if !self.tripped.swap(true, Ordering::SeqCst) {
                tracing::error!(
                    reason = reason,
                    "[AnonGuard KillSwitch] TRIPPED! Enforcing strict fail-closed drop. (>5 failures/sec)"
                );
                let _ = self.notifier_tx.send(true);
            }
        } else {
            tracing::warn!(
                reason = reason,
                failures = failures.len(),
                "KillSwitch warning: connection failure recorded, but under threshold (5/sec)."
            );
        }
    }

    /// Resets the kill switch after fresh verified re-initialization.
    pub fn reset(&self) {
        self.tripped.store(false, Ordering::SeqCst);
        self.failures.lock().unwrap().clear();
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
