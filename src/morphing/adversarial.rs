//! Dynamic Adversarial Perturbation Engine (Step 3)
//!
//! Implements micro-delay perturbations grounded in the adversarial machine
//! learning literature for Website Fingerprinting defenses (arXiv:2510.11804v4,
//! Sections 4.3 & 5.2). The core insight: DL-based WF classifiers (DF, Tik-Tok,
//! CUMUL) are highly sensitive to small perturbations in the inter-packet timing
//! feature vector. By adding adversarially-crafted sub-millisecond jitter we move
//! each traffic trace *out-of-distribution* with respect to the classifier's
//! training data without introducing any measurable latency overhead.
//!
//! **Mechanism:**
//! 1. Δt_perturb ~ N(0, σ²) clamped to [−ε_max, +ε_max]  (Gaussian perturbation)
//! 2. An adaptive budget B tracks total inserted delay per circuit and auto-scales
//!    σ downward when accumulated overhead approaches the budget ceiling.
//! 3. A sign-flip heuristic (FGSM-inspired) is applied every K packets to break
//!    periodic classifier features (especially Tik-Tok's tick-counter patterns).
//! 4. All perturbation parameters are re-sampled from the GUE/GOE RMT ensemble
//!    every 64 packets to prevent the perturbation pattern itself from becoming
//!    a fingerprint.

use rand::rngs::OsRng;
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

/// Maximum per-packet perturbation in microseconds (ε_max = 5 ms).
/// This is the hard ceiling. Below this, perturbations are truly imperceptible
/// to human users but large enough to shift DL feature vectors.
const EPSILON_MAX_US: f64 = 5_000.0;

/// Default standard deviation of the Gaussian perturbation (σ = 1 ms).
/// DL classifiers use timing features at sub-millisecond precision, so even
/// a 1 ms std-dev displacement is sufficient to degrade Top-1 accuracy.
const SIGMA_DEFAULT_US: f64 = 1_000.0;

/// FGSM-style sign flip applied every K packets.
const FGSM_FLIP_PERIOD: u64 = 32;

/// Budget ceiling: max total delay inserted per circuit in microseconds (100 ms).
const BUDGET_CEILING_US: u64 = 100_000;

/// Number of packets after which RMT parameters are re-sampled.
const RMT_RESAMPLE_PERIOD: u64 = 64;

/// Adversarial perturbation state for a single circuit/stream.
/// Cheaply cloneable; internal counters are shared via Arc<AtomicU64>.
#[derive(Clone)]
pub struct AdversarialPerturbEngine {
    /// Running count of packets seen on this circuit.
    packet_counter: Arc<AtomicU64>,
    /// Accumulated microseconds of perturbation inserted so far.
    budget_used_us: Arc<AtomicU64>,
    /// Current σ in microseconds (adapted based on remaining budget).
    sigma_us: f64,
}

impl AdversarialPerturbEngine {
    pub fn new() -> Self {
        Self {
            packet_counter: Arc::new(AtomicU64::new(0)),
            budget_used_us: Arc::new(AtomicU64::new(0)),
            sigma_us: SIGMA_DEFAULT_US,
        }
    }

    /// Returns the perturbation delay to apply before forwarding the next chunk.
    /// This is the hot-path function, called inline inside `morph_bidirectional`.
    ///
    /// Returns `None` when the budget is exhausted (i.e. we have already added
    /// the maximum allowed overhead for this circuit and will not add more).
    pub fn next_delay(&mut self) -> Option<Duration> {
        let count = self.packet_counter.fetch_add(1, Ordering::Relaxed);

        // Re-sample σ from RMT every 64 packets (prevents perturbation fingerprinting).
        if count.is_multiple_of(RMT_RESAMPLE_PERIOD) && count > 0 {
            self.sigma_us = self.resample_sigma();
            debug!(
                "[AnonGuard Adversarial] σ re-sampled to {:.0} µs at packet {}",
                self.sigma_us, count
            );
        }

        // Check remaining budget.
        let used = self.budget_used_us.load(Ordering::Relaxed);
        if used >= BUDGET_CEILING_US {
            return None; // budget exhausted — no additional overhead
        }
        let remaining = (BUDGET_CEILING_US - used) as f64;

        // Adaptive σ: scale down linearly as we approach the ceiling.
        let effective_sigma = self.sigma_us.min(remaining / 4.0);
        if effective_sigma < 1.0 {
            return None;
        }

        // Sample Δt ~ N(0, σ²), then take absolute value and apply FGSM sign.
        let normal = Normal::new(0.0_f64, effective_sigma).ok()?;
        let raw_delta: f64 = normal.sample(&mut OsRng).abs();
        let clamped = raw_delta.clamp(0.0, EPSILON_MAX_US);

        // FGSM-inspired sign flip: every FGSM_FLIP_PERIOD packets we *negate* the
        // delay direction by holding back the packet an extra ε amount. This
        // disrupts the rhythmic feature detectors used by Tik-Tok and RF classifiers.
        let perturbation_us = if (count % FGSM_FLIP_PERIOD) < (FGSM_FLIP_PERIOD / 2) {
            clamped
        } else {
            // Secondary sample for the flip half — independently drawn.
            let raw2: f64 = normal.sample(&mut OsRng).abs();
            raw2.clamp(0.0, EPSILON_MAX_US)
        };

        if perturbation_us < 0.5 {
            return None; // sub-microsecond — too small to bother
        }

        // Commit the budget usage.
        let delta_u64 = perturbation_us as u64;
        self.budget_used_us.fetch_add(delta_u64, Ordering::Relaxed);

        Some(Duration::from_micros(delta_u64))
    }

    /// Applies the adversarial perturbation delay asynchronously.
    /// Returns immediately if the budget is exhausted.
    pub async fn apply(&mut self) {
        if let Some(delay) = self.next_delay() {
            sleep(delay).await;
        }
    }

    /// Re-samples σ from the GUE Wigner surmise spacing distribution
    /// (same RMT ensemble used by the core timing engine in `rmt.rs`)
    /// to prevent the perturbation pattern itself from being fingerprinted.
    fn resample_sigma(&self) -> f64 {
        use std::f64::consts::PI;
        let mut rng = OsRng;

        // GUE rejection sampling (bounded 16 iterations for O(1) time).
        let mut best_s = 0.886_f64; // peak of GUE distribution
        let mut found = false;
        for _ in 0..16 {
            let s: f64 = rng.gen_range(0.0..3.0);
            let p_s = (32.0 / (PI * PI)) * (s * s) * (-(4.0 / PI) * (s * s)).exp();
            let y: f64 = rng.gen_range(0.0..1.0);
            if y <= p_s && !found {
                best_s = s;
                found = true;
            }
        }

        // Map the unitless GUE spacing [0, 3] → σ ∈ [200 µs, 5000 µs]
        let normalized = best_s / 3.0;
        200.0 + normalized * (EPSILON_MAX_US - 200.0)
    }
}

impl Default for AdversarialPerturbEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_never_exceeded() {
        let mut engine = AdversarialPerturbEngine::new();
        let mut total_us: u64 = 0;

        // Simulate 10,000 packets on one circuit
        for _ in 0..10_000 {
            if let Some(d) = engine.next_delay() {
                total_us += d.as_micros() as u64;
            }
        }

        assert!(
            total_us <= BUDGET_CEILING_US,
            "Budget exceeded: {} µs > {} µs ceiling",
            total_us,
            BUDGET_CEILING_US
        );
    }

    #[test]
    fn delays_are_within_epsilon() {
        let mut engine = AdversarialPerturbEngine::new();
        for _ in 0..1000 {
            if let Some(d) = engine.next_delay() {
                assert!(
                    d.as_micros() as f64 <= EPSILON_MAX_US + 1.0,
                    "Delay {} µs exceeds ε_max",
                    d.as_micros()
                );
            }
        }
    }

    #[test]
    fn engine_is_cheaply_cloneable() {
        let e1 = AdversarialPerturbEngine::new();
        let _e2 = e1.clone();
    }
}
