//! Statistical Random Matrix Theory (RMT) Timing Engine
//!
//! Samples inter-packet delay and chunk size from the eigenvalue-spacing
//! distribution of Gaussian Orthogonal Ensembles (GOE) and Gaussian Unitary
//! Ensembles (GUE) via the Wigner surmise — a classical result from random
//! matrix theory (nuclear physics/statistics), unrelated to quantum computing.
//! Sampling uses a standard CSPRNG and runs in O(1) time per packet.

use rand::Rng;
use std::f64::consts::PI;

#[derive(Clone, Debug)]
pub enum RmtEnsemble {
    /// Gaussian Orthogonal Ensemble (Time-reversal symmetry)
    GOE,
    /// Gaussian Unitary Ensemble (Broken time-reversal symmetry)
    GUE,
}

#[derive(Clone)]
pub struct RmtTimingEngine {
    ensemble: RmtEnsemble,
    base_delay_ms: f64,
    base_size_bytes: usize,
}

impl RmtTimingEngine {
    pub fn new(ensemble: RmtEnsemble, base_delay_ms: f64, base_size_bytes: usize) -> Self {
        Self {
            ensemble,
            base_delay_ms,
            base_size_bytes,
        }
    }

    /// Generates the next packet size based on RMT level spacing
    pub fn next_chunk_size(&self) -> usize {
        let spacing = match self.ensemble {
            RmtEnsemble::GOE => self.sample_goe(),
            RmtEnsemble::GUE => self.sample_gue(),
        };

        // Scale spacing to chunk size (e.g. baseline 1024 bytes)
        // Add a strict boundary to prevent zero-length or excessively large fragments
        let size = (spacing * self.base_size_bytes as f64) as usize;
        size.clamp(16, 4096)
    }

    /// Generates the next microsecond delay based on RMT level spacing
    pub fn next_delay_us(&self) -> u64 {
        let spacing = match self.ensemble {
            RmtEnsemble::GOE => self.sample_goe(),
            RmtEnsemble::GUE => self.sample_gue(),
        };

        // Scale spacing to microsecond delay
        let delay_ms = spacing * self.base_delay_ms;
        (delay_ms * 1000.0) as u64
    }

    /// Samples spacing `s` from the GOE Wigner Surmise:
    /// P(s) = (pi/2) * s * exp(-pi/4 * s^2)
    /// Using inverse transform sampling: s = sqrt(- (4/pi) * ln(U))
    fn sample_goe(&self) -> f64 {
        let mut rng = rand::thread_rng();
        // Prevent strictly 0.0 to avoid ln(0) infinity
        let u: f64 = rng.gen_range(1e-9..1.0);
        (-(4.0 / PI) * u.ln()).sqrt()
    }

    /// Samples spacing `s` from the GUE Wigner Surmise:
    /// P(s) = (32 / pi^2) * s^2 * exp(-4/pi * s^2)
    /// Using Rejection Sampling with an exponential envelope.
    fn sample_gue(&self) -> f64 {
        let mut rng = rand::thread_rng();

        let mut best_s = 0.886; // Default to peak if all iterations fail
        let mut found = false;

        // Bounded iteration (constant time) to prevent timing side-channels (V-002 fix).
        // 16 iterations gives a very high probability of success while maintaining O(1) execution time.
        for _ in 0..16 {
            let s: f64 = rng.gen_range(0.0..3.0);
            let p_s = (32.0 / (PI * PI)) * (s * s) * (-(4.0 / PI) * (s * s)).exp();
            let y: f64 = rng.gen_range(0.0..1.0);

            // If we found a valid sample and haven't already locked one in, keep it.
            // We evaluate both sides fully to keep execution path uniform.
            let valid = y <= p_s;
            if valid && !found {
                best_s = s;
                found = true;
            }
        }

        best_s
    }
}
