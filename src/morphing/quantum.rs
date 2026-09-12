//! Quantum Random Matrix Theory (Q-RMT) Timing Engine
//! 
//! Simulates the eigenvalue spacing of Gaussian Orthogonal Ensembles (GOE)
//! and Gaussian Unitary Ensembles (GUE) using the Wigner Surmise.
//! Provides computationally efficient O(1) level repulsion for traffic morphing.

use rand::Rng;
use std::f64::consts::PI;

#[derive(Clone, Debug)]
pub enum QuantumEnsemble {
    /// Gaussian Orthogonal Ensemble (Time-reversal symmetry)
    GOE,
    /// Gaussian Unitary Ensemble (Broken time-reversal symmetry)
    GUE,
}

#[derive(Clone)]
pub struct QuantumRmtEngine {
    ensemble: QuantumEnsemble,
    base_delay_ms: f64,
    base_size_bytes: usize,
}

impl QuantumRmtEngine {
    pub fn new(ensemble: QuantumEnsemble, base_delay_ms: f64, base_size_bytes: usize) -> Self {
        Self {
            ensemble,
            base_delay_ms,
            base_size_bytes,
        }
    }

    /// Generates the next packet size based on RMT level spacing
    pub fn next_chunk_size(&self) -> usize {
        let spacing = match self.ensemble {
            QuantumEnsemble::GOE => self.sample_goe(),
            QuantumEnsemble::GUE => self.sample_gue(),
        };
        
        // Scale spacing to chunk size (e.g. baseline 1024 bytes)
        // Add a strict boundary to prevent zero-length or excessively large fragments
        let size = (spacing * self.base_size_bytes as f64) as usize;
        size.clamp(16, 4096)
    }

    /// Generates the next microsecond delay based on RMT level spacing
    pub fn next_delay_us(&self) -> u64 {
        let spacing = match self.ensemble {
            QuantumEnsemble::GOE => self.sample_goe(),
            QuantumEnsemble::GUE => self.sample_gue(),
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
        let s = (-(4.0 / PI) * u.ln()).sqrt();
        s
    }

    /// Samples spacing `s` from the GUE Wigner Surmise:
    /// P(s) = (32 / pi^2) * s^2 * exp(-4/pi * s^2)
    /// Using Rejection Sampling with an exponential envelope.
    fn sample_gue(&self) -> f64 {
        let mut rng = rand::thread_rng();
        
        loop {
            // Envelope generation: Exponential distribution is a good fit for the tail.
            // Simplified rejection sampling against uniform box [0, 3] covering 99.9% of mass
            // In a highly optimized version, we'd use a fitted bounding function.
            let s: f64 = rng.gen_range(0.0..3.0);
            let p_s = (32.0 / (PI * PI)) * (s * s) * (- (4.0 / PI) * (s * s)).exp();
            
            // Peak of GUE Wigner is roughly at s = sqrt(pi/4) approx 0.886
            // Max value is P(0.886) approx 0.932. Let's box max Y at 1.0
            let y: f64 = rng.gen_range(0.0..1.0);
            
            if y <= p_s {
                return s;
            }
        }
    }
}
