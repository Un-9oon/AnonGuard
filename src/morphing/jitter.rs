//! Poisson process timing jitter generator to defeat traffic correlation.

use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct PoissonJitter {
    lambda: f64,
    min_ms: f64,
    max_ms: f64,
}

impl PoissonJitter {
    pub fn new(lambda: f64, min_ms: f64, max_ms: f64) -> Self {
        Self {
            lambda: if lambda <= 0.0 { 0.05 } else { lambda },
            min_ms: min_ms.max(0.0),
            max_ms: max_ms.max(min_ms),
        }
    }

    /// Samples the next inter-packet delay from an exponential distribution (Poisson inter-arrival time).
    pub fn sample_delay(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let u: f64 = rng.gen_range(0.0001..0.9999);
        // Inverse transform sampling for Exponential distribution: t = -ln(1 - u) / lambda
        let raw_ms = -((1.0 - u).ln()) / self.lambda;
        let clamped_ms = raw_ms.clamp(self.min_ms, self.max_ms);
        Duration::from_secs_f64(clamped_ms / 1000.0)
    }

    /// Asynchronously applies the sampled Poisson delay.
    pub async fn apply(&self) {
        let delay = self.sample_delay();
        sleep(delay).await;
    }
}

impl Default for PoissonJitter {
    fn default() -> Self {
        Self::new(0.05, 5.0, 45.0)
    }
}
