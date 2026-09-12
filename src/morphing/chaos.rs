//! Deterministic Chaos Engine for Traffic Morphing
//!
//! Uses the Lorenz Attractor equations to generate pseudo-random, highly unpredictable
//! (but mathematically deterministic) packet shard sizes and timing delays.
//! This defeats AI correlation models that rely on stochastic noise filtering.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct LorenzAttractor {
    state: Arc<Mutex<LorenzState>>,
    dt: f64,
}

#[derive(Debug)]
struct LorenzState {
    x: f64,
    y: f64,
    z: f64,
    sigma: f64,
    rho: f64,
    beta: f64,
}

impl LorenzAttractor {
    pub fn new(sigma: f64, rho: f64, beta: f64, dt: f64) -> Self {
        Self {
            state: Arc::new(Mutex::new(LorenzState {
                x: 1.0, // initial conditions (the butterfly effect starts here)
                y: 1.0,
                z: 1.0,
                sigma,
                rho,
                beta,
            })),
            dt,
        }
    }

    /// Steps the chaotic system forward using Euler's method and returns (X, Y).
    fn step(&self) -> (f64, f64) {
        let mut s = self.state.lock().unwrap();
        let dx = s.sigma * (s.y - s.x);
        let dy = s.x * (s.rho - s.z) - s.y;
        let dz = s.x * s.y - s.beta * s.z;

        s.x += dx * self.dt;
        s.y += dy * self.dt;
        s.z += dz * self.dt;

        (s.x, s.y)
    }

    /// Computes the next packet shard size based on the chaotic X axis.
    /// Maps the chaotic X output (typically -20 to 20) to a shard size (e.g. 50 to 1500 bytes).
    pub fn sample_shard_size(&self, max_buffer_len: usize) -> usize {
        if max_buffer_len <= 50 {
            return max_buffer_len;
        }

        let (x, _) = self.step();

        // Normalize X from roughly [-20.0, 20.0] to [0.0, 1.0]
        let normalized_x = ((x + 20.0) / 40.0).clamp(0.0, 1.0);

        let min_size = 50;
        let max_size = 1500.min(max_buffer_len);

        let size = min_size as f64 + (normalized_x * (max_size - min_size) as f64);
        size as usize
    }

    /// Computes the next timing delay based on the chaotic Y axis.
    /// Maps the chaotic Y output (typically -30 to 30) to a micro-delay (e.g. 1ms to 45ms).
    pub fn sample_delay(&self) -> Duration {
        let (_, y) = self.step();

        // Normalize Y from roughly [-30.0, 30.0] to [0.0, 1.0]
        let normalized_y = ((y + 30.0) / 60.0).clamp(0.0, 1.0);

        let min_ms = 1.0;
        let max_ms = 45.0;

        let ms = min_ms + (normalized_y * (max_ms - min_ms));
        Duration::from_secs_f64(ms / 1000.0)
    }

    /// Asynchronously applies the chaotic delay.
    pub async fn apply_delay(&self) {
        let delay = self.sample_delay();
        sleep(delay).await;
    }
}

impl Default for LorenzAttractor {
    fn default() -> Self {
        Self::new(10.0, 28.0, 8.0 / 3.0, 0.01)
    }
}
