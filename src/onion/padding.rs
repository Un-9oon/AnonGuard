use rand_distr::{Distribution, Exp};
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

/// The WTF-PAD state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WtfPadState {
    Burst,
    Gap,
}

/// A padding state machine based on the WTF-PAD protocol for Website Fingerprinting Defense.
/// It transitions between Burst and Gap states. During Gap states, it schedules dummy cells
/// to hide the silence and mask traffic bursts.
pub struct AdaptivePaddingEngine {
    state: WtfPadState,
    last_real_packet_time: Instant,
    next_padding_time: Option<Instant>,
    burst_timeout: Duration,
    // The mean inter-arrival time for dummy packets during a gap state
    gap_mean_iat: Duration,
}

impl AdaptivePaddingEngine {
    pub fn new(burst_timeout: Duration, gap_mean_iat: Duration) -> Self {
        Self {
            state: WtfPadState::Burst,
            last_real_packet_time: Instant::now(),
            next_padding_time: None,
            burst_timeout,
            gap_mean_iat,
        }
    }

    /// Default configuration for normal web traffic (values from literature)
    pub fn default_config() -> Self {
        Self::new(
            Duration::from_millis(500), // Consider it a gap if no traffic for 500ms
            Duration::from_millis(150), // Mean gap padding rate
        )
    }

    /// Call this whenever a real packet is sent/received.
    pub fn record_real_packet(&mut self) {
        self.last_real_packet_time = Instant::now();
        if self.state == WtfPadState::Gap {
            self.state = WtfPadState::Burst;
            self.next_padding_time = None;
        }
    }

    /// Evaluates whether the engine should emit a padding cell right now.
    pub fn should_send_padding(&mut self) -> bool {
        let now = Instant::now();

        // Check if we need to transition from Burst to Gap
        if self.state == WtfPadState::Burst && now.duration_since(self.last_real_packet_time) >= self.burst_timeout {
            self.state = WtfPadState::Gap;
            self.schedule_next_padding(now);
        }

        if self.state == WtfPadState::Gap {
            if let Some(target) = self.next_padding_time {
                if now >= target {
                    // Time to send padding! Schedule the next one immediately.
                    self.schedule_next_padding(now);
                    return true;
                }
            }
        }

        false
    }

    /// Returns the duration until the next event (either a Burst->Gap timeout, or a Gap->Padding timeout).
    /// This is very useful for tokio select! loops.
    pub fn next_event_delay(&self) -> Duration {
        let now = Instant::now();
        if self.state == WtfPadState::Burst {
            let timeout_at = self.last_real_packet_time + self.burst_timeout;
            timeout_at.saturating_duration_since(now)
        } else if let Some(target) = self.next_padding_time {
            target.saturating_duration_since(now)
        } else {
            Duration::from_secs(86400)
        }
    }

    /// Uses an Exponential distribution to sample the next padding interval
    fn schedule_next_padding(&mut self, now: Instant) {
        // Sample from Exp(lambda) where lambda = 1 / mean
        let lambda = 1.0 / self.gap_mean_iat.as_secs_f64();
        let exp = Exp::new(lambda).unwrap();
        let delay_secs = exp.sample(&mut OsRng);
        let delay = Duration::from_secs_f64(delay_secs);
        self.next_padding_time = Some(now + delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_wtf_pad_transitions() {
        let mut engine = AdaptivePaddingEngine::new(Duration::from_millis(10), Duration::from_millis(5));
        
        // Initial state is Burst
        assert_eq!(engine.state, WtfPadState::Burst);
        assert!(!engine.should_send_padding());

        // Wait past burst timeout
        thread::sleep(Duration::from_millis(15));
        
        // Next check should trigger Gap state
        engine.should_send_padding();
        assert_eq!(engine.state, WtfPadState::Gap);
        assert!(engine.next_padding_time.is_some());

        // Record real packet, should revert to Burst
        engine.record_real_packet();
        assert_eq!(engine.state, WtfPadState::Burst);
        assert!(engine.next_padding_time.is_none());
    }
}
