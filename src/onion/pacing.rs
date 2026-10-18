//! Phase-preserving pacing without catch-up bursts. This cannot hide TCP congestion.
use std::time::Duration;
use tokio::time::Instant;

pub(super) fn next_deadline(previous: Instant, now: Instant, interval: Duration) -> Instant {
    assert!(!interval.is_zero());
    let nominal = previous + interval;
    if nominal > now {
        return nominal;
    }
    // Skip expired opportunities instead of leaking a backlog as a burst.
    // A very long suspension may exceed the multiplier; safely rebase then.
    let skipped = (now - nominal).as_nanos() / interval.as_nanos() + 1;
    match u32::try_from(skipped)
        .ok()
        .and_then(|n| interval.checked_mul(n))
    {
        Some(delay) => nominal + delay,
        None => now + interval,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_write_cost_does_not_accumulate_into_cadence() {
        let start = Instant::now();
        let interval = Duration::from_millis(20);
        let mut slot = start;
        for index in 1..=100 {
            let write_time = Duration::from_millis(if index % 2 == 0 { 12 } else { 1 });
            slot = next_deadline(slot, slot + write_time, interval);
            assert_eq!(slot, start + interval * index);
        }
    }

    #[test]
    fn congestion_skips_slots_without_immediate_catchup() {
        let start = Instant::now();
        for elapsed in [20, 21, 39, 40, 105, 1000] {
            let now = start + Duration::from_millis(elapsed);
            let next = next_deadline(start, now, Duration::from_millis(20));
            assert!(next > now);
            assert!(next - now <= Duration::from_millis(20));
            assert_eq!((next - start).as_millis() % 20, 0);
        }
    }
}
