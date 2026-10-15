//! Bounded, ephemeral source-group handshake admission. This is not identity or
//! Sybil certification. NAT clients share a budget; distributed floods remain.
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

pub(crate) const SOURCE_SLOTS: usize = 4;
const SOURCE_BURST: u32 = 64;
const SOURCE_REFILL: Duration = Duration::from_micros(83_334); // At most 12 starts/s.
const SOURCE_IDLE: Duration = Duration::from_secs(120);
const MAX_SOURCES: usize = 4096;

pub(crate) struct TokenBucket {
    tokens: u32,
    burst: u32,
    refill: Duration,
    last: Instant,
}
impl TokenBucket {
    pub(crate) fn new(burst: u32, refill: Duration, now: Instant) -> Self {
        assert!(burst > 0 && !refill.is_zero());
        Self {
            tokens: burst,
            burst,
            refill,
            last: now,
        }
    }
    pub(crate) fn available(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        let refill = elapsed.as_nanos() / self.refill.as_nanos();
        if refill >= u128::from(self.burst) {
            self.tokens = self.burst;
            self.last = now;
        } else if refill > 0 {
            let refill = refill as u32;
            self.tokens = self.tokens.saturating_add(refill).min(self.burst);
            self.last += self.refill * refill;
        }
        self.tokens > 0
    }
    pub(crate) fn take(&mut self, now: Instant) -> bool {
        if !self.available(now) {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Hash, PartialEq, Eq)]
enum SourceGroup {
    V4([u8; 4]),
    V6([u8; 8]),
}
impl From<IpAddr> for SourceGroup {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip.octets()),
            IpAddr::V6(ip) => {
                if let Some(v4) = ip.to_ipv4_mapped() {
                    return Self::V4(v4.octets());
                }
                Self::V6(ip.octets()[..8].try_into().expect("eight-byte prefix"))
            }
        }
    }
}
struct Source {
    slots: Arc<Semaphore>,
    rate: TokenBucket,
    seen: Instant,
}

/// Owned by a listener, with no per-source waiter tasks or persistent IP logs.
/// Entries with outstanding permits are never evicted: replacing their semaphore
/// would allow a still-live source to reset its concurrency allowance.
pub(crate) struct SourceAdmission {
    sources: HashMap<SourceGroup, Source>,
    next_sweep: Option<Instant>,
}
impl SourceAdmission {
    pub(crate) fn new() -> Self {
        Self {
            sources: HashMap::new(),
            next_sweep: None,
        }
    }
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.sources.retain(|_, source| {
            source.slots.available_permits() != SOURCE_SLOTS
                || now.saturating_duration_since(source.seen) < SOURCE_IDLE
        });
        self.next_sweep = Some(now + Duration::from_secs(1));
    }
    pub(crate) fn try_admit(&mut self, ip: IpAddr, now: Instant) -> Option<OwnedSemaphorePermit> {
        let group = SourceGroup::from(ip);
        if !self.sources.contains_key(&group) {
            if self.sources.len() >= MAX_SOURCES || self.next_sweep.is_none_or(|next| now >= next) {
                self.sweep(now);
            }
            if self.sources.len() >= MAX_SOURCES {
                return None;
            }
        }
        let source = self.sources.entry(group).or_insert_with(|| Source {
            slots: Arc::new(Semaphore::new(SOURCE_SLOTS)),
            rate: TokenBucket::new(SOURCE_BURST, SOURCE_REFILL, now),
            seen: now,
        });
        let slot = source.slots.clone().try_acquire_owned().ok()?;
        // Returning a concurrency slot never returns spent rate credit.
        if !source.rate.take(now) {
            return None;
        }
        source.seen = now;
        Some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(last: u32) -> IpAddr {
        IpAddr::V4((0x0a000000 + last).into())
    }

    #[test]
    fn one_source_cannot_occupy_other_sources_slots_and_eof_releases() {
        let now = Instant::now();
        let mut admission = SourceAdmission::new();
        let slots: Vec<_> = (0..SOURCE_SLOTS)
            .map(|_| admission.try_admit(ip(1), now).unwrap())
            .collect();
        assert!(admission.try_admit(ip(1), now).is_none());
        assert!(admission.try_admit(ip(2), now).is_some());
        drop(slots);
        assert!(admission.try_admit(ip(1), now).is_some());
    }

    #[test]
    fn mapped_v4_and_rotated_v6_addresses_share_source_budget() {
        let now = Instant::now();
        let mut admission = SourceAdmission::new();
        let v4 = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..SOURCE_SLOTS)
            .map(|_| admission.try_admit(v4, now).unwrap())
            .collect();
        assert!(admission
            .try_admit("::ffff:192.0.2.1".parse().unwrap(), now)
            .is_none());
        drop(held);
        let held: Vec<_> = (1..=SOURCE_SLOTS)
            .map(|i| {
                admission
                    .try_admit(format!("2001:db8:1:2::{i}").parse().unwrap(), now)
                    .unwrap()
            })
            .collect();
        assert!(admission
            .try_admit("2001:db8:1:2::ffff".parse().unwrap(), now)
            .is_none());
        assert!(admission
            .try_admit("2001:db8:1:3::1".parse().unwrap(), now)
            .is_some());
        drop(held);
    }

    #[test]
    fn rapid_completed_handshakes_do_not_refund_source_rate() {
        let now = Instant::now();
        let mut admission = SourceAdmission::new();
        for _ in 0..SOURCE_BURST {
            drop(admission.try_admit(ip(1), now).unwrap());
        }
        assert!(admission.try_admit(ip(1), now).is_none());
        assert!(admission.try_admit(ip(2), now).is_some());
        assert!(admission.try_admit(ip(1), now + SOURCE_REFILL).is_some());
        assert!(admission.try_admit(ip(1), now + SOURCE_REFILL).is_none());
    }

    #[test]
    fn inactive_source_state_expires_without_another_source_connecting() {
        let now = Instant::now();
        let mut admission = SourceAdmission::new();
        drop(admission.try_admit(ip(1), now).unwrap());
        admission.sweep(now + SOURCE_IDLE - Duration::from_nanos(1));
        assert_eq!(admission.sources.len(), 1);
        admission.sweep(now + SOURCE_IDLE);
        assert!(admission.sources.is_empty());
    }

    #[test]
    fn bounded_accounting_reclaims_expired_idle_but_not_live_sources() {
        let now = Instant::now();
        let mut admission = SourceAdmission::new();
        let live = admission.try_admit(ip(0), now).unwrap();
        for index in 1..MAX_SOURCES {
            drop(admission.try_admit(ip(index as u32), now).unwrap());
        }
        assert_eq!(admission.sources.len(), MAX_SOURCES);
        assert!(admission.try_admit(ip(MAX_SOURCES as u32), now).is_none());
        let later = now + SOURCE_IDLE;
        assert!(admission.try_admit(ip(MAX_SOURCES as u32), later).is_some());
        assert_eq!(admission.sources.len(), 2);
        // The original source's live permit remains part of its same semaphore.
        let additional: Vec<_> = (1..SOURCE_SLOTS)
            .map(|_| admission.try_admit(ip(0), later).unwrap())
            .collect();
        assert!(admission.try_admit(ip(0), later).is_none());
        drop((live, additional));
    }
}
