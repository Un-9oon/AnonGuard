//! Bounded context reservations; initialization never holds the shared map lock.
use std::{collections::HashMap, future::Future, sync::Arc};
use tokio::sync::{Mutex, OnceCell};

type Slot<T> = Arc<OnceCell<Result<Arc<T>, String>>>;

pub(super) struct SessionCache<T> {
    slots: Mutex<HashMap<[u8; 32], Slot<T>>>,
    maximum: usize,
}
impl<T> SessionCache<T> {
    pub fn new(maximum: usize) -> Self {
        assert!(maximum > 0);
        Self {
            slots: Mutex::new(HashMap::new()),
            maximum,
        }
    }
    pub async fn get_or_start<F, Fut>(
        &self,
        key: [u8; 32],
        alive: impl Fn(&T) -> bool,
        start: F,
    ) -> Result<Arc<T>, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, String>>,
    {
        let slot = {
            let mut slots = self.slots.lock().await;
            // Pending initializers retain their reservation. Failed/completed
            // sessions can be reclaimed; different contexts are never merged.
            slots.retain(|_, slot| match slot.get() {
                Some(result) => result.as_ref().is_ok_and(|value| alive(value)),
                None => Arc::strong_count(slot) > 1,
            });
            if !slots.contains_key(&key) && slots.len() >= self.maximum {
                return Err("Privacy context limit reached".into());
            }
            slots
                .entry(key)
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };
        // OnceCell shares one initializer among same-context requests. If that
        // future is cancelled a live waiter may retry; an abandoned reservation
        // is reclaimed on the next lookup. Successful sessions stay cache-owned.
        slot.get_or_init(|| async { start().await.map(Arc::new) })
            .await
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn slow_context_does_not_block_other_context_and_pending_counts_toward_limit() {
        let cache = Arc::new(SessionCache::new(2));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let worker = {
            let (cache, entered, release) = (cache.clone(), entered.clone(), release.clone());
            tokio::spawn(async move {
                cache
                    .get_or_start(
                        [1; 32],
                        |_| true,
                        || async {
                            entered.notify_one();
                            release.notified().await;
                            Ok(1)
                        },
                    )
                    .await
            })
        };
        entered.notified().await;
        let second = tokio::time::timeout(
            Duration::from_secs(1),
            cache.get_or_start([2; 32], |_| true, || async { Ok(2) }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(*second, 2);
        assert!(cache
            .get_or_start([3; 32], |_| true, || async { Ok(3) })
            .await
            .is_err());
        release.notify_one();
        assert_eq!(*worker.await.unwrap().unwrap(), 1);
    }

    #[tokio::test]
    async fn same_context_shares_one_session_and_failed_slots_are_reclaimed() {
        let cache = SessionCache::new(1);
        let calls = AtomicUsize::new(0);
        let start = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(7)
        };
        let (a, b) = tokio::join!(
            cache.get_or_start([1; 32], |_| true, start),
            cache.get_or_start([1; 32], |_| true, start)
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cache
            .get_or_start([2; 32], |_| false, || async { Err("setup failed".into()) })
            .await
            .is_err());
        assert_eq!(
            *cache
                .get_or_start([3; 32], |_| true, || async { Ok(3) })
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn cancelled_initializer_does_not_permanently_exhaust_context_budget() {
        let cache = Arc::new(SessionCache::<u8>::new(1));
        let entered = Arc::new(Notify::new());
        let worker = {
            let (cache, entered) = (cache.clone(), entered.clone());
            tokio::spawn(async move {
                cache
                    .get_or_start(
                        [1; 32],
                        |_| true,
                        || async {
                            entered.notify_one();
                            std::future::pending().await
                        },
                    )
                    .await
            })
        };
        entered.notified().await;
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        assert_eq!(
            *cache
                .get_or_start([2; 32], |_| true, || async { Ok(2) })
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            *cache
                .get_or_start([1; 32], |_| false, || async { Ok(1) })
                .await
                .unwrap(),
            1
        );
    }
}
