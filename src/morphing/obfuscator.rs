use crate::morphing::{AdversarialPerturbEngine, LorenzAttractor, PoissonJitter, RmtTimingEngine};
use rand::Rng;
use std::io::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone)]
pub enum JitterEngine {
    Poisson(PoissonJitter),
    Chaos(LorenzAttractor),
    Rmt(RmtTimingEngine),
    /// Step 3: Dynamic Adversarial Perturbation — FGSM-inspired micro-delays
    /// that push each traffic trace out-of-distribution for DL WF classifiers.
    Adversarial(AdversarialPerturbEngine),
}

impl JitterEngine {
    /// Experimental onion scheduling interval, independent of DATA/ACK/DUMMY.
    /// Bounded to prevent unbounded stalls or high-rate cover traffic.
    pub fn onion_interval(&self) -> std::time::Duration {
        let sampled = match self {
            Self::Rmt(engine) => std::time::Duration::from_micros(engine.next_pacing_delay_us()),
            Self::Poisson(engine) => engine.sample_delay(),
            Self::Chaos(engine) => engine.sample_delay(),
            // This research engine has no traffic-independent sampling contract.
            Self::Adversarial(_) => std::time::Duration::from_millis(20),
        };
        sampled.clamp(
            std::time::Duration::from_millis(5),
            std::time::Duration::from_millis(100),
        )
    }

    pub async fn apply_delay(&self) {
        match self {
            JitterEngine::Poisson(p) => p.apply().await,
            JitterEngine::Chaos(c) => c.apply_delay().await,
            JitterEngine::Rmt(q) => {
                let delay = q.next_delay_us();
                tokio::time::sleep(std::time::Duration::from_micros(delay)).await;
            }
            JitterEngine::Adversarial(a) => {
                // Clone then apply — the shared Arc counters propagate correctly.
                a.clone().apply().await;
            }
        }
    }
}

/// A continuous stream morphing engine that replaces `tokio::io::copy_bidirectional`.
/// It shards data into random chunks and injects Poisson delays to defeat timing correlation.
pub async fn morph_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    jitter: Option<JitterEngine>,
) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    morph_bidirectional_guarded(a, b, jitter, None).await
}

/// Continuous stream morphing engine with active fail-closed KillSwitch cancellation.
pub async fn morph_bidirectional_guarded<A, B>(
    a: &mut A,
    b: &mut B,
    jitter: Option<JitterEngine>,
    kill_switch: Option<crate::kernel::KillSwitchController>,
) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if let Some(ref ks) = kill_switch {
        if ks.is_tripped() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Kill switch tripped: refusing stream",
            ));
        }
    }

    // If no jitter is configured, run copy with killswitch monitor
    if jitter.is_none() {
        if let Some(ks) = kill_switch {
            let mut rx = ks.subscribe();
            return tokio::select! {
                res = tokio::io::copy_bidirectional(a, b) => res,
                _ = async {
                    while rx.changed().await.is_ok() {
                        if *rx.borrow() {
                            break;
                        }
                    }
                } => {
                    tracing::error!("[AnonGuard KillSwitch] TRIPPED! Enforcing zero-leak stream termination.");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "Kill switch tripped mid-stream: stream aborted",
                    ))
                }
            };
        } else {
            return tokio::io::copy_bidirectional(a, b).await;
        }
    }

    let Some(j) = jitter else {
        return tokio::io::copy_bidirectional(a, b).await;
    };
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let j1 = j.clone();
    let j2 = j.clone();

    let a_to_b_task = async move {
        let mut transferred = 0;
        let mut buf = vec![0u8; 32768];
        loop {
            match a_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut data = &buf[..n];
                    while !data.is_empty() {
                        let shard_len = match &j1 {
                            JitterEngine::Poisson(_) => {
                                if data.len() <= 50 {
                                    data.len()
                                } else {
                                    rand::thread_rng()
                                        .gen_range(50..=std::cmp::min(data.len(), 1500))
                                }
                            }
                            JitterEngine::Chaos(c) => c.sample_shard_size(data.len()),
                            JitterEngine::Rmt(q) => {
                                let target = q.next_chunk_size();
                                std::cmp::min(target, data.len())
                            }
                            JitterEngine::Adversarial(_) => {
                                // Use RMT-style random sharding so packet sizes vary
                                if data.len() <= 64 {
                                    data.len()
                                } else {
                                    rand::thread_rng()
                                        .gen_range(64..=std::cmp::min(data.len(), 2048))
                                }
                            }
                        };
                        let (chunk, rest) = data.split_at(std::cmp::min(shard_len, data.len()));
                        data = rest;

                        match &j1 {
                            JitterEngine::Poisson(p) => p.apply().await,
                            JitterEngine::Chaos(c) => c.apply_delay().await,
                            JitterEngine::Rmt(q) => {
                                let delay = q.next_delay_us();
                                tokio::time::sleep(std::time::Duration::from_micros(delay)).await;
                            }
                            JitterEngine::Adversarial(a) => {
                                a.clone().apply().await;
                            }
                        }
                        if b_write.write_all(chunk).await.is_err() {
                            break;
                        }
                        transferred += chunk.len() as u64;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = b_write.shutdown().await;
        transferred
    };

    let b_to_a_task = async move {
        let mut transferred = 0;
        let mut buf = vec![0u8; 32768];
        loop {
            match b_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut data = &buf[..n];
                    while !data.is_empty() {
                        let shard_len = match &j2 {
                            JitterEngine::Poisson(_) => {
                                if data.len() <= 50 {
                                    data.len()
                                } else {
                                    rand::thread_rng()
                                        .gen_range(50..=std::cmp::min(data.len(), 1500))
                                }
                            }
                            JitterEngine::Chaos(c) => c.sample_shard_size(data.len()),
                            JitterEngine::Rmt(q) => {
                                let target = q.next_chunk_size();
                                std::cmp::min(target, data.len())
                            }
                            JitterEngine::Adversarial(_) => {
                                if data.len() <= 64 {
                                    data.len()
                                } else {
                                    rand::thread_rng()
                                        .gen_range(64..=std::cmp::min(data.len(), 2048))
                                }
                            }
                        };
                        let (chunk, rest) = data.split_at(std::cmp::min(shard_len, data.len()));
                        data = rest;

                        match &j2 {
                            JitterEngine::Poisson(p) => p.apply().await,
                            JitterEngine::Chaos(c) => c.apply_delay().await,
                            JitterEngine::Rmt(q) => {
                                let delay = q.next_delay_us();
                                tokio::time::sleep(std::time::Duration::from_micros(delay)).await;
                            }
                            JitterEngine::Adversarial(a) => {
                                a.clone().apply().await;
                            }
                        }
                        if a_write.write_all(chunk).await.is_err() {
                            break;
                        }
                        transferred += chunk.len() as u64;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = a_write.shutdown().await;
        transferred
    };

    if let Some(ks) = kill_switch {
        let mut rx = ks.subscribe();
        tokio::select! {
            (a_to_b, b_to_a) = async { tokio::join!(a_to_b_task, b_to_a_task) } => Ok((a_to_b, b_to_a)),
            _ = async {
                while rx.changed().await.is_ok() {
                    if *rx.borrow() {
                        break;
                    }
                }
            } => {
                tracing::error!("[AnonGuard KillSwitch] TRIPPED! Enforcing zero-leak stream termination.");
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Kill switch tripped mid-stream: stream aborted",
                ))
            }
        }
    } else {
        let (a_to_b, b_to_a) = tokio::join!(a_to_b_task, b_to_a_task);
        Ok((a_to_b, b_to_a))
    }
}
