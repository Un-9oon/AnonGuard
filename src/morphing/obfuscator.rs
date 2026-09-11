use crate::morphing::{LorenzAttractor, PoissonJitter};
use rand::Rng;
use std::io::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone)]
pub enum JitterEngine {
    Poisson(PoissonJitter),
    Chaos(LorenzAttractor),
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
    // If no jitter is configured, fallback to high-speed zero-copy standard bidirectional transfer.
    if jitter.is_none() {
        return tokio::io::copy_bidirectional(a, b).await;
    }

    let j = jitter.unwrap();
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
                                rand::thread_rng().gen_range(50..=std::cmp::min(data.len(), 1500))
                            }
                            JitterEngine::Chaos(c) => c.sample_shard_size(data.len()),
                        };
                        let (chunk, rest) = data.split_at(std::cmp::min(shard_len, data.len()));
                        data = rest;

                        match &j1 {
                            JitterEngine::Poisson(p) => p.apply().await,
                            JitterEngine::Chaos(c) => c.apply_delay().await,
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
                                rand::thread_rng().gen_range(50..=std::cmp::min(data.len(), 1500))
                            }
                            JitterEngine::Chaos(c) => c.sample_shard_size(data.len()),
                        };
                        let (chunk, rest) = data.split_at(std::cmp::min(shard_len, data.len()));
                        data = rest;

                        match &j2 {
                            JitterEngine::Poisson(p) => p.apply().await,
                            JitterEngine::Chaos(c) => c.apply_delay().await,
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
        transferred
    };

    let (a_to_b, b_to_a) = tokio::join!(a_to_b_task, b_to_a_task);
    Ok((a_to_b, b_to_a))
}
