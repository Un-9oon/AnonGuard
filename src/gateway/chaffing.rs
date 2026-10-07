use rand::rngs::OsRng;
use rand::Rng;
use rand_distr::{Distribution, Exp};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info};

/// Experimental decoy traffic generator. Classifier resistance is unverified.
/// Decoys use the configured proxy and do not provide traffic-analysis guarantees.
pub struct ChaffingEngine {
    proxy_addr: String,
    decoy_targets: Vec<(&'static str, u16)>,
    mean_chaff_interval: Duration,
}

impl ChaffingEngine {
    pub fn new(proxy_addr: String) -> Self {
        Self {
            proxy_addr,
            decoy_targets: vec![
                ("en.wikipedia.org", 443), // Wikipedia
                ("www.google.com", 443),   // Google
                ("www.github.com", 443),   // GitHub
                ("www.reddit.com", 443),   // Reddit
                ("www.amazon.com", 443),   // Amazon
            ],
            mean_chaff_interval: Duration::from_secs(10), // Spawn a decoy connection on average every 10 seconds
        }
    }

    /// Spawns the Chaffing Engine in the background
    pub fn spawn(self) {
        tokio::spawn(async move {
            info!(
                "[AnonGuard Chaffing] Engine started on local proxy {}",
                self.proxy_addr
            );
            self.run_loop().await;
        });
    }

    pub(crate) async fn run_loop(&self) {
        loop {
            // Wait for a random interval modeled by an exponential distribution
            let lambda = 1.0 / self.mean_chaff_interval.as_secs_f64();
            // BUG-03 FIX: Exp::new() fails if lambda <= 0 or is NaN/inf.
            // Use a safe fallback of 0.1 (mean 10s) instead of panicking.
            let exp = Exp::new(lambda)
                .unwrap_or_else(|_| Exp::new(0.1).expect("safe: 0.1 is a valid Exp rate"));
            let delay_secs = exp.sample(&mut OsRng).clamp(1.0, 30.0);
            sleep(Duration::from_secs_f64(delay_secs)).await;

            debug!("[AnonGuard Chaffing] Injecting decoy stream to hide real traffic...");
            self.inject_decoy_stream().await;
        }
    }

    async fn inject_decoy_stream(&self) {
        if timeout(Duration::from_secs(15), self.send_decoy())
            .await
            .is_err()
        {
            debug!("[AnonGuard Chaffing] Decoy operation timed out");
        }
    }

    async fn send_decoy(&self) {
        let Some(&(host, port)) = self.decoy_targets.get(if self.decoy_targets.is_empty() {
            0
        } else {
            OsRng.gen_range(0..self.decoy_targets.len())
        }) else {
            return;
        };
        let stream = match TcpStream::connect(&self.proxy_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "[AnonGuard Chaffing] Failed to connect to local proxy: {}",
                    e
                );
                return;
            }
        };
        let mut stream = match super::chain::socks5_connect_through(stream, host, port, true).await
        {
            Ok(s) => s,
            Err(_) => {
                debug!("[AnonGuard Chaffing] Proxy rejected decoy SOCKS5 connection");
                return;
            }
        };
        let mut fake_data = vec![0u8; OsRng.gen_range(500..4000)];
        OsRng.fill(&mut fake_data[..]);
        if stream.write_all(&fake_data).await.is_err() {
            return;
        }
        sleep(Duration::from_millis(OsRng.gen_range(200..1500))).await;
        let mut response = [0u8; 1024];
        let _ = stream.read(&mut response).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn decoy_uses_remote_dns_and_handles_ipv6_bound_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let engine = ChaffingEngine {
            proxy_addr: listener.local_addr().unwrap().to_string(),
            decoy_targets: vec![("local.test", 443)],
            mean_chaff_interval: Duration::from_secs(10),
        };
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 17];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..5], &[5, 1, 0, 3, 10]);
            assert_eq!(&request[5..15], b"local.test");
            assert_eq!(&request[15..], &443u16.to_be_bytes());
            let mut reply = vec![5, 0, 0, 4];
            reply.extend_from_slice(&[0; 18]);
            stream.write_all(&reply).await.unwrap();
            let mut data = [0; 500];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(b"reply").await.unwrap();
        });
        timeout(Duration::from_secs(5), engine.inject_decoy_stream())
            .await
            .unwrap();
        proxy.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_proxy_has_bounded_decoy_lifetime() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let engine = ChaffingEngine::new(listener.local_addr().unwrap().to_string());
        let task = tokio::spawn(async move { engine.inject_decoy_stream().await });
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        peer.read_exact(&mut greeting).await.unwrap();
        tokio::time::advance(Duration::from_secs(16)).await;
        task.await.unwrap();
        assert_eq!(peer.read(&mut greeting).await.unwrap(), 0);
    }
}
