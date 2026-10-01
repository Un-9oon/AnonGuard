use rand::rngs::OsRng;
use rand::Rng;
use rand_distr::{Distribution, Exp};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{debug, error, info};

/// A Traffic Chaffing Engine that injects fake SOCKS5 TCP streams locally
/// to confuse Deep Learning (DL) Website Fingerprinting classifiers.
/// It mimics a user browsing a decoy site concurrently.
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
                ("1.1.1.1", 443), // Cloudflare
                ("8.8.8.8", 443), // Google
                ("9.9.9.9", 443), // Quad9
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

    async fn run_loop(&self) {
        loop {
            // Wait for a random interval modeled by an exponential distribution
            let lambda = 1.0 / self.mean_chaff_interval.as_secs_f64();
            let exp = Exp::new(lambda).unwrap();
            let delay_secs = exp.sample(&mut OsRng).clamp(1.0, 30.0);
            sleep(Duration::from_secs_f64(delay_secs)).await;

            debug!("[AnonGuard Chaffing] Injecting decoy stream to hide real traffic...");
            self.inject_decoy_stream().await;
        }
    }

    async fn inject_decoy_stream(&self) {
        // Connect to the local SOCKS5 proxy
        let mut stream = match TcpStream::connect(&self.proxy_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "[AnonGuard Chaffing] Failed to connect to local proxy: {}",
                    e
                );
                return;
            }
        };

        // Select a random decoy target
        let target_idx = OsRng.gen_range(0..self.decoy_targets.len());
        let (host, port) = self.decoy_targets[target_idx];

        // Perform SOCKS5 Handshake
        // 1. Greeting
        if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
            return;
        }
        let mut auth_resp = [0u8; 2];
        if stream.read_exact(&mut auth_resp).await.is_err() || auth_resp[1] != 0x00 {
            return;
        }

        // 2. Connection Request (IPv4 or Domain Name)
        // We just use IPv4 targets for simplicity in decoy traffic
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        let ip_parts: Vec<u8> = host.split('.').map(|s| s.parse().unwrap()).collect();
        req.extend_from_slice(&ip_parts);
        req.push((port >> 8) as u8);
        req.push((port & 0xFF) as u8);

        if stream.write_all(&req).await.is_err() {
            return;
        }

        let mut conn_resp = [0u8; 10];
        if stream.read_exact(&mut conn_resp).await.is_err() || conn_resp[1] != 0x00 {
            debug!("[AnonGuard Chaffing] Proxy rejected decoy SOCKS5 connection");
            return;
        }

        // 3. Connection established! Send fake TLS/HTTP noise
        let mut fake_data = vec![0u8; OsRng.gen_range(500..4000)];
        OsRng.fill(&mut fake_data[..]);

        // Send a burst
        if stream.write_all(&fake_data).await.is_err() {
            return;
        }

        // Wait a little bit to simulate downloading, then randomly drop or read
        sleep(Duration::from_millis(OsRng.gen_range(200..1500))).await;

        let mut response = [0u8; 1024];
        let _ = stream.read(&mut response).await; // Consume incoming dummy data

        debug!("[AnonGuard Chaffing] Decoy stream completed successfully");
    }
}
