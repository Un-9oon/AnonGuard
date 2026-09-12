//! Standalone CLI daemon for the AnonGuard engine.

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use anonguard::core::GuardConfig;
use anonguard::gateway::GatewayServer;
use anonguard::kernel::KillSwitchController;
use anonguard::mesh::ProxyPool;

#[derive(Parser, Debug)]
#[command(
    name = "anonguard-daemon",
    version = "0.1.0",
    about = "AnonGuard Standalone Anonymity Gateway"
)]
struct Args {
    /// Local address to bind the gateway listener
    #[arg(short, long, default_value = "127.0.0.1:9050")]
    listen: String,

    /// Path to a text file containing proxy endpoints (one per line)
    #[arg(short, long)]
    pool: Option<PathBuf>,

    /// Inline proxy to load immediately (e.g. socks5://127.0.0.1:1080)
    #[arg(long)]
    proxy: Option<String>,

    /// Enable Poisson timing jitter to defeat NetFlow traffic correlation
    #[arg(long, default_value_t = false)]
    jitter: bool,

    /// Rate parameter (lambda) for Poisson timing jitter
    #[arg(long, default_value_t = 0.05)]
    jitter_lambda: f64,

    /// Enable Chaotic Attractor Morphing
    #[arg(long, default_value_t = false)]
    chaos: bool,

    #[arg(long, default_value_t = 10.0)]
    chaos_sigma: f64,

    #[arg(long, default_value_t = 28.0)]
    chaos_rho: f64,

    #[arg(long, default_value_t = 2.666666)]
    chaos_beta: f64,

    /// Enable Quantum Random Matrix Theory (Q-RMT) Morphing
    #[arg(long, default_value_t = false)]
    quantum: bool,

    /// Quantum Ensemble type: "goe" (Orthogonal) or "gue" (Unitary)
    #[arg(long, default_value = "goe")]
    quantum_ensemble: String,

    /// Run as a SOCKS5 relay node (bypasses proxy pool and connects directly)
    #[arg(short, long, default_value_t = false)]
    relay: bool,

    /// Run as a Directory Authority Tracker
    #[arg(long, default_value_t = false)]
    tracker: bool,

    /// Run as a Reverse Relay Node (Volunteer mode behind NAT)
    #[arg(long, default_value_t = false)]
    reverse_relay: bool,

    /// Tracker URL to announce this relay to (e.g. http://1.2.3.4:8080)
    #[arg(long)]
    announce: Option<String>,

    /// Tracker URL to fetch active nodes from (e.g. http://1.2.3.4:8080)
    #[arg(long)]
    fetch_from: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    info!(
        version = "0.1.0",
        listen_addr = %args.listen,
        "[AnonGuard] Starting Research-Grade Anonymity Gateway..."
    );

    let config = GuardConfig {
        listen_addr: args.listen.clone(),
        enable_jitter: args.jitter,
        jitter_lambda: args.jitter_lambda,
        enable_chaos: args.chaos,
        chaos_sigma: args.chaos_sigma,
        chaos_rho: args.chaos_rho,
        chaos_beta: args.chaos_beta,
        enable_quantum: args.quantum,
        quantum_ensemble: args.quantum_ensemble.clone(),
        relay_mode: args.relay,
        reverse_relay_mode: args.reverse_relay,
        tracker_url: args.fetch_from.clone(),
        ..GuardConfig::default()
    };

    if args.tracker {
        let tracker = anonguard::mesh::TrackerServer::new(args.listen);
        tracker.run().await?;
        return Ok(());
    }

    let pool = ProxyPool::new();

    if let Some(file_path) = args.pool {
        match pool.load_file(&file_path).await {
            Ok(count) => {
                info!(count = count, path = %file_path.display(), "[AnonGuard] Loaded proxies from file")
            }
            Err(e) => tracing::error!(error = %e, "[AnonGuard] Failed to load proxy file"),
        }
    }

    if let Some(inline) = args.proxy {
        let _ = pool.add_proxy(&inline).await;
        info!(proxy = %inline, "[AnonGuard] Added inline proxy to pool");
    }

    if args.relay {
        if let Some(tracker_url) = args.announce.clone() {
            let my_listen = args.listen.clone();
            tokio::spawn(async move {
                // Parse host/port from tracker_url (e.g. http://127.0.0.1:8080)
                let host_port = tracker_url.trim_start_matches("http://");
                let proxy_uri = format!("socks5://{}", my_listen);
                let payload = format!(
                    "POST /register HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}",
                    host_port,
                    proxy_uri.len(),
                    proxy_uri
                );

                loop {
                    if let Ok(mut stream) = tokio::net::TcpStream::connect(host_port).await {
                        use tokio::io::AsyncWriteExt;
                        let _ = stream.write_all(payload.as_bytes()).await;
                        tracing::debug!("Announced presence to tracker {}", tracker_url);
                    } else {
                        tracing::warn!("Failed to announce to tracker {}", tracker_url);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            });
        }
    }

    if !args.relay && !args.reverse_relay {
        if let Some(tracker_url) = args.fetch_from.clone() {
            let pool_clone = pool.clone();
            tokio::spawn(async move {
                let host_port = tracker_url.trim_start_matches("http://");
                let payload = format!("GET /nodes HTTP/1.1\r\nHost: {}\r\n\r\n", host_port);

                loop {
                    if let Ok(mut stream) = tokio::net::TcpStream::connect(host_port).await {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let _ = stream.write_all(payload.as_bytes()).await;

                        let mut resp = vec![0; 4096];
                        if let Ok(n) = stream.read(&mut resp).await {
                            let resp_str = String::from_utf8_lossy(&resp[..n]);
                            if let Some(idx) = resp_str.find("\r\n\r\n") {
                                let body = &resp_str[idx + 4..];
                                // Clear existing nodes and add new ones
                                for line in body.lines() {
                                    let node = line.trim();
                                    if !node.is_empty() {
                                        // Store as reverse:// to signal the engine to use Rendezvous connection
                                        let reverse_uri = format!("reverse://{}:0", node);
                                        let _ = pool_clone.add_proxy(&reverse_uri).await;
                                    }
                                }
                                tracing::debug!("Fetched updated reverse node list from tracker");
                            }
                        }
                    } else {
                        tracing::warn!("Failed to fetch from tracker {}", tracker_url);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(45)).await;
                }
            });
        }
    }

    let kill_switch = KillSwitchController::new();
    let gateway = GatewayServer::new(config, pool, kill_switch);

    if args.reverse_relay {
        if let Some(tracker_url) = args.announce {
            // Generate a random Node ID
            let node_id = format!(
                "Node_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    % 10000
            );
            gateway.run_reverse_relay(&tracker_url, &node_id).await?;
            return Ok(());
        } else {
            tracing::error!("--announce <tracker_url> is required for --reverse-relay");
            return Ok(());
        }
    }

    gateway.run().await?;
    Ok(())
}
