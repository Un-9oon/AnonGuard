//! Standalone CLI daemon for the AnonGuard engine.

use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use anonguard::core::GuardConfig;
use anonguard::gateway::GatewayServer;
use anonguard::kernel::KillSwitchController;
use anonguard::mesh::ProxyPool;

#[derive(Parser, Debug)]
#[command(name = "anonguard-daemon", version = "0.1.0", about = "AnonGuard Standalone Anonymity Gateway")]
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

    let mut config = GuardConfig::default();
    config.listen_addr = args.listen;
    config.enable_jitter = args.jitter;
    config.jitter_lambda = args.jitter_lambda;

    let pool = ProxyPool::new();

    if let Some(file_path) = args.pool {
        match pool.load_file(&file_path).await {
            Ok(count) => info!(count = count, path = %file_path.display(), "[AnonGuard] Loaded proxies from file"),
            Err(e) => tracing::error!(error = %e, "[AnonGuard] Failed to load proxy file"),
        }
    }

    if let Some(inline) = args.proxy {
        let _ = pool.add_proxy(&inline).await;
        info!(proxy = %inline, "[AnonGuard] Added inline proxy to pool");
    }

    let kill_switch = KillSwitchController::new();
    let gateway = GatewayServer::new(config, pool, kill_switch);

    gateway.run().await?;
    Ok(())
}
