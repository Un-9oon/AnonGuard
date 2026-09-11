//! Tokio asynchronous local gateway server listening on 127.0.0.1:9050.

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::core::GuardConfig;
use crate::kernel::KillSwitchController;
use crate::mesh::ProxyPool;
use crate::morphing::PoissonJitter;

pub struct GatewayServer {
    config: GuardConfig,
    pool: ProxyPool,
    kill_switch: KillSwitchController,
    jitter: Option<PoissonJitter>,
}

impl GatewayServer {
    pub fn new(config: GuardConfig, pool: ProxyPool, kill_switch: KillSwitchController) -> Self {
        let jitter = if config.enable_jitter {
            Some(PoissonJitter::new(config.jitter_lambda, 5.0, 45.0))
        } else {
            None
        };

        Self {
            config,
            pool,
            kill_switch,
            jitter,
        }
    }

    /// Starts the asynchronous listener loop.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!(
            listen_addr = %self.config.listen_addr,
            "[AnonGuard Gateway] Active and guarded. Listening for client connections..."
        );

        loop {
            // If kill switch is active, do not accept new connections
            if self.kill_switch.is_tripped() {
                warn!("[AnonGuard Gateway] Kill switch active: refusing incoming connections.");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                continue;
            }

            let (client_stream, client_addr) = listener.accept().await?;
            let pool = self.pool.clone();
            let kill_switch = self.kill_switch.clone();
            let jitter = self.jitter.clone();

            tokio::spawn(async move {
                if kill_switch.is_tripped() {
                    return;
                }

                if let Some(j) = jitter {
                    j.apply().await;
                }

                if let Some(upstream_node) = pool.get_next().await {
                    let target_addr = format!("{}:{}", upstream_node.host, upstream_node.port);
                    match TcpStream::connect(&target_addr).await {
                        Ok(mut upstream_stream) => {
                            let mut client = client_stream;
                            let _ = copy_bidirectional(&mut client, &mut upstream_stream).await;
                        }
                        Err(e) => {
                            error!(error = %e, target = %target_addr, "[AnonGuard Gateway] Upstream connection failed");
                            pool.rotate_on_block(&upstream_node.raw_url).await;
                        }
                    }
                } else {
                    warn!(client = %client_addr, "[AnonGuard Gateway] No upstream proxies available in pool");
                }
            });
        }
    }
}
