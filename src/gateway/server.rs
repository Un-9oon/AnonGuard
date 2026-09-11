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
            let config = self.config.clone();

            tokio::spawn(async move {
                if kill_switch.is_tripped() {
                    return;
                }

                if let Some(j) = jitter {
                    j.apply().await;
                }

                let mut client = client_stream;
                
                // 1. Intercept SOCKS5 from local client to find target
                let (target_host, target_port) = match crate::gateway::chain::intercept_socks5_request(&mut client).await {
                    Ok(res) => res,
                    Err(e) => {
                        error!("Failed to intercept client SOCKS5 handshake: {}", e);
                        return;
                    }
                };

                if config.relay_mode {
                    // Node Mode: Connect directly to the requested target
                    let target_addr = format!("{}:{}", target_host, target_port);
                    match TcpStream::connect(&target_addr).await {
                        Ok(mut target_stream) => {
                            info!("Relay Mode: Forwarding traffic to {}:{}", target_host, target_port);
                            let _ = copy_bidirectional(&mut client, &mut target_stream).await;
                        }
                        Err(e) => {
                            error!("Relay Mode: Failed to connect to target {}: {}", target_addr, e);
                        }
                    }
                } else {
                    // Client Mode: Select dynamic random proxy chain
                    let chain = pool.get_random_chain(config.min_chain_length, config.max_chain_length).await;
                    if chain.is_empty() {
                        warn!(client = %client_addr, "[AnonGuard Gateway] No upstream proxies available for chain");
                        return;
                    }

                    // 3. Build Onion Tunnel
                    let mut current_stream = None;
                    for (i, node) in chain.iter().enumerate() {
                        let is_first = i == 0;
                        let is_last = i == chain.len() - 1;

                        // If first node, connect raw TCP
                        if is_first {
                            let addr = format!("{}:{}", node.host, node.port);
                            match TcpStream::connect(&addr).await {
                                Ok(s) => current_stream = Some(s),
                                Err(e) => {
                                    error!("Failed to connect to entry node {}: {}", addr, e);
                                    pool.rotate_on_block(&node.raw_url).await;
                                    if config.strict_killswitch {
                                        kill_switch.trip("Entry node connection failure");
                                    }
                                    return;
                                }
                            }
                        }

                        let next_host = if is_last {
                            target_host.clone()
                        } else {
                            chain[i + 1].host.clone()
                        };
                        let next_port = if is_last {
                            target_port
                        } else {
                            chain[i + 1].port
                        };

                        if let Some(s) = current_stream.take() {
                            match crate::gateway::chain::socks5_connect_through(s, &next_host, next_port).await {
                                Ok(s_new) => {
                                    current_stream = Some(s_new);
                                }
                                Err(e) => {
                                    error!("Failed to negotiate tunnel at node {}: {}", node.host, e);
                                    pool.rotate_on_block(&node.raw_url).await;
                                    if config.strict_killswitch {
                                        kill_switch.trip("Tunnel negotiation failure");
                                    }
                                    return;
                                }
                            }
                        }
                    }

                    // 4. Stream data through the completed onion tunnel
                    if let Some(mut upstream_stream) = current_stream {
                        info!("Established {}-hop onion tunnel to {}:{}", chain.len(), target_host, target_port);
                        let _ = copy_bidirectional(&mut client, &mut upstream_stream).await;
                    }
                }
            });
        }
    }
}
