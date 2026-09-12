//! Tokio asynchronous local gateway server listening on 127.0.0.1:9050.

use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::core::GuardConfig;
use crate::kernel::KillSwitchController;
use crate::mesh::ProxyPool;
use crate::morphing::{PoissonJitter, LorenzAttractor, QuantumRmtEngine, QuantumEnsemble, JitterEngine, morph_bidirectional};
use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
use crate::onion::circuit::{derive_hop_keys, OnionCircuit};
use rand::rngs::OsRng;
use x25519_dalek::EphemeralSecret;

pub struct GatewayServer {
    config: GuardConfig,
    pool: ProxyPool,
    kill_switch: KillSwitchController,
    jitter: Option<JitterEngine>,
}

impl GatewayServer {
    pub fn new(config: GuardConfig, pool: ProxyPool, kill_switch: KillSwitchController) -> Self {
        let jitter = if config.enable_quantum {
            let ensemble = if config.quantum_ensemble.to_lowercase() == "gue" {
                QuantumEnsemble::GUE
            } else {
                QuantumEnsemble::GOE
            };
            Some(JitterEngine::Quantum(QuantumRmtEngine::new(ensemble, 1.5, 1024)))
        } else if config.enable_chaos {
            Some(JitterEngine::Chaos(LorenzAttractor::new(
                config.chaos_sigma,
                config.chaos_rho,
                config.chaos_beta,
                0.01,
            )))
        } else if config.enable_jitter {
            Some(JitterEngine::Poisson(PoissonJitter::new(
                config.jitter_lambda,
                5.0,
                45.0,
            )))
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

                let mut client = client_stream;

                // 1. Intercept SOCKS5 from local client to find target
                let (target_host, target_port) =
                    match crate::gateway::chain::intercept_socks5_request(&mut client).await {
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
                            info!(
                                "Relay Mode: Forwarding traffic to {}:{}",
                                target_host, target_port
                            );
                            let _ = morph_bidirectional(
                                &mut client,
                                &mut target_stream,
                                jitter.clone(),
                            )
                            .await;
                        }
                        Err(e) => {
                            error!(
                                "Relay Mode: Failed to connect to target {}: {}",
                                target_addr, e
                            );
                        }
                    }
                } else {
                    // Client Mode: Select dynamic proxy chain (enforcing subnet diversity if enabled)
                    let chain = if config.enable_onion_routing || config.enforce_subnet_diversity {
                        pool.get_diverse_onion_chain(
                            config.min_chain_length.max(3),
                            config.max_chain_length.max(3),
                            config.enforce_subnet_diversity,
                        )
                        .await
                    } else {
                        pool.get_random_chain(config.min_chain_length, config.max_chain_length)
                            .await
                    };
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
                            if node.raw_url.starts_with("reverse://") {
                                let node_id = node.host.clone();
                                let tracker_url = config
                                    .tracker_url
                                    .as_ref()
                                    .expect("tracker_url required for reverse")
                                    .trim_start_matches("http://")
                                    .to_string();
                                match TcpStream::connect(&tracker_url).await {
                                    Ok(mut s) => {
                                        use tokio::io::{
                                            AsyncBufReadExt, AsyncWriteExt, BufReader,
                                        };
                                        let payload = format!("CONNECT_REVERSE {}\n", node_id);
                                        let _ = s.write_all(payload.as_bytes()).await;
                                        let mut reader = BufReader::new(s);
                                        let mut resp = String::new();
                                        if reader.read_line(&mut resp).await.is_ok() {
                                            if resp.trim() == "OK" {
                                                current_stream = Some(reader.into_inner());
                                            } else {
                                                error!(
                                                    "Tracker rejected CONNECT_REVERSE: {}",
                                                    resp
                                                );
                                                pool.rotate_on_block(&node.raw_url).await;
                                                return;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to connect to tracker {}: {}",
                                            tracker_url, e
                                        );
                                        pool.rotate_on_block(&node.raw_url).await;
                                        return;
                                    }
                                }
                            } else {
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
                            match crate::gateway::chain::socks5_connect_through(
                                s, &next_host, next_port,
                            )
                            .await
                            {
                                Ok(s_new) => {
                                    current_stream = Some(s_new);
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to negotiate tunnel at node {}: {}",
                                        node.host, e
                                    );
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
                        info!(
                            "Established {}-hop onion tunnel to {}:{}",
                            chain.len(),
                            target_host,
                            target_port
                        );

                        if config.enable_onion_routing {
                            let circuit_id: u32 = rand::random();
                            let mut circuit = OnionCircuit::new(circuit_id);
                            let mut exit_mac = [0u8; 32];
                            for hop_idx in 0..chain.len() {
                                let client_secret = EphemeralSecret::random_from_rng(OsRng);
                                let hop_secret = EphemeralSecret::random_from_rng(OsRng);
                                let pub_hop = x25519_dalek::PublicKey::from(&hop_secret);
                                let shared = client_secret.diffie_hellman(&pub_hop);
                                let (fwd, bwd, mac) = derive_hop_keys(shared.as_bytes(), hop_idx as u8);
                                if hop_idx == chain.len() - 1 {
                                    exit_mac = mac;
                                }
                                circuit.add_hop(fwd, bwd, mac);
                            }

                            info!(
                                circuit_id = circuit_id,
                                hops = chain.len(),
                                "Activating 3-hop layered ChaCha20/Poly1305 onion encryption on tunnel"
                            );

                            let _ = stream_onion_circuit(
                                &mut client,
                                &mut upstream_stream,
                                circuit,
                                exit_mac,
                                jitter.clone(),
                            )
                            .await;
                        } else {
                            let _ =
                                morph_bidirectional(&mut client, &mut upstream_stream, jitter.clone())
                                    .await;
                        }
                    }
                }
            });
        }
    }

    pub async fn run_reverse_relay(
        &self,
        tracker_url: &str,
        node_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let host_port = tracker_url.trim_start_matches("http://");
        info!("[AnonGuard Reverse Relay] Active and guarded. Maintaining outbound pool to Tracker: {}", host_port);

        // Keep a pool of 3 connections
        for _ in 0..3 {
            let hp = host_port.to_string();
            let nid = node_id.to_string();
            let jitter = self.jitter.clone();

            tokio::spawn(async move {
                loop {
                    match TcpStream::connect(&hp).await {
                        Ok(mut stream) => {
                            use tokio::io::AsyncWriteExt;
                            let now = crate::mesh::sybil::current_timestamp_secs();
                            let nonce = crate::mesh::sybil::solve_pow(&nid, now, 12);
                            let payload = format!("REGISTER_REVERSE {} {} {}\n", nid, now, nonce);
                            if stream.write_all(payload.as_bytes()).await.is_ok() {
                                // Wait for the tracker to send data (meaning a client has connected to this stream)
                                // We peek 1 byte to see if data arrived. If so, it's a SOCKS5 client!
                                let mut buf = [0u8; 1];
                                if stream.peek(&mut buf).await.is_ok() {
                                    info!("Reverse Relay: Received incoming client connection from tracker!");

                                    // Process exactly like a Relay Mode client
                                    let (target_host, target_port) =
                                        match crate::gateway::chain::intercept_socks5_request(
                                            &mut stream,
                                        )
                                        .await
                                        {
                                            Ok(res) => res,
                                            Err(e) => {
                                                error!("Reverse Relay: Failed to intercept client SOCKS5 handshake: {}", e);
                                                continue; // reconnect to refill pool
                                            }
                                        };

                                    let target_addr = format!("{}:{}", target_host, target_port);
                                    match TcpStream::connect(&target_addr).await {
                                        Ok(mut target_stream) => {
                                            info!(
                                                "Reverse Relay: Forwarding traffic to {}:{}",
                                                target_host, target_port
                                            );
                                            let _ = morph_bidirectional(
                                                &mut stream,
                                                &mut target_stream,
                                                jitter.clone(),
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            error!(
                                                "Reverse Relay: Failed to connect to target {}: {}",
                                                target_addr, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to connect to Tracker: {}", e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        }
                    }
                }
            });
        }

        // Block forever
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Streams bidirectional client TCP traffic over an authenticated 3-hop OnionCircuit.
/// Outbound traffic is chunked into <= 999 byte slices, encapsulated into 1024-byte OnionCells,
/// wrapped in 3 layers of ChaCha20 encryption with a 16-byte Poly1305 MAC, and sent upstream.
/// Inbound traffic is read in 1024-byte cells, unwrapped across all 3 layers, verified with Poly1305,
/// and forwarded to the local client.
pub async fn stream_onion_circuit(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    circuit: OnionCircuit,
    exit_mac_key: [u8; 32],
    jitter: Option<JitterEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    let circuit = Arc::new(Mutex::new(circuit));
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let circuit_fwd = circuit.clone();
    let jitter_fwd = jitter.clone();
    let exit_mac_fwd = exit_mac_key;

    let fwd = async move {
        let mut buf = [0u8; PAYLOAD_SIZE];
        let stream_id = 1u16;
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            let cell = {
                let guard = circuit_fwd.lock().await;
                OnionCell::new(
                    guard.circuit_id,
                    CellCommand::Data,
                    stream_id,
                    &buf[..n],
                    &exit_mac_fwd,
                )
            };

            let wire_buffer = {
                let mut guard = circuit_fwd.lock().await;
                guard.wrap_forward(&cell)
            };

            if let Some(ref j) = jitter_fwd {
                j.apply_delay().await;
            }

            if upstream_write.write_all(&wire_buffer).await.is_err() {
                break;
            }
        }
        let _ = upstream_write.shutdown().await;
    };

    let circuit_bwd = circuit.clone();
    let exit_mac_bwd = exit_mac_key;
    let bwd = async move {
        let mut wire_buffer = [0u8; ONION_CELL_SIZE];
        loop {
            if upstream_read.read_exact(&mut wire_buffer).await.is_err() {
                break;
            }

            let cell_res = {
                let mut guard = circuit_bwd.lock().await;
                guard.unwrap_backward(&mut wire_buffer)
            };

            match cell_res {
                Ok(cell) => {
                    if !cell.is_mac_valid(&exit_mac_bwd) {
                        warn!("Dropped return onion cell: Poly1305 MAC tag mismatch");
                        continue;
                    }

                    match cell.command {
                        CellCommand::Data => {
                            let len = (cell.length as usize).min(cell.payload.len());
                            if client_write.write_all(&cell.payload[..len]).await.is_err() {
                                break;
                            }
                        }
                        CellCommand::Destroy => break,
                        _ => {}
                    }
                }
                Err(e) => {
                    warn!("Failed to unwrap backward onion cell: {}", e);
                    break;
                }
            }
        }
        let _ = client_write.shutdown().await;
    };

    tokio::select! {
        _ = fwd => {},
        _ = bwd => {},
    }

    Ok(())
}
