//! Tokio asynchronous local gateway server listening on 127.0.0.1:9050.

use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::core::GuardConfig;
use crate::kernel::KillSwitchController;
use crate::mesh::ProxyPool;
use crate::morphing::{
    morph_bidirectional_guarded, JitterEngine, LorenzAttractor, PoissonJitter, QuantumEnsemble,
    QuantumRmtEngine,
};
use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
use crate::onion::circuit::{
    build_create_cell, decode_extend_payload, encode_extend_payload, handle_create_cell,
    process_created_cell, OnionCircuit, PeelResult,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::EphemeralSecret;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;
pub const MAX_CONCURRENT_PER_IP: u32 = 64;

pub struct GatewayServer {
    config: GuardConfig,
    pool: ProxyPool,
    kill_switch: KillSwitchController,
    jitter: Option<JitterEngine>,
    connection_semaphore: Arc<Semaphore>,
    ip_connections: Arc<RwLock<HashMap<IpAddr, u32>>>,
}

impl GatewayServer {
    pub fn new(config: GuardConfig, pool: ProxyPool, kill_switch: KillSwitchController) -> Self {
        let jitter = if config.enable_quantum {
            let ensemble = if config.quantum_ensemble.to_lowercase() == "gue" {
                QuantumEnsemble::GUE
            } else {
                QuantumEnsemble::GOE
            };
            Some(JitterEngine::Quantum(QuantumRmtEngine::new(
                ensemble, 1.5, 1024,
            )))
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
            connection_semaphore: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_CONNECTIONS)),
            ip_connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Starts the asynchronous listener loop with global and per-IP connection bounds.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!(
            listen_addr = %self.config.listen_addr,
            "[AnonGuard Gateway] Active and guarded. Listening for client connections (DoS limits: max {} concurrent, max {}/IP)...",
            DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            MAX_CONCURRENT_PER_IP
        );

        loop {
            // If kill switch is active, do not accept new connections
            if self.kill_switch.is_tripped() {
                warn!("[AnonGuard Gateway] Kill switch active: refusing incoming connections.");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                continue;
            }

            let (client_stream, client_addr) = listener.accept().await?;
            let client_ip = client_addr.ip();

            // 1. Global connection ceiling (prevent file descriptor/memory exhaustion)
            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        client = %client_addr,
                        "[AnonGuard DoS Defense] Dropped connection: global concurrent limit ({}) reached",
                        DEFAULT_MAX_CONCURRENT_CONNECTIONS
                    );
                    continue;
                }
            };

            // 2. Per-IP connection ceiling (prevent single-client connection flooding)
            {
                let mut ip_map = self.ip_connections.write().await;
                let count = ip_map.entry(client_ip).or_insert(0);
                if *count >= MAX_CONCURRENT_PER_IP {
                    warn!(
                        client = %client_addr,
                        current = *count,
                        limit = MAX_CONCURRENT_PER_IP,
                        "[AnonGuard DoS Defense] Dropped connection: per-IP connection cap exceeded"
                    );
                    continue;
                }
                *count += 1;
            }

            let pool = self.pool.clone();
            let kill_switch = self.kill_switch.clone();
            let jitter = self.jitter.clone();
            let config = self.config.clone();
            let ip_tracker = self.ip_connections.clone();

            tokio::spawn(async move {
                let _permit = permit;

                // RAII guard to decrement per-IP active connection count on disconnect
                struct IpGuard {
                    ip: IpAddr,
                    tracker: Arc<RwLock<HashMap<IpAddr, u32>>>,
                }
                impl Drop for IpGuard {
                    fn drop(&mut self) {
                        let ip = self.ip;
                        let tracker = self.tracker.clone();
                        tokio::spawn(async move {
                            let mut map = tracker.write().await;
                            if let std::collections::hash_map::Entry::Occupied(mut entry) =
                                map.entry(ip)
                            {
                                if *entry.get() <= 1 {
                                    entry.remove();
                                } else {
                                    *entry.get_mut() -= 1;
                                }
                            }
                        });
                    }
                }
                let _ip_guard = IpGuard {
                    ip: client_ip,
                    tracker: ip_tracker,
                };

                if kill_switch.is_tripped() {
                    return;
                }

                let mut client = client_stream;

                if config.relay_mode {
                    let mut peek_buf = [0u8; 1];
                    let is_socks5 = client.peek(&mut peek_buf).await.is_ok() && peek_buf[0] == 0x05;
                    if is_socks5 {
                        if !config.allow_open_socks5 {
                            warn!(
                                client = %client_addr,
                                "Relay Mode: Rejected unauthenticated plain SOCKS5 proxy request on onion relay port (anti-abuse policy)"
                            );
                            return;
                        }

                        let (target_host, target_port) =
                            match crate::gateway::chain::read_socks5_request(&mut client).await {
                                Ok(res) => res,
                                Err(e) => {
                                    error!(
                                        "Relay Mode: Failed to intercept SOCKS5 handshake: {}",
                                        e
                                    );
                                    return;
                                }
                            };

                        let exit_policy = crate::kernel::ExitPolicy::new(config.allow_private_exit);
                        match exit_policy
                            .resolve_and_connect(&target_host, target_port)
                            .await
                        {
                            Ok(mut target_stream) => {
                                info!(
                                    "Relay Mode: Forwarding traffic to {}:{}",
                                    target_host, target_port
                                );
                                let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x00)
                                    .await;
                                let _ = morph_bidirectional_guarded(
                                    &mut client,
                                    &mut target_stream,
                                    jitter.clone(),
                                    Some(kill_switch.clone()),
                                )
                                .await;
                            }
                            Err(e) => {
                                error!(
                                    "Relay Mode: Target {}:{} blocked or unreachable: {}",
                                    target_host, target_port, e
                                );
                                let rep = if e.kind() == std::io::ErrorKind::PermissionDenied {
                                    0x02 // Connection not allowed by ruleset (SSRF/private IP blocked)
                                } else {
                                    0x04 // Host unreachable
                                };
                                let _ = crate::gateway::chain::send_socks5_reply(&mut client, rep)
                                    .await;
                            }
                        }
                    } else {
                        info!("Relay Mode: Processing incoming in-band Onion Cell connection");
                        let exit_policy = crate::kernel::ExitPolicy::new(config.allow_private_exit);
                        // Generate or load the relay's long-term Ed25519 identity key.
                        // In production this should be persisted to disk; here we use an
                        // ephemeral key per-process (stable within one daemon lifetime).
                        let relay_identity_key = Ed25519SigningKey::generate(&mut OsRng);
                        let _ = handle_onion_relay_connection(
                            client,
                            Some(kill_switch.clone()),
                            jitter.clone(),
                            Some(exit_policy),
                            &relay_identity_key,
                        )
                        .await;
                    }
                    return;
                }

                // 1. Intercept SOCKS5 from local client to find target
                let (target_host, target_port) =
                    match crate::gateway::chain::read_socks5_request(&mut client).await {
                        Ok(res) => res,
                        Err(e) => {
                            error!("Failed to intercept client SOCKS5 handshake: {}", e);
                            return;
                        }
                    };

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
                    let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x01).await;
                    return;
                }

                if config.enable_onion_routing {
                    // 3. Authenticated Telescopic Onion Routing
                    // Connect TCP strictly to the entry Guard node (Hop 0).
                    // Zero intermediate SOCKS5 chaining — eliminates path leak completely.
                    let entry_node = &chain[0];
                    let mut guard_stream = if entry_node.raw_url.starts_with("reverse://") {
                        let node_id = entry_node.host.clone();
                        let auth_token = entry_node.username.as_deref().unwrap_or("");
                        let tracker_url = match config.tracker_url.as_ref() {
                            Some(u) => u.trim_start_matches("http://").to_string(),
                            None => {
                                error!("Circuit initiation error: tracker_url required for reverse node connection");
                                let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x01)
                                    .await;
                                return;
                            }
                        };
                        match TcpStream::connect(&tracker_url).await {
                            Ok(mut s) => {
                                use tokio::io::{
                                    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader,
                                };
                                let payload = if !auth_token.is_empty() {
                                    format!("CONNECT_REVERSE {} {}\n", node_id, auth_token)
                                } else {
                                    format!("CONNECT_REVERSE {}\n", node_id)
                                };
                                let _ = s.write_all(payload.as_bytes()).await;
                                let mut reader = BufReader::new(s);
                                let mut resp = String::new();
                                if (&mut reader).take(1024).read_line(&mut resp).await.is_ok()
                                    && resp.trim() == "OK"
                                {
                                    reader.into_inner()
                                } else {
                                    error!(
                                        "Tracker rejected CONNECT_REVERSE for entry node: {}",
                                        resp
                                    );
                                    pool.rotate_on_block(&entry_node.raw_url).await;
                                    let _ =
                                        crate::gateway::chain::send_socks5_reply(&mut client, 0x04)
                                            .await;
                                    return;
                                }
                            }
                            Err(e) => {
                                error!("Failed to connect to tracker {}: {}", tracker_url, e);
                                pool.rotate_on_block(&entry_node.raw_url).await;
                                let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x04)
                                    .await;
                                return;
                            }
                        }
                    } else {
                        let addr = format!("{}:{}", entry_node.host, entry_node.port);
                        match TcpStream::connect(&addr).await {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Failed to connect to entry Guard node {}: {}", addr, e);
                                pool.rotate_on_block(&entry_node.raw_url).await;
                                let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x04)
                                    .await;
                                if config.strict_killswitch {
                                    kill_switch.trip("Entry Guard node connection failure");
                                }
                                return;
                            }
                        }
                    };

                    // Generate circuit ID where highest byte is not 0x05 so Guard peeks != 0x05
                    let mut circuit_id: u32 = rand::random();
                    if (circuit_id >> 24) == 0x05 || (circuit_id >> 24) == 0x00 {
                        circuit_id ^= 0x10000000;
                    }

                    let pinned_identity_keys = pool.get_identity_keys(&chain).await;

                    match build_telescopic_circuit(
                        &mut guard_stream,
                        circuit_id,
                        &chain,
                        &pinned_identity_keys,
                        &target_host,
                        target_port,
                    )
                    .await
                    {
                        Ok(circuit) => {
                            info!(
                                circuit_id = circuit_id,
                                hops = chain.len(),
                                target = %format!("{}:{}", target_host, target_port),
                                "Activating authentic 3-hop layered ChaCha20-Poly1305 AEAD onion circuit to destination"
                            );
                            let _ =
                                crate::gateway::chain::send_socks5_reply(&mut client, 0x00).await;
                            let _ = stream_onion_circuit(
                                &mut client,
                                &mut guard_stream,
                                circuit,
                                jitter.clone(),
                                Some(kill_switch.clone()),
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Failed to negotiate telescopic onion circuit: {}", e);
                            let _ =
                                crate::gateway::chain::send_socks5_reply(&mut client, 0x05).await;
                            if config.strict_killswitch {
                                kill_switch.trip("Telescopic circuit negotiation failure");
                            }
                        }
                    }
                } else {
                    // Plain SOCKS5 multi-proxy chaining (when onion routing is disabled)
                    let mut current_stream = None;
                    for (i, node) in chain.iter().enumerate() {
                        let is_first = i == 0;
                        let is_last = i == chain.len() - 1;

                        if is_first {
                            if node.raw_url.starts_with("reverse://") {
                                let node_id = node.host.clone();
                                let auth_token = node.username.as_deref().unwrap_or("");
                                let tracker_url = match config.tracker_url.as_ref() {
                                    Some(u) => u.trim_start_matches("http://").to_string(),
                                    None => {
                                        error!("Plain SOCKS5 chain error: tracker_url required for reverse node connection");
                                        let _ = crate::gateway::chain::send_socks5_reply(
                                            &mut client,
                                            0x01,
                                        )
                                        .await;
                                        return;
                                    }
                                };
                                match TcpStream::connect(&tracker_url).await {
                                    Ok(mut s) => {
                                        use tokio::io::{
                                            AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader,
                                        };
                                        let payload = if !auth_token.is_empty() {
                                            format!("CONNECT_REVERSE {} {}\n", node_id, auth_token)
                                        } else {
                                            format!("CONNECT_REVERSE {}\n", node_id)
                                        };
                                        let _ = s.write_all(payload.as_bytes()).await;
                                        let mut reader = BufReader::new(s);
                                        let mut resp = String::new();
                                        if (&mut reader)
                                            .take(1024)
                                            .read_line(&mut resp)
                                            .await
                                            .is_ok()
                                            && resp.trim() == "OK"
                                        {
                                            current_stream = Some(reader.into_inner());
                                        } else {
                                            error!("Tracker rejected CONNECT_REVERSE: {}", resp);
                                            pool.rotate_on_block(&node.raw_url).await;
                                            let _ = crate::gateway::chain::send_socks5_reply(
                                                &mut client,
                                                0x04,
                                            )
                                            .await;
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to connect to tracker {}: {}",
                                            tracker_url, e
                                        );
                                        pool.rotate_on_block(&node.raw_url).await;
                                        let _ = crate::gateway::chain::send_socks5_reply(
                                            &mut client,
                                            0x04,
                                        )
                                        .await;
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
                                        let _ = crate::gateway::chain::send_socks5_reply(
                                            &mut client,
                                            0x04,
                                        )
                                        .await;
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
                                s,
                                &next_host,
                                next_port,
                                config.disable_ipv6,
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
                                    let _ =
                                        crate::gateway::chain::send_socks5_reply(&mut client, 0x05)
                                            .await;
                                    if config.strict_killswitch {
                                        kill_switch.trip("Tunnel negotiation failure");
                                    }
                                    return;
                                }
                            }
                        }
                    }

                    if let Some(mut upstream_stream) = current_stream {
                        info!(
                            "Established {}-hop proxy tunnel to {}:{}",
                            chain.len(),
                            target_host,
                            target_port
                        );
                        let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x00).await;
                        let _ = crate::morphing::morph_bidirectional_guarded(
                            &mut client,
                            &mut upstream_stream,
                            jitter.clone(),
                            Some(kill_switch.clone()),
                        )
                        .await;
                    } else {
                        let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x05).await;
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
        // Generate a cryptographically secure authorization token for this reverse relay instance
        let auth_token = format!("{:016x}", rand::random::<u64>());
        info!("[AnonGuard Reverse Relay] Active and guarded (node: {}, token: {}). Maintaining outbound pool to Tracker: {}", node_id, auth_token, host_port);

        // Keep a pool of 3 connections
        for _ in 0..3 {
            let hp = host_port.to_string();
            let nid = node_id.to_string();
            let token = auth_token.clone();
            let jitter = self.jitter.clone();
            let kill_switch = self.kill_switch.clone();
            let pow_difficulty = self.config.pow_difficulty;
            let allow_private_exit = self.config.allow_private_exit;

            tokio::spawn(async move {
                loop {
                    match TcpStream::connect(&hp).await {
                        Ok(mut stream) => {
                            use tokio::io::AsyncWriteExt;
                            let now = crate::mesh::sybil::current_timestamp_secs();
                            let nonce = crate::mesh::sybil::solve_pow(&nid, now, pow_difficulty);
                            let payload =
                                format!("REGISTER_REVERSE {} {} {} {}\n", nid, token, now, nonce);
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

                                    let exit_policy =
                                        crate::kernel::ExitPolicy::new(allow_private_exit);
                                    match exit_policy
                                        .resolve_and_connect(&target_host, target_port)
                                        .await
                                    {
                                        Ok(mut target_stream) => {
                                            info!(
                                                "Reverse Relay: Forwarding traffic to {}:{}",
                                                target_host, target_port
                                            );
                                            let _ = morph_bidirectional_guarded(
                                                &mut stream,
                                                &mut target_stream,
                                                jitter.clone(),
                                                Some(kill_switch.clone()),
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            error!(
                                                "Reverse Relay: Target {}:{} blocked or unreachable: {}",
                                                target_host, target_port, e
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
/// wrapped in 3 layers of ChaCha20 encryption with a 16-byte HMAC-SHA256 MAC, and sent upstream.
/// Inbound traffic is read in 1024-byte cells, unwrapped across all 3 layers, verified with HMAC-SHA256,
/// and forwarded to the local client. Tripping the kill switch immediately aborts active streams.
pub async fn stream_onion_circuit(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    circuit: OnionCircuit,
    jitter: Option<JitterEngine>,
    kill_switch: Option<KillSwitchController>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    let circuit = Arc::new(Mutex::new(circuit));
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let circuit_fwd = circuit.clone();
    let jitter_fwd = jitter.clone();

    let fwd = async move {
        let mut buf = [0u8; PAYLOAD_SIZE];
        let stream_id = 1u16;
        let mut client_seq = 2u32; // Seq 1 was RELAY cell
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            let mut cell = {
                let guard = circuit_fwd.lock().await;
                let seq = client_seq;
                client_seq += 1;
                match OnionCell::new(
                    guard.circuit_id,
                    seq,
                    CellCommand::Data,
                    stream_id,
                    &buf[..n],
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("OnionCell construction failed: {}", e);
                        break;
                    }
                }
            };

            let wire_buffer = {
                let mut guard = circuit_fwd.lock().await;
                guard.wrap_forward(&mut cell)
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

    tokio::pin!(fwd);
    tokio::pin!(bwd);

    let mut fwd_done = false;
    let mut rx_opt = kill_switch.map(|ks| ks.subscribe());

    loop {
        let kill_wait = async {
            if let Some(ref mut rx) = rx_opt {
                while rx.changed().await.is_ok() {
                    if *rx.borrow() {
                        return;
                    }
                }
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            _ = kill_wait => {
                tracing::error!("[AnonGuard KillSwitch] TRIPPED! Enforcing immediate fail-closed circuit termination.");
                break;
            }
            _ = &mut bwd => {
                // Upstream connection ended or remote sent Destroy cell
                break;
            }
            _ = &mut fwd, if !fwd_done => {
                // Client upload finished; keep bwd running until upstream closes
                fwd_done = true;
            }
        }
    }

    Ok(())
}

/// Negotiates an authentic multi-hop telescopic onion circuit over the wire.
/// Sends a CREATE cell with ephemeral public key X1 to Hop 0, processes CREATED with Y1,
/// and sequentially extends the circuit through in-band encrypted EXTEND cells.
///
/// # Security
/// `pinned_identity_keys[i]` MUST be the `identity_key_ed25519` from the consensus-verified
/// `RelayDescriptor` for `chain[i]`. The handshake is rejected unless the relay proves it holds
/// the corresponding private key via Ed25519 signature (MITM protection).
pub async fn build_telescopic_circuit(
    stream: &mut TcpStream,
    circuit_id: u32,
    chain: &[crate::mesh::node::ProxyNode],
    pinned_identity_keys: &[[u8; 32]],
    target_host: &str,
    target_port: u16,
) -> Result<OnionCircuit, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut circuit = OnionCircuit::new(circuit_id);

    // 1. Hop 0 (Guard) in-band CREATE/CREATED handshake
    let client_secret_0 = EphemeralSecret::random_from_rng(OsRng);
    let client_pub_0 = x25519_dalek::PublicKey::from(&client_secret_0);
    let client_pub_0_bytes = *client_pub_0.as_bytes();
    let create_cell = build_create_cell(circuit_id, &client_pub_0)
        .map_err(|e| format!("Failed to build CREATE cell: {}", e))?;
    stream.write_all(&create_cell.serialize()).await?;

    let mut created_buf = [0u8; ONION_CELL_SIZE];
    stream.read_exact(&mut created_buf).await?;
    let created_cell = OnionCell::parse(&created_buf)
        .map_err(|e| format!("Failed to parse CREATED cell: {}", e))?;
    let pinned_key_0 = pinned_identity_keys
        .first()
        .ok_or("No pinned identity key for Hop 0 — refusing unauthenticated handshake")?;
    let (fwd0, bwd0, mac0) =
        process_created_cell(&created_cell, client_secret_0, &client_pub_0_bytes, pinned_key_0)
            .map_err(|e| format!("Hop 0 identity-bound handshake failed: {}", e))?;
    circuit.add_hop(fwd0, bwd0, mac0);
    // 2. Telescopic circuit extension for subsequent hops
    #[allow(clippy::needless_range_loop)]
    for hop_idx in 1..chain.len() {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = x25519_dalek::PublicKey::from(&client_secret);
        let client_pub_bytes = *client_pub.as_bytes();

        let extend_payload =
            encode_extend_payload(&chain[hop_idx].host, chain[hop_idx].port, &client_pub)
                .map_err(|e| format!("Failed to encode EXTEND payload: {}", e))?;
        let mut extend_cell = OnionCell::new(
            circuit_id,
            hop_idx as u32,
            CellCommand::Extend,
            0,
            &extend_payload,
        )
        .map_err(|e| format!("Failed to build EXTEND cell: {}", e))?;

        let wire_buffer = circuit.wrap_forward(&mut extend_cell);
        stream.write_all(&wire_buffer).await?;

        let mut return_wire = [0u8; ONION_CELL_SIZE];
        stream.read_exact(&mut return_wire).await?;
        let resp_cell = circuit
            .unwrap_backward(&mut return_wire)
            .map_err(|e| format!("Failed to unwrap backward cell from Hop {}: {}", hop_idx, e))?;

        let pinned_key = pinned_identity_keys
            .get(hop_idx)
            .ok_or_else(|| format!("No pinned identity key for Hop {hop_idx} — refusing unauthenticated handshake"))?;
        let (fwd, bwd, mac) =
            process_created_cell(&resp_cell, client_secret, &client_pub_bytes, pinned_key)
                .map_err(|e| format!("Hop {hop_idx} identity-bound handshake failed: {e}"))?;

        circuit.add_hop(fwd, bwd, mac);
    }

    // 3. Instruct the exit hop to connect in-band to target_host:target_port
    let relay_payload = crate::onion::circuit::encode_relay_target(target_host, target_port)
        .map_err(|e| format!("Failed to encode RELAY target payload: {}", e))?;
    let mut relay_cell = OnionCell::new(
        circuit_id,
        1,
        CellCommand::Relay,
        0,
        &relay_payload,
    )
    .map_err(|e| format!("Failed to build RELAY cell: {}", e))?;

    let wire_buffer = circuit.wrap_forward(&mut relay_cell);
    stream.write_all(&wire_buffer).await?;

    let mut return_wire = [0u8; ONION_CELL_SIZE];
    stream.read_exact(&mut return_wire).await?;
    let resp_cell = circuit
        .unwrap_backward(&mut return_wire)
        .map_err(|e| format!("Failed to unwrap backward cell from Exit hop: {}", e))?;

    if resp_cell.command != CellCommand::Relay {
        return Err(format!(
            "Expected RELAY response from exit hop, got {:?}",
            resp_cell.command
        )
        .into());
    }

    Ok(circuit)
}

/// Handles incoming Onion Cell connections on a relay node, completing the identity-bound
/// X25519/Ed25519 handshake and forwarding cells in-band.
///
/// The `relay_identity_key` is the relay's long-term Ed25519 signing key. In production this
/// should be loaded from a persisted key file; callers must ensure it is the same key registered
/// in the directory consensus so clients can pin and verify it.
pub async fn handle_onion_relay_connection(
    mut client: TcpStream,
    kill_switch: Option<KillSwitchController>,
    jitter: Option<JitterEngine>,
    exit_policy: Option<crate::kernel::ExitPolicy>,
    relay_identity_key: &Ed25519SigningKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let policy = exit_policy.unwrap_or_default();

    // 1. Read initial CREATE cell from client
    let mut initial_buf = [0u8; ONION_CELL_SIZE];
    client.read_exact(&mut initial_buf).await?;
    let create_cell = OnionCell::parse(&initial_buf)
        .map_err(|e| format!("Failed to parse incoming CREATE cell: {}", e))?;

    let (mut relay_hop, created_cell) = handle_create_cell(&create_cell, relay_identity_key)
        .map_err(|e| format!("Failed to handle CREATE cell: {}", e))?;
    client.write_all(&created_cell.serialize()).await?;
    let id_bytes = relay_identity_key.verifying_key().to_bytes();
    info!(
        circuit_id = create_cell.circuit_id,
        identity_key_prefix = ?&id_bytes[..4],
        "Relay established identity-bound onion circuit hop"
    );

    // 2. Relay packet processing loop
    let mut downstream: Option<TcpStream> = None;
    let mut is_exit = false;
    let mut rx_kill = kill_switch.as_ref().map(|ks| ks.subscribe());

    loop {
        if let Some(ref ks) = kill_switch {
            if ks.is_tripped() {
                break;
            }
        }

        let mut client_buf = [0u8; ONION_CELL_SIZE];

        let kill_wait = async {
            if let Some(ref mut rx) = rx_kill {
                while rx.changed().await.is_ok() {
                    if *rx.borrow() {
                        return;
                    }
                }
            } else {
                std::future::pending::<()>().await;
            }
        };

        if let Some(ref mut ds) = downstream {
            if is_exit {
                // Exit relay: downstream is the destination target server (raw TCP)
                let mut raw_buf = [0u8; PAYLOAD_SIZE];
                tokio::select! {
                    _ = kill_wait => break,
                    res = client.read_exact(&mut client_buf) => {
                        if res.is_err() { break; }
                        match relay_hop.peel_forward(&mut client_buf) {
                            Ok(PeelResult::AddressedToThisRelay(CellCommand::Data, payload)) => {
                                if ds.write_all(&payload).await.is_err() {
                                    break;
                                }
                            }
                            Ok(PeelResult::AddressedToThisRelay(CellCommand::Destroy, _)) => break,
                            _ => {}
                        }
                    }
                    res = ds.read(&mut raw_buf) => {
                        let n = match res {
                            Ok(0) => {
                                let seq = relay_hop.next_send_seq;
                                relay_hop.next_send_seq += 1;
                                if let Ok(destroy_cell) = OnionCell::new(
                                    relay_hop.circuit_id,
                                    seq,
                                    CellCommand::Destroy,
                                    1,
                                    &[],
                                ) {
                                    let mut wire = destroy_cell.serialize();
                                    relay_hop.wrap_backward_aead(&mut wire);
                                    let _ = client.write_all(&wire).await;
                                }
                                break;
                            }
                            Ok(n) => n,
                            Err(_) => {
                                let seq = relay_hop.next_send_seq;
                                relay_hop.next_send_seq += 1;
                                if let Ok(destroy_cell) = OnionCell::new(
                                    relay_hop.circuit_id,
                                    seq,
                                    CellCommand::Destroy,
                                    1,
                                    &[],
                                ) {
                                    let mut wire = destroy_cell.serialize();
                                    relay_hop.wrap_backward_aead(&mut wire);
                                    let _ = client.write_all(&wire).await;
                                }
                                break;
                            }
                        };
                        let seq = relay_hop.next_send_seq;
                        relay_hop.next_send_seq += 1;
                        let Ok(return_cell) = OnionCell::new(
                            relay_hop.circuit_id,
                            seq,
                            CellCommand::Data,
                            1,
                            &raw_buf[..n],
                        ) else {
                            break;
                        };
                        let mut wire = return_cell.serialize();
                        relay_hop.wrap_backward_aead(&mut wire);
                        if let Some(ref j) = jitter {
                            j.apply_delay().await;
                        }
                        if client.write_all(&wire).await.is_err() {
                            break;
                        }
                    }
                }
            } else {
                // Intermediate relay: downstream is another onion relay
                let mut ds_buf = [0u8; ONION_CELL_SIZE];
                tokio::select! {
                    _ = kill_wait => break,
                    res = client.read_exact(&mut client_buf) => {
                        if res.is_err() { break; }
                        match relay_hop.peel_forward(&mut client_buf) {
                            Ok(PeelResult::AddressedToThisRelay(CellCommand::Extend, payload)) => {
                                if let Ok((next_h, next_p, next_pub)) = decode_extend_payload(&payload) {
                                    if let Ok(mut next_s) = policy.resolve_and_connect(&next_h, next_p).await {
                                        if let Ok(c_cell) = build_create_cell(relay_hop.circuit_id, &next_pub) {
                                            if next_s.write_all(&c_cell.serialize()).await.is_ok() {
                                                let mut resp = [0u8; ONION_CELL_SIZE];
                                                if next_s.read_exact(&mut resp).await.is_ok() {
                                                    relay_hop.wrap_backward_aead(&mut resp);
                                                    let _ = client.write_all(&resp).await;
                                                    downstream = Some(next_s);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(PeelResult::ForwardDownstream(forward_buf)) => {
                                if let Some(ref j) = jitter {
                                    j.apply_delay().await;
                                }
                                if ds.write_all(&*forward_buf).await.is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    res = ds.read_exact(&mut ds_buf) => {
                        if res.is_err() { break; }
                        relay_hop.wrap_backward(&mut ds_buf);
                        if let Some(ref j) = jitter {
                            j.apply_delay().await;
                        }
                        if client.write_all(&ds_buf).await.is_err() {
                            break;
                        }
                    }
                }
            }
        } else {
            // Awaiting initial EXTEND (as intermediate relay) or RELAY (as exit relay)
            tokio::select! {
                _ = kill_wait => break,
                res = client.read_exact(&mut client_buf) => {
                    if res.is_err() { break; }
                    match relay_hop.peel_forward(&mut client_buf) {
                        Ok(PeelResult::AddressedToThisRelay(CellCommand::Extend, payload)) => {
                            if let Ok((next_h, next_p, next_pub)) = decode_extend_payload(&payload) {
                                match policy.resolve_and_connect(&next_h, next_p).await {
                                    Ok(mut next_s) => {
                                        if let Ok(c_cell) = build_create_cell(relay_hop.circuit_id, &next_pub) {
                                            if next_s.write_all(&c_cell.serialize()).await.is_ok() {
                                                let mut resp = [0u8; ONION_CELL_SIZE];
                                                if next_s.read_exact(&mut resp).await.is_ok() {
                                                    relay_hop.wrap_backward_aead(&mut resp);
                                                    let _ = client.write_all(&resp).await;
                                                    downstream = Some(next_s);
                                                    is_exit = false;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Relay blocked or failed to connect to next hop {}:{}: {}", next_h, next_p, e);
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(PeelResult::AddressedToThisRelay(CellCommand::Relay, payload)) => {
                            if let Ok((target_h, target_p)) = crate::onion::circuit::decode_relay_target(&payload) {
                                match policy.resolve_and_connect(&target_h, target_p).await {
                                    Ok(target_s) => {
                                        let seq = relay_hop.next_send_seq;
                                        relay_hop.next_send_seq += 1;
                                        if let Ok(resp_cell) = OnionCell::new(
                                            relay_hop.circuit_id,
                                            seq,
                                            CellCommand::Relay,
                                            0,
                                            b"CONNECTED",
                                        ) {
                                            let mut resp = resp_cell.serialize();
                                            relay_hop.wrap_backward_aead(&mut resp);
                                            if client.write_all(&resp).await.is_ok() {
                                                info!("Exit relay successfully bridged circuit {} to target {}:{}", relay_hop.circuit_id, target_h, target_p);
                                                downstream = Some(target_s);
                                                is_exit = true;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Exit relay blocked or failed to connect to destination target {}:{}: {}", target_h, target_p, e);
                                        break;
                                    }
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }
        }
    }

    Ok(())
}
