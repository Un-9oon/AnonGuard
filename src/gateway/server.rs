//! Tokio asynchronous local gateway server listening on 127.0.0.1:9050.

use crate::core::state_machine::{ActiveGuarded, GuardedSocket};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::core::GuardConfig;
use crate::kernel::KillSwitchController;
use crate::mesh::ProxyPool;
use crate::morphing::{
    morph_bidirectional_guarded, JitterEngine, LorenzAttractor, PoissonJitter, RmtEnsemble,
    RmtTimingEngine,
};
use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
use crate::onion::circuit::{
    build_create_cell, decode_extend_payload, encode_extend_payload, handle_create_cell,
    process_created_cell, OnionCircuit, PeelOutcome,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::EphemeralSecret;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

/// Normalizes an IP address for per-IP counting.
/// IPv6 addresses are masked to /48 so that a single operator cannot bypass the
/// per-IP cap by allocating thousands of addresses from their /48 allocation.
/// IPv4 addresses are returned unchanged.
fn normalize_ip_for_cap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // Zero out segments 4-8 (keep only the first 48 bits = 3 segments)
            IpAddr::V6(Ipv6Addr::new(seg[0], seg[1], seg[2], 0, 0, 0, 0, 0))
        }
    }
}

pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;
pub const MAX_CONCURRENT_PER_IP: u32 = 64;

pub struct GatewayServer {
    config: GuardConfig,
    pool: ProxyPool,
    kill_switch: KillSwitchController,
    jitter: Option<JitterEngine>,
    connection_semaphore: Arc<Semaphore>,
    ip_connections: Arc<RwLock<HashMap<IpAddr, u32>>>,
    relay_identity_key: Arc<Ed25519SigningKey>,
}

impl GatewayServer {
    pub fn new(
        config: GuardConfig,
        pool: ProxyPool,
        kill_switch: KillSwitchController,
        relay_identity_key: Arc<Ed25519SigningKey>,
    ) -> Self {
        let jitter = if config.enable_rmt_morphing {
            let ensemble = if config.rmt_ensemble.to_lowercase() == "gue" {
                RmtEnsemble::GUE
            } else {
                RmtEnsemble::GOE
            };
            Some(JitterEngine::Rmt(RmtTimingEngine::new(ensemble, 1.5, 1024)))
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
            relay_identity_key,
        }
    }

    /// Starts the asynchronous listener loop with global and per-IP connection bounds.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.pool
            .init_guard_state(self.config.guard_state_path.clone())
            .await;

        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!(
            listen_addr = %self.config.listen_addr,
            "[AnonGuard Gateway] Active and guarded. Listening for client connections (DoS limits: max {} concurrent, max {}/IP)...",
            DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            MAX_CONCURRENT_PER_IP
        );

        if self.config.relay_mode && !self.config.directory_authorities.is_empty() {
            let auths = self.config.directory_authorities.clone();
            let identity_key = self.relay_identity_key.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600)); // 10 mins
                loop {
                    let now = crate::mesh::sybil::current_timestamp_secs();
                    let pub_key_bytes = identity_key.verifying_key().to_bytes();
                    let node_id = hex::encode(&pub_key_bytes[0..8]); // stable node_id based on key

                    let pow_nonce = match crate::mesh::sybil::solve_pow_bounded(
                        &node_id,
                        now,
                        config.pow_difficulty,
                    ) {
                        Some(n) => n,
                        None => {
                            warn!("Failed to solve PoW for registration, will retry later");
                            interval.tick().await;
                            continue;
                        }
                    };

                    let port = config
                        .listen_addr
                        .split(':')
                        .last()
                        .unwrap_or("9050")
                        .parse()
                        .unwrap_or(9050);
                    let host = config
                        .listen_addr
                        .split(':')
                        .next()
                        .unwrap_or("127.0.0.1")
                        .to_string();

                    let mut desc = crate::mesh::consensus::RelayDescriptor::new(
                        node_id,
                        host,
                        port,
                        [0u8; 32],
                        pub_key_bytes,
                        config.is_exit,
                        pow_nonce,
                        now,
                    );
                    desc.sign_with_key(&identity_key);

                    let json_payload = serde_json::to_string(&desc).unwrap();
                    let request = format!("REGISTER_RELAY {}", json_payload);

                    for auth_url in &auths {
                        let auth_host_port = auth_url.trim_start_matches("http://");
                        if let Ok(stream) = tokio::net::TcpStream::connect(auth_host_port).await {
                            if let Ok(mut session) =
                                crate::mesh::transport::SecureTransportSession::client_handshake(
                                    stream, None,
                                )
                                .await
                            {
                                let _ = session.write_frame(request.as_bytes()).await;
                                if let Ok(Ok(msg)) = tokio::time::timeout(
                                    tokio::time::Duration::from_secs(5),
                                    session.read_frame(),
                                )
                                .await
                                {
                                    info!(
                                        "Registered with auth {}: {}",
                                        auth_url,
                                        String::from_utf8_lossy(&msg)
                                    );
                                }
                            }
                        }
                    }

                    interval.tick().await;
                }
            });
        }

        loop {
            // If kill switch is active, do not accept new connections
            if self.kill_switch.is_tripped() {
                warn!("[AnonGuard Gateway] Kill switch active: refusing incoming connections.");
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                continue;
            }

            // 1. Global connection ceiling (prevent file descriptor/memory exhaustion)
            // Use acquire_owned().await BEFORE accept() to provide true backpressure to the OS backlog
            let permit = match self.connection_semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        "[AnonGuard DoS Defense] Connection semaphore closed, stopping accept loop"
                    );
                    break Ok(());
                }
            };

            let (client_stream, client_addr) = listener.accept().await?;
            let client_ip = client_addr.ip();

            // 2. Per-IP connection ceiling (prevent single-client connection flooding)
            // IPv6: key on /48 prefix to prevent cap bypass via large allocations
            let client_ip_key = normalize_ip_for_cap(client_ip);
            {
                let mut ip_map = self.ip_connections.write().await;
                let count = ip_map.entry(client_ip_key).or_insert(0);
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
            let relay_identity_key = self.relay_identity_key.clone();

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
                    ip: client_ip_key,
                    tracker: ip_tracker,
                };

                if kill_switch.is_tripped() {
                    return;
                }

                let mut peek_buf = [0u8; 1];
                // Bug #5: add timeout around peek() — without it, a client that never sends
                // a byte keeps the connection open indefinitely (Slowloris against the gateway)
                let is_socks5 = match tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    client_stream.peek(&mut peek_buf),
                )
                .await
                {
                    Ok(Ok(_)) => peek_buf[0] == 0x05,
                    Ok(Err(_)) | Err(_) => {
                        warn!(client = %client_addr, "Client closed or timed out before sending first byte");
                        return;
                    }
                };

                let mut client = GuardedSocket::new(client_stream, kill_switch.atomic_handle())
                    .begin_verification()
                    .mark_verified();

                if config.relay_mode {
                    if is_socks5 {
                        if !config.allow_open_socks5 {
                            warn!(
                                client = %client_addr,
                                "Relay Mode: Rejected unauthenticated plain SOCKS5 proxy request on onion relay port (anti-abuse policy)"
                            );
                            return;
                        }

                        let (target_host, target_port) = match tokio::time::timeout(
                            tokio::time::Duration::from_secs(10),
                            crate::gateway::chain::read_socks5_request(&mut client),
                        )
                        .await
                        {
                            Ok(Ok(target)) => target,
                            Ok(Err(e)) => {
                                warn!("Relay Mode: SOCKS5 handshake failed: {}", e);
                                return;
                            }
                            Err(_) => {
                                warn!("Relay Mode: SOCKS5 handshake timed out (Slowloris defense)");
                                return;
                            }
                        };

                        let exit_policy = crate::kernel::ExitPolicy::new(config.allow_private_exit);
                        match exit_policy
                            .resolve_and_connect(&target_host, target_port)
                            .await
                        {
                            Ok(mut target_stream) => {
                                // Bug #13: don't log target_host:target_port — destination is sensitive
                                info!("Relay Mode: Forwarding traffic to connected destination");

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
                        let _ = handle_onion_relay_connection(
                            client,
                            kill_switch.atomic_handle(),
                            jitter.clone(),
                            Some(exit_policy),
                            &relay_identity_key,
                            config.is_exit,
                            pool.clone(),
                        )
                        .await;
                    }
                    return;
                }

                // 1. Intercept SOCKS5 from local client to find target
                let timeout_duration = tokio::time::Duration::from_secs(10);
                let (target_host, target_port) = match tokio::time::timeout(
                    timeout_duration,
                    crate::gateway::chain::read_socks5_request(&mut client),
                )
                .await
                {
                    Ok(Ok(res)) => res,
                    Ok(Err(e)) => {
                        error!("Failed to intercept client SOCKS5 handshake: {}", e);
                        return;
                    }
                    Err(_) => {
                        warn!(
                            "SOCKS5 handshake timed out after {}s (Slowloris defense)",
                            timeout_duration.as_secs()
                        );
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
                            let mut guard_stream_guarded =
                                GuardedSocket::new(guard_stream, kill_switch.atomic_handle())
                                    .begin_verification()
                                    .mark_verified();
                            let _ = stream_onion_circuit(
                                &mut client,
                                &mut guard_stream_guarded,
                                circuit,
                                jitter.clone(),
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
        info!("[AnonGuard Reverse Relay] Active and guarded (node: {}, token: <REDACTED>). Maintaining outbound pool to Tracker: {}", node_id, host_port);

        // Keep a pool of 3 connections
        for _ in 0..3 {
            let hp = host_port.to_string();
            let nid = node_id.to_string();
            let token = auth_token.clone();
            let jitter = self.jitter.clone();
            let kill_switch = self.kill_switch.clone();
            let pow_difficulty = self.config.pow_difficulty;
            let allow_private_exit = self.config.allow_private_exit;
            let allow_open_socks5 = self.config.allow_open_socks5;
            let identity_key = self.relay_identity_key.clone();
            let pool = self.pool.clone();

            tokio::spawn(async move {
                loop {
                    match TcpStream::connect(&hp).await {
                        Ok(mut stream) => {
                            use tokio::io::AsyncWriteExt;
                            let now = crate::mesh::sybil::current_timestamp_secs();
                            let nonce = match crate::mesh::sybil::solve_pow_bounded(
                                &nid,
                                now,
                                pow_difficulty,
                            ) {
                                Some(n) => n,
                                None => {
                                    error!("Failed to solve PoW for reverse relay registration within bounds (DoS protection)");
                                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                                    continue;
                                }
                            };
                            let payload =
                                format!("REGISTER_REVERSE {} {} {} {}\n", nid, token, now, nonce);
                            if stream.write_all(payload.as_bytes()).await.is_ok() {
                                // Wait for the tracker to send data (meaning a client has connected to this stream)
                                // We peek 1 byte to see if it's SOCKS5 (0x05) or Onion Protocol (anything else)
                                let mut buf = [0u8; 1];
                                if stream.peek(&mut buf).await.is_ok() {
                                    info!("Reverse Relay: Received incoming client connection from tracker!");

                                    let is_socks5 = buf[0] == 0x05;

                                    if is_socks5 {
                                        if !allow_open_socks5 {
                                            warn!("Reverse Relay: Rejected unauthenticated plain SOCKS5 proxy request (anti-abuse policy)");
                                            continue;
                                        }

                                        // Process exactly like a Relay Mode client for open SOCKS5
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
                                    } else {
                                        // Handle as an Onion Relay Connection
                                        let guarded_stream =
                                            GuardedSocket::new(stream, kill_switch.atomic_handle())
                                                .begin_verification()
                                                .mark_verified(); // Connection from tracker is trusted via registration

                                        let exit_policy =
                                            crate::kernel::ExitPolicy::new(allow_private_exit);
                                        let _ = handle_onion_relay_connection(
                                            guarded_stream,
                                            kill_switch.atomic_handle(),
                                            jitter.clone(),
                                            Some(exit_policy),
                                            &identity_key,
                                            true, // require_auth via the onion handshake
                                            pool.clone(),
                                        )
                                        .await;
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
    client: &mut GuardedSocket<ActiveGuarded>,
    upstream: &mut GuardedSocket<ActiveGuarded>,
    circuit: OnionCircuit,
    jitter: Option<JitterEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    let circuit = Arc::new(Mutex::new(circuit));
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let circuit_fwd = circuit.clone();
    let jitter_fwd = jitter.clone();

    let fwd = async move {
        let mut buf = [0u8; PAYLOAD_SIZE];
        let stream_id = 1u16;
        let mut client_seq = 2u32; // Seq 1 was RELAY cell
        let mut dummy_interval = tokio::time::interval(std::time::Duration::from_millis(1000));

        loop {
            let mut is_dummy = false;
            let n = tokio::select! {
                res = client_read.read(&mut buf) => match res {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                },
                _ = dummy_interval.tick() => {
                    is_dummy = true;
                    0
                }
            };

            let mut cell = {
                let guard = circuit_fwd.lock().await;
                let seq = client_seq;
                client_seq += 1;

                let cmd = if is_dummy {
                    CellCommand::Dummy
                } else {
                    CellCommand::Data
                };
                match OnionCell::new(guard.circuit_id, seq, cmd, stream_id, &buf[..n]) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("OnionCell construction failed: {}", e);
                        break;
                    }
                }
            };

            let wire_buffer_res = {
                let mut guard = circuit_fwd.lock().await;
                guard.wrap_forward(&mut cell)
            };

            let wire_buffer = match wire_buffer_res {
                Ok(buf) => buf,
                Err(e) => {
                    tracing::warn!("Failed to wrap forward cell: {:?}", e);
                    break;
                }
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
                Ok((_hop, cell)) => match cell.command {
                    CellCommand::Data => {
                        let len = (cell.length as usize).min(cell.payload.len());
                        if client_write.write_all(&cell.payload[..len]).await.is_err() {
                            break;
                        }
                    }
                    CellCommand::Destroy => break,
                    _ => {}
                },
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

    loop {
        tokio::select! {
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
    // Bug #4: enforce minimum 3 hops (Guard → Middle → Exit)
    if chain.len() < 3 {
        return Err(format!(
            "Circuit chain too short: {} hops (minimum is 3 for anonymity)",
            chain.len()
        )
        .into());
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut circuit = OnionCircuit::new(circuit_id);

    // 1. Hop 0 (Guard) in-band CREATE/CREATED handshake
    let client_secret_0 = EphemeralSecret::random_from_rng(OsRng);
    let client_pub_0 = x25519_dalek::PublicKey::from(&client_secret_0);
    let client_pub_0_bytes = *client_pub_0.as_bytes();
    let create_cell = build_create_cell(circuit_id, &client_pub_0, 0)
        .map_err(|e| format!("Failed to build CREATE cell: {:?}", e))?;
    stream.write_all(&create_cell.serialize()).await?;

    let mut created_buf = [0u8; ONION_CELL_SIZE];
    stream.read_exact(&mut created_buf).await?;
    let created_cell = OnionCell::parse(&created_buf)
        .map_err(|e| format!("Failed to parse CREATED cell: {}", e))?;
    let pinned_key_0 = pinned_identity_keys
        .first()
        .ok_or("No pinned identity key for Hop 0 — refusing unauthenticated handshake")?;
    let hop_keys_0 = process_created_cell(
        &created_cell,
        client_secret_0,
        &client_pub_0_bytes,
        pinned_key_0,
        circuit_id,
        0,
    )
    .map_err(|e| format!("Hop 0 identity-bound handshake failed: {}", e))?;
    circuit
        .add_hop(hop_keys_0)
        .map_err(|e| format!("Failed to add hop 0: {:?}", e))?;
    // 2. Telescopic circuit extension for subsequent hops
    #[allow(clippy::needless_range_loop)]
    for hop_idx in 1..chain.len() {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = x25519_dalek::PublicKey::from(&client_secret);
        let client_pub_bytes = *client_pub.as_bytes();

        let extend_payload = encode_extend_payload(
            &chain[hop_idx].host,
            chain[hop_idx].port,
            &client_pub,
            hop_idx,
        )
        .map_err(|e| format!("Failed to encode EXTEND payload: {:?}", e))?;
        let mut extend_cell = OnionCell::new(
            circuit_id,
            hop_idx as u32,
            CellCommand::Extend,
            0,
            &extend_payload,
        )
        .map_err(|e| format!("Failed to build EXTEND cell: {}", e))?;

        let wire_buffer = circuit
            .wrap_forward(&mut extend_cell)
            .map_err(|e| format!("Failed to wrap forward: {:?}", e))?;
        stream.write_all(&wire_buffer).await?;

        let mut return_wire = [0u8; ONION_CELL_SIZE];
        stream.read_exact(&mut return_wire).await?;
        let (_hop, resp_cell) = circuit.unwrap_backward(&mut return_wire).map_err(|e| {
            format!(
                "Failed to unwrap backward cell from Hop {}: {:?}",
                hop_idx, e
            )
        })?;

        let pinned_key = pinned_identity_keys.get(hop_idx).ok_or_else(|| {
            format!("No pinned identity key for Hop {hop_idx} — refusing unauthenticated handshake")
        })?;
        let keys = process_created_cell(
            &resp_cell,
            client_secret,
            &client_pub_bytes,
            pinned_key,
            circuit_id,
            hop_idx,
        )
        .map_err(|e| format!("Hop {hop_idx} identity-bound handshake failed: {:?}", e))?;

        circuit
            .add_hop(keys)
            .map_err(|e| format!("Failed to add hop {}: {:?}", hop_idx, e))?;
    }

    // 3. Instruct the exit hop to connect in-band to target_host:target_port
    let relay_payload = crate::onion::circuit::encode_relay_target(target_host, target_port)
        .map_err(|e| format!("Failed to encode RELAY target payload: {:?}", e))?;
    let mut relay_cell = OnionCell::new(circuit_id, 1, CellCommand::Relay, 0, &relay_payload)
        .map_err(|e| format!("Failed to build RELAY cell: {}", e))?;

    let wire_buffer = circuit
        .wrap_forward(&mut relay_cell)
        .map_err(|e| format!("Failed to wrap forward relay cell: {:?}", e))?;
    stream.write_all(&wire_buffer).await?;

    let mut return_wire = [0u8; ONION_CELL_SIZE];
    stream.read_exact(&mut return_wire).await?;
    let (_hop, resp_cell) = circuit
        .unwrap_backward(&mut return_wire)
        .map_err(|e| format!("Failed to unwrap backward cell from Exit hop: {:?}", e))?;

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
/// Spawns a persistent task that owns `read_half` for the life of the connection and pushes
/// complete, fixed-size onion cells through an `mpsc` channel.
///
/// This exists to fix Critical Bug #2 (cell loss under `tokio::select!`): racing
/// `AsyncReadExt::read_exact` directly inside `select!` is NOT cancel-safe. If a concurrent
/// branch of the `select!` resolves first, the `read_exact` future is dropped mid-flight and
/// any bytes it already pulled off the socket are silently lost — corrupting the cell stream
/// under any concurrent load in either direction. By contrast, `mpsc::Receiver::recv()` IS
/// cancel-safe: the byte-level read has already fully completed, inside this task, before the
/// frame is ever pushed onto the channel, so cancelling a `recv()` future never discards data.
fn spawn_onion_cell_reader(
    mut read_half: tokio::io::ReadHalf<GuardedSocket<ActiveGuarded>>,
) -> tokio::sync::mpsc::Receiver<[u8; ONION_CELL_SIZE]> {
    use tokio::io::AsyncReadExt;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let mut buf = [0u8; ONION_CELL_SIZE];
            if read_half.read_exact(&mut buf).await.is_err() {
                break;
            }
            if tx.send(buf).await.is_err() {
                break;
            }
        }
        // `tx` drops here on EOF/error/backpressure-close, so the paired `rx.recv()` on the
        // main loop resolves to `None` exactly once, cleanly signalling closure.
    });
    rx
}

/// Same as [`spawn_onion_cell_reader`], but for a raw (non-onion-framed) downstream connection
/// at an Exit relay, where the far side is an arbitrary destination server rather than another
/// AnonGuard hop. Reads are variable-length (`read`, not `read_exact`) up to `PAYLOAD_SIZE`.
fn spawn_raw_downstream_reader(
    mut read_half: tokio::io::ReadHalf<GuardedSocket<ActiveGuarded>>,
) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let mut buf = [0u8; PAYLOAD_SIZE];
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

pub async fn handle_onion_relay_connection(
    mut client: GuardedSocket<ActiveGuarded>,
    kill_switch_arc: std::sync::Arc<std::sync::atomic::AtomicBool>,
    jitter: Option<JitterEngine>,
    exit_policy: Option<crate::kernel::ExitPolicy>,
    relay_identity_key: &Ed25519SigningKey,
    is_exit_allowed: bool,
    pool: crate::mesh::pool::ProxyPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let policy = exit_policy.unwrap_or_default();

    // 1. Read initial CREATE cell from client
    let mut initial_buf = [0u8; ONION_CELL_SIZE];
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        client.read_exact(&mut initial_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(format!("Failed to read initial CREATE cell: {}", e).into()),
        Err(_) => return Err("Timeout waiting for initial CREATE cell (Slowloris defense)".into()),
    }
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

    // 2. Relay packet processing loop.
    //
    // The client side is split once, up front, and read exclusively by a persistent background
    // task (see `spawn_onion_cell_reader`) for the entire lifetime of the connection. The main
    // loop below only ever awaits `client_cell_rx.recv()`, never `client.read_exact()` directly,
    // which is what makes racing it against the downstream read in `select!` cancel-safe.
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_cell_rx = spawn_onion_cell_reader(client_read);

    let mut is_currently_exit_hop = false;
    let mut ds_write: Option<tokio::io::WriteHalf<GuardedSocket<ActiveGuarded>>> = None;
    let mut ds_cell_rx: Option<tokio::sync::mpsc::Receiver<[u8; ONION_CELL_SIZE]>> = None;
    let mut ds_data_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>> = None;

    loop {
        if let Some(ref mut ds_w) = ds_write {
            if is_currently_exit_hop {
                // Exit relay: downstream is the destination target server (raw TCP).
                let ds_rx = ds_data_rx
                    .as_mut()
                    .expect("set alongside ds_write for exit hop");
                tokio::select! {
                    cell = client_cell_rx.recv() => {
                        let Some(mut client_buf) = cell else { break; };
                        match relay_hop.peel_forward(&mut client_buf) {
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::Data, len }) => {
                                let payload = &client_buf[13..13+len];
                                if ds_w.write_all(payload).await.is_err() {
                                    break;
                                }
                            }
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::Destroy, .. }) => break,
                            _ => {}
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                        error!("Idle circuit timeout (exit mode)");
                        break;
                    }
                    data = ds_rx.recv() => {
                        // `None` covers both a clean EOF (`Ok(0)`) and a read error on the
                        // downstream socket — the reader task collapses both into "stop
                        // forwarding", matching the original behaviour, which reacted to
                        // Ok(0)/Err(_) identically by tearing the circuit down.
                        let Some(n_bytes) = data else {
                            if let Ok(destroy_cell) = OnionCell::new(
                                relay_hop.circuit_id,
                                0,
                                CellCommand::Destroy,
                                1,
                                &[],
                            ) {
                                let mut wire = destroy_cell.serialize();
                                // Bug #10: break on crypto error rather than silently succeeding
                                if relay_hop.wrap_backward_originate(&mut wire).is_ok() {
                                    let _ = client_write.write_all(&wire).await;
                                }
                            }
                            break;
                        };
                        let Ok(return_cell) = OnionCell::new(
                            relay_hop.circuit_id,
                            0,
                            CellCommand::Data,
                            1,
                            &n_bytes,
                        ) else {
                            break;
                        };
                        let mut wire = return_cell.serialize();
                        // Bug #10: break on crypto error rather than silently discarding
                        if relay_hop.wrap_backward_originate(&mut wire).is_err() { break; }
                        if let Some(ref j) = jitter {
                            j.apply_delay().await;
                        }
                        if client_write.write_all(&wire).await.is_err() {
                            break;
                        }
                    }
                }
            } else {
                // Intermediate relay: downstream is the next relay in the mesh (OnionCells).
                let ds_rx = ds_cell_rx
                    .as_mut()
                    .expect("set alongside ds_write for intermediate hop");
                tokio::select! {
                    cell = client_cell_rx.recv() => {
                        let Some(mut client_buf) = cell else { break; };
                        match relay_hop.peel_forward(&mut client_buf) {
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::Extend, .. }) => {
                                error!("EXTEND rejected: relay is already an intermediate hop");
                                break;
                            }
                            Ok(PeelOutcome::ForwardDownstream) => {
                                if let Some(ref j) = jitter {
                                    j.apply_delay().await;
                                }
                                if ds_w.write_all(&client_buf).await.is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                        error!("Idle circuit timeout (intermediate mode)");
                        break;
                    }
                    cell = ds_rx.recv() => {
                        let Some(mut ds_buf) = cell else { break; };
                        // Bug #10: break on crypto error rather than silently forwarding
                        if relay_hop.wrap_backward_relay(&mut ds_buf).is_err() { break; }
                        if let Some(ref j) = jitter {
                            j.apply_delay().await;
                        }
                        if client_write.write_all(&ds_buf).await.is_err() {
                            break;
                        }
                    }
                }
            }
        } else {
            // Awaiting initial EXTEND (as intermediate relay) or RELAY (as exit relay).
            let Ok(Some(mut client_buf)) =
                tokio::time::timeout(tokio::time::Duration::from_secs(60), client_cell_rx.recv())
                    .await
            else {
                error!("Idle circuit timeout (awaiting setup)");
                break;
            };
            match relay_hop.peel_forward(&mut client_buf) {
                Ok(PeelOutcome::AddressedToThisRelay {
                    command: CellCommand::Extend,
                    len,
                }) => {
                    let payload = &client_buf[13..13 + len];
                    let extend_ok = async {
                            let (next_h, next_p, next_pub, hop_index) = decode_extend_payload(&payload)
                                .map_err(|e| format!("bad EXTEND payload: {e}"))?;

                            if hop_index != relay_hop.hop_index + 1 {
                                return Err(format!("EXTEND rejected: requested hop_index {} does not match expected {}", hop_index, relay_hop.hop_index + 1));
                            }
                            if hop_index >= crate::onion::circuit::MAX_HOPS {
                                return Err(format!("EXTEND rejected: max chain depth {} exceeded", crate::onion::circuit::MAX_HOPS));
                            }

                            // V-11: Enforce is_exit check for non-mesh targets
                            if !is_exit_allowed && !pool.is_mesh_target(&next_h, next_p).await {
                                return Err("EXTEND rejected: target is not a known mesh node and relay is not an exit node".to_string());
                            }

                            let mut next_s = policy.resolve_and_connect(&next_h, next_p).await

                            .map_err(|e| format!("next hop {next_h}:{next_p} unreachable: {e}"))?;
                        let c_cell = build_create_cell(relay_hop.circuit_id, &next_pub, hop_index)
                            .map_err(|e| format!("failed to build CREATE cell: {e}"))?;
                        next_s.write_all(&c_cell.serialize()).await
                            .map_err(|e| format!("failed to write CREATE to next hop: {e}"))?;
                        let mut resp = [0u8; ONION_CELL_SIZE];
                        next_s.read_exact(&mut resp).await
                            .map_err(|e| format!("no CREATED response from next hop: {e}"))?;
                        Ok::<_, String>((next_s, resp))
                    }.await;

                    match extend_ok {
                        Ok((next_s, mut resp)) => {
                            let _ = relay_hop.wrap_backward_originate(&mut resp);
                            if client_write.write_all(&resp).await.is_err() {
                                break;
                            }
                            let guarded = GuardedSocket::new(next_s, kill_switch_arc.clone())
                                .begin_verification()
                                .mark_verified();
                            let (new_read, new_write) = tokio::io::split(guarded);
                            ds_cell_rx = Some(spawn_onion_cell_reader(new_read));
                            ds_write = Some(new_write);
                            is_currently_exit_hop = false;
                        }
                        Err(e) => {
                            error!("EXTEND failed on circuit {}: {}", relay_hop.circuit_id, e);
                            if let Ok(destroy_cell) = OnionCell::new(
                                relay_hop.circuit_id,
                                0,
                                CellCommand::Destroy,
                                0,
                                &[],
                            ) {
                                let mut wire = destroy_cell.serialize();
                                let _ = relay_hop.wrap_backward_originate(&mut wire);
                                let _ = client_write.write_all(&wire).await;
                            }
                            break;
                        }
                    }
                }
                Ok(PeelOutcome::AddressedToThisRelay {
                    command: CellCommand::Relay,
                    len,
                }) => {
                    let payload = &client_buf[13..13 + len];
                    if let Ok((target_h, target_p)) =
                        crate::onion::circuit::decode_relay_target(&payload)
                    {
                        // V-11: Enforce is_exit check for Relay cells
                        if !is_exit_allowed && !pool.is_mesh_target(&target_h, target_p).await {
                            error!("Relay cell rejected: not an exit relay and target is not a known mesh node");
                            break;
                        }
                        match policy.resolve_and_connect(&target_h, target_p).await {
                            Ok(target_s) => {
                                if let Ok(resp_cell) = OnionCell::new(
                                    relay_hop.circuit_id,
                                    0,
                                    CellCommand::Relay,
                                    0,
                                    b"CONNECTED",
                                ) {
                                    let mut resp = resp_cell.serialize();
                                    // Bug #10: break on crypto error
                                    if relay_hop.wrap_backward_originate(&mut resp).is_err() {
                                        break;
                                    }
                                    if client_write.write_all(&resp).await.is_ok() {
                                        // Bug #13: don't log destination host/port
                                        info!(
                                            "Exit relay successfully bridged circuit {}",
                                            relay_hop.circuit_id
                                        );
                                        let guarded =
                                            GuardedSocket::new(target_s, kill_switch_arc.clone())
                                                .begin_verification()
                                                .mark_verified();
                                        let (new_read, new_write) = tokio::io::split(guarded);
                                        ds_data_rx = Some(spawn_raw_downstream_reader(new_read));
                                        ds_write = Some(new_write);
                                        is_currently_exit_hop = true;
                                    }
                                }
                            }
                            Err(_e) => {
                                // Bug #13: don't log destination host/port
                                error!("Exit relay blocked or failed to connect to destination");
                                break;
                            }
                        }
                    }
                }
                _ => break,
            }
        }
    }

    Ok(())
}
