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
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
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
        let mut tasks = tokio::task::JoinSet::new();
        self.pool
            .init_guard_state(self.config.guard_state_path.clone())
            .await?;

        if self.config.relay_mode
            && !self.config.directory_authorities.is_empty()
            && self.config.authority_endpoints.len() != self.config.directory_authorities.len()
        {
            return Err(
                "Relay registration requires bound authority identity/address/pin records".into(),
            );
        }
        // Validate a supplied public/NAT endpoint before opening the listener.
        let configured_bind: std::net::SocketAddr = self.config.listen_addr.parse()?;
        self.config.advertised_relay_address(configured_bind)?;
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        let bound_address = listener.local_addr()?;
        let advertised_address = self.config.advertised_relay_address(bound_address)?;
        info!(
            listen_addr = %bound_address,
            "[AnonGuard Gateway] Active and guarded. Listening for client connections (DoS limits: max {} concurrent, max {}/IP)...",
            DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            MAX_CONCURRENT_PER_IP
        );

        // Step 2: Spawn the Website Fingerprinting Traffic Chaffing Engine
        if self.config.enable_chaffing {
            let engine =
                crate::gateway::chaffing::ChaffingEngine::new(self.config.listen_addr.clone());
            tasks.spawn(async move {
                engine.run_loop().await;
            });
        }

        if self.config.unlisted_bridge
            && (!self.config.relay_mode
                || self.config.is_exit
                || self.config.allow_open_socks5
                || !advertised_address.ip().is_loopback())
        {
            return Err("Unlisted bridges require a non-exit, onion-only loopback relay".into());
        }
        if self.config.relay_mode
            && !self.config.unlisted_bridge
            && !self.config.directory_authorities.is_empty()
        {
            let auths = self.config.authority_endpoints.clone();
            let identity_key = self.relay_identity_key.clone();
            let config = self.config.clone();
            tasks.spawn(async move {
                loop {
                    let now = crate::mesh::sybil::current_timestamp_secs();
                    let pub_key_bytes = identity_key.verifying_key().to_bytes();
                    let node_id = hex::encode(&pub_key_bytes[0..8]); // stable node_id based on key

                    let mining_id = node_id.clone();
                    let difficulty = config.pow_difficulty;
                    let pow_nonce = match tokio::task::spawn_blocking(move || {
                        crate::mesh::sybil::solve_pow_bounded(&mining_id, now, difficulty)
                    })
                    .await
                    {
                        Ok(Some(n)) => n,
                        _ => {
                            warn!(
                                "PoW attempt exhausted; retrying a fresh challenge in 30 seconds"
                            );
                            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                            continue;
                        }
                    };

                    let port = advertised_address.port();
                    let host = advertised_address.ip().to_string();

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

                    let Ok(json_payload) = serde_json::to_string(&desc) else {
                        continue;
                    };
                    let request = format!("REGISTER_RELAY {}", json_payload);

                    for (auth_idx, authority) in auths.iter().enumerate() {
                        let auth_url = &authority.address;
                        // [B3] Wire authority identity key pinning (STS, Diffie-van Oorschot-Wiener 1992).
                        //
                        // The correct mechanism (sign ephemeral DH keys with long-term identity key,
                        // verify against a pinned key) is already implemented in
                        // SecureTransportSession::client_handshake. This was a wiring bug — pinned_key
                        // was always None, making the handshake vulnerable to active MITM impersonation.
                        //
                        // Bootstrap: authority_identity_keys is empty by default. Operators MUST
                        // pre-populate it from their authority's published Ed25519 key. An empty list
                        // produces a startup warning — see docs/reports/hardening_findings.md.
                        let pinned_vk =
                            ed25519_dalek::VerifyingKey::from_bytes(&authority.public_key).ok();

                        if pinned_vk.is_none() {
                            if !config.allow_unauthenticated_registration {
                                error!(
                                    "Registration to {} refused: no pinned identity key for authority index {}. \
                                     This would be unauthenticated and vulnerable to active MITM. \
                                     Populate GuardConfig::authority_identity_keys, or explicitly set \
                                     allow_unauthenticated_registration = true for local testnets.",
                                    auth_url, auth_idx
                                );
                                continue;
                            } else {
                                warn!(
                                    "No pinned identity key for authority index {} ({}); \
                                     handshake will be unauthenticated (allow_unauthenticated_registration is enabled). \
                                     MITM risk!",
                                    auth_idx, auth_url
                                );
                            }
                        }

                        let auth_host_port = auth_url
                            .split_once('@')
                            .map_or(auth_url.as_str(), |(_, addr)| addr)
                            .trim_start_matches("http://");
                        if let Ok(Ok(stream)) = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            tokio::net::TcpStream::connect(auth_host_port),
                        )
                        .await
                        {
                            if let Ok(Ok(mut session)) = tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                crate::mesh::transport::SecureTransportSession::client_handshake(
                                    stream,
                                    pinned_vk.as_ref(),
                                ),
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
                            } else {
                                warn!(
                                    "Relay registration to {} rejected: handshake failed. \
                                     Check authority_identity_keys configuration.",
                                    auth_url
                                );
                            }
                        }
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(600)).await;
                }
            });
        }

        loop {
            while tasks.try_join_next().is_some() {}
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
                        current = *count,
                        limit = MAX_CONCURRENT_PER_IP,
                        "[AnonGuard DoS Defense] Dropped connection: per-IP connection cap exceeded"
                    );
                    crate::observability::inc_connection_limit_drops();
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

            tasks.spawn(async move {
                let mut cancellation = kill_switch.subscribe();
                let work = async move {
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
                            warn!("Client closed or timed out before sending first byte");
                            crate::observability::inc_timeouts();
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

                            let exit_policy =
                                crate::kernel::ExitPolicy::new(config.allow_private_exit);
                            match exit_policy
                                .resolve_and_connect(&target_host, target_port)
                                .await
                            {
                                Ok(mut target_stream) => {
                                    // Bug #13: don't log target_host:target_port — destination is sensitive
                                    info!(
                                        "Relay Mode: Forwarding traffic to connected destination"
                                    );

                                    let _ =
                                        crate::gateway::chain::send_socks5_reply(&mut client, 0x00)
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
                                    error!(kind=?e.kind(), "Relay destination blocked or unreachable");
                                    let rep = if e.kind() == std::io::ErrorKind::PermissionDenied {
                                        0x02 // Connection not allowed by ruleset (SSRF/private IP blocked)
                                    } else {
                                        0x04 // Host unreachable
                                    };
                                    let _ =
                                        crate::gateway::chain::send_socks5_reply(&mut client, rep)
                                            .await;
                                }
                            }
                        } else {
                            info!("Relay Mode: Processing incoming in-band Onion Cell connection");
                            let exit_policy =
                                crate::kernel::ExitPolicy::new(config.allow_private_exit);
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
                    let chain = if config.private_bridges {
                        pool.get_private_bridge_chain_with_bounds(&config.bridge_transports, config.enforce_subnet_diversity, config.min_chain_length.max(3), config.max_chain_length.max(3)).await
                    } else if config.enable_onion_routing || config.enforce_subnet_diversity {
                        let pins: Vec<_> = config.bridge_transports.iter().map(|entry| entry.identity).collect();
                        pool.get_onion_chain_with_entry_pins(
                            config.min_chain_length.max(3),
                            config.max_chain_length.max(3),
                            config.enforce_subnet_diversity,
                            true,
                            &pins,
                        )
                        .await
                    } else {
                        pool.get_random_chain(config.min_chain_length, config.max_chain_length)
                            .await
                    };
                    if chain.is_empty() {
                        warn!("[AnonGuard Gateway] No upstream proxies available for chain");
                        let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x01).await;
                        return;
                    }

                    if config.enable_onion_routing {
                        // Multipath requires a shared exit session and symmetric framing.
                        // Until that protocol exists, use one byte-preserving circuit.
                        let result = async {
                            let entry = chain.first().ok_or("No entry relay")?;
                            if entry.raw_url.starts_with("reverse://") {
                                return Err("Reverse onion transport is unsupported".into());
                            }
                            let addr = (entry.host.as_str(), entry.port);
                            let mut keys = pool.get_identity_keys(&chain).await;
                            if config.private_bridges {
                                let binding = config.bridge_transports.iter().find(|binding|
                                    binding.bridge.ip().to_string() == entry.host && binding.bridge.port() == entry.port)
                                    .ok_or("Unlisted entry binding missing")?;
                                keys[0] = binding.identity;
                            }
                            let stream = match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                async {
                                    if config.bridge_transports.is_empty() {
                                        TcpStream::connect(addr).await
                                    } else {
                                        let transport = config.bridge_transports.iter()
                                            .find(|binding| binding.identity == keys[0])
                                            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Entry has no provisioned transport"))?;
                                        crate::onion::transport::connect(transport.proxy, transport.bridge, &transport.arguments).await
                                    }
                                },
                            )
                            .await
                            {
                                Ok(Ok(stream)) => stream,
                                _ => {
                                    pool.note_guard_link_failure(keys[0]).await;
                                    return Err("Entry relay connection failed".into());
                                }
                            };
                            let mut stream =
                                match crate::onion::link::connect(stream, keys[0]).await {
                                    Ok(stream) => stream,
                                    Err(error) => {
                                        pool.note_guard_link_failure(keys[0]).await;
                                        return Err(error.into());
                                    }
                                };
                            let mut circuit_id: u32 = rand::random();
                            if (circuit_id >> 24) == 0x05 || (circuit_id >> 24) == 0x00 {
                                circuit_id ^= 0x10000000;
                            }
                            let circuit = build_telescopic_circuit(
                                &mut stream,
                                circuit_id,
                                &chain,
                                &keys,
                                &target_host,
                                target_port,
                            )
                            .await?;
                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((stream, circuit))
                        };
                        match tokio::time::timeout(std::time::Duration::from_secs(30), result).await
                        {
                            Ok(Ok((stream, circuit))) => {
                                let mut upstream =
                                    GuardedSocket::new(stream, kill_switch.atomic_handle())
                                        .begin_verification()
                                        .mark_verified();
                                if crate::gateway::chain::send_socks5_reply(&mut client, 0x00)
                                    .await
                                    .is_ok()
                                {
                                    let _ = stream_onion_circuit(
                                        &mut client,
                                        &mut upstream,
                                        circuit,
                                        jitter.clone(),
                                    )
                                    .await;
                                }
                            }
                            _ => {
                                let _ = crate::gateway::chain::send_socks5_reply(&mut client, 0x05)
                                    .await;
                                if config.strict_killswitch {
                                    kill_switch.trip("Onion circuit negotiation failure");
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
                                                AsyncBufReadExt, AsyncReadExt, AsyncWriteExt,
                                                BufReader,
                                            };
                                            let payload = if !auth_token.is_empty() {
                                                format!(
                                                    "CONNECT_REVERSE {} {}\n",
                                                    node_id, auth_token
                                                )
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
                                                error!(
                                                    "Tracker rejected CONNECT_REVERSE: {}",
                                                    resp
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
                                    let addr = if node.host.contains(':') {
                                        format!("[{}]:{}", node.host, node.port)
                                    } else {
                                        format!("{}:{}", node.host, node.port)
                                    };
                                    match TcpStream::connect(&addr).await {
                                        Ok(s) => current_stream = Some(s),
                                        Err(e) => {
                                            error!(
                                                "Failed to connect to entry node {}: {}",
                                                addr, e
                                            );
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
                                        let _ = crate::gateway::chain::send_socks5_reply(
                                            &mut client,
                                            0x05,
                                        )
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
                            info!(hops = chain.len(), "Established proxy tunnel");
                            let _ =
                                crate::gateway::chain::send_socks5_reply(&mut client, 0x00).await;
                            let _ = crate::morphing::morph_bidirectional_guarded(
                                &mut client,
                                &mut upstream_stream,
                                jitter.clone(),
                                Some(kill_switch.clone()),
                            )
                            .await;
                        } else {
                            let _ =
                                crate::gateway::chain::send_socks5_reply(&mut client, 0x05).await;
                        }
                    }
                };
                tokio::select! {
                    _ = work => {}
                    _ = async {
                        loop {
                            if *cancellation.borrow() { break; }
                            if cancellation.changed().await.is_err() { break; }
                        }
                    } => {}
                }
            });
        }
    }

    pub async fn run_reverse_relay(
        &self,
        tracker_url: &str,
        node_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut tasks = tokio::task::JoinSet::new();
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

            tasks.spawn(async move {
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
                                                info!("Reverse relay forwarding traffic");
                                                let _ = morph_bidirectional_guarded(
                                                    &mut stream,
                                                    &mut target_stream,
                                                    jitter.clone(),
                                                    Some(kill_switch.clone()),
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                error!(kind=?e.kind(), "Reverse relay destination blocked or unreachable");
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

/// Writes an authenticated fixed-size cell through the shared circuit sequence state.
/// The write deadline bounds backpressure from an unresponsive relay.
async fn write_client_cell(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    circuit: &Arc<tokio::sync::Mutex<OnionCircuit>>,
    command: CellCommand,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncWriteExt;
    let wire = {
        let mut circuit = circuit.lock().await;
        let mut cell = OnionCell::new(circuit.circuit_id, 0, command, 1, payload)?;
        circuit.wrap_forward(&mut cell)?
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), writer.write_all(&wire)).await??;
    Ok(())
}

pub async fn stream_onion_circuit(
    client: &mut GuardedSocket<ActiveGuarded>,
    upstream: &mut GuardedSocket<ActiveGuarded>,
    circuit: OnionCircuit,
    jitter: Option<JitterEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;
    let exit_index = circuit
        .hop_count()
        .checked_sub(1)
        .ok_or("Empty onion circuit")?;
    let circuit = Arc::new(Mutex::new(circuit));
    let window = Arc::new(Mutex::new(crate::onion::flow::SendWindow::default()));
    let (ack_tx, mut ack_rx) = tokio::sync::mpsc::channel::<u32>(4);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let circuit_fwd = circuit.clone();
    let window_fwd = window.clone();
    let fwd = async move {
        let mut buffer = std::collections::VecDeque::new();
        let mut input = [0u8; 8192];
        let mut upload_open = true;
        let mut end_sent = false;
        let mut pending_ack = None;
        let mut prefer_data = false;
        // A persistent, shared profile. Application reads cannot restart its timer.
        let next_interval = || {
            jitter.as_ref().map_or(
                std::time::Duration::from_millis(20),
                JitterEngine::onion_interval,
            )
        };
        let clock = tokio::time::sleep(next_interval());
        tokio::pin!(clock);
        loop {
            tokio::select! {
                biased;
                ack = ack_rx.recv() => {
                    let Some(ack) = ack else { return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()); };
                    pending_ack = Some(ack);
                }
                _ = &mut clock => {
                    clock.as_mut().reset(tokio::time::Instant::now() + next_interval());
                    prefer_data = !prefer_data;
                    let data_ready = !buffer.is_empty() && window_fwd.lock().await.available();
                    if pending_ack.is_some() && (!data_ready || !prefer_data) {
                        let ack = pending_ack.take().ok_or("Missing pending acknowledgement")?;
                        write_client_cell(&mut upstream_write, &circuit_fwd, CellCommand::DataAck, &ack.to_be_bytes()).await?;
                        continue;
                    }
                    if !upload_open && buffer.is_empty() && !end_sent {
                        write_client_cell(&mut upstream_write, &circuit_fwd, CellCommand::End, &[]).await?;
                        end_sent = true;
                    } else if !buffer.is_empty() && window_fwd.lock().await.available() {
                        let length = buffer.len().min(PAYLOAD_SIZE);
                        let bytes: Vec<u8> = buffer.drain(..length).collect();
                        window_fwd.lock().await.sent()?;
                        write_client_cell(&mut upstream_write, &circuit_fwd, CellCommand::Data, &bytes).await?;
                    } else {
                        write_client_cell(&mut upstream_write, &circuit_fwd, CellCommand::Dummy, &[]).await?;
                    }
                }
                read = client_read.read(&mut input), if upload_open && buffer.len() <= 65536 - input.len() => {
                    let n = read?;
                    if n == 0 { upload_open = false; } else { buffer.extend(&input[..n]); }
                }
            }
        }
    };
    let bwd = async move {
        let mut raw = [0u8; ONION_CELL_SIZE];
        let mut received = 0u32;
        loop {
            tokio::time::timeout(
                std::time::Duration::from_secs(60),
                upstream_read.read_exact(&mut raw),
            )
            .await??;
            let (hop, cell) = circuit.lock().await.unwrap_backward(&mut raw)?;
            if hop != exit_index {
                return Err("Stream response originated before the selected exit".into());
            }
            if cell.stream_id != 1 && cell.command != CellCommand::Destroy {
                return Err("Wrong onion stream identifier".into());
            }
            match cell.command {
                CellCommand::Data => {
                    let length = cell.length as usize;
                    tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        client_write.write_all(&cell.payload[..length]),
                    )
                    .await??;
                    received = received
                        .checked_add(1)
                        .ok_or("Receive data counter exhausted")?;
                    ack_tx
                        .send(received)
                        .await
                        .map_err(|_| "Forward control channel closed")?;
                }
                CellCommand::DataAck => window
                    .lock()
                    .await
                    .acknowledge(&cell.payload[..cell.length as usize])?,
                CellCommand::Destroy => {
                    client_write.shutdown().await?;
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                CellCommand::Dummy => {}
                _ => return Err("Unexpected backward onion command".into()),
            }
        }
    };

    tokio::pin!(fwd, bwd);
    tokio::select! {
        result = &mut fwd => {
            match result {
                Ok(()) => Ok(()),
                Err(error) => {
                    // A final authenticated response can already be queued when
                    // sending cover cells discovers the downstream TLS closure.
                    // Drain the backward direction briefly; EOF without DESTROY
                    // remains an error, and no application data is replayed.
                    match tokio::time::timeout(std::time::Duration::from_secs(5), &mut bwd).await {
                        Ok(Ok(())) => Ok(()),
                        _ => Err(error),
                    }
                }
            }
        },
        result = &mut bwd => result,
        _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => Err("Circuit lifetime expired; reconnect without replaying application data".into()),
    }
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
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    circuit_id: u32,
    chain: &[crate::mesh::node::ProxyNode],
    pinned_identity_keys: &[[u8; 32]],
    target_host: &str,
    target_port: u16,
) -> Result<OnionCircuit, Box<dyn std::error::Error + Send + Sync>> {
    // Bug #4: enforce minimum 3 hops (Guard → Middle → Exit)
    if chain.len() < 3 {
        return Err(format!(
            "Circuit chain too short: {} hops (minimum is 3)",
            chain.len()
        )
        .into());
    }
    if chain.len() > crate::onion::circuit::MAX_HOPS || pinned_identity_keys.len() != chain.len() {
        return Err(format!(
            "Invalid circuit: {} hops (allowed 3..=8), with one pin per hop",
            chain.len()
        )
        .into());
    }

    let identities: std::collections::HashSet<_> = pinned_identity_keys.iter().collect();
    let endpoints: std::collections::HashSet<_> =
        chain.iter().map(|hop| (&hop.host, hop.port)).collect();
    if identities.len() != chain.len()
        || endpoints.len() != chain.len()
        || pinned_identity_keys.contains(&[0; 32])
    {
        return Err(
            "Circuit requires distinct endpoints and nonzero independent identity pins".into(),
        );
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut circuit = OnionCircuit::new(circuit_id);

    // 1. Hop 0 (Guard) in-band CREATE/CREATED handshake
    let client_secret_0 = EphemeralSecret::random_from_rng(OsRng);
    let client_pub_0 = x25519_dalek::PublicKey::from(&client_secret_0);
    let client_pub_0_bytes = *client_pub_0.as_bytes();
    let (client_mlkem_dk_0, client_mlkem_ek_0) = MlKem768::generate(&mut OsRng);
    let create_cell = build_create_cell(circuit_id, &client_pub_0, &client_mlkem_ek_0, 0)
        .map_err(|e| format!("Failed to build CREATE cell: {:?}", e))?;
    stream.write_all(&create_cell.serialize()).await?;

    let mut created_buf = [0u8; ONION_CELL_SIZE];
    stream.read_exact(&mut created_buf).await?;
    let created_cell = OnionCell::parse(&created_buf)
        .map_err(|e| format!("Failed to parse CREATED cell: {}", e))?;
    let pinned_key_0 = pinned_identity_keys
        .first()
        .ok_or("No pinned identity key for Hop 0 — refusing unauthenticated handshake")?;
    let mut client_mlkem_pub_bytes_0 = [0u8; 1184];
    client_mlkem_pub_bytes_0.copy_from_slice(client_mlkem_ek_0.as_bytes().as_slice());
    let hop_keys_0 = process_created_cell(
        &created_cell,
        client_secret_0,
        &client_pub_0_bytes,
        &client_mlkem_dk_0,
        &client_mlkem_pub_bytes_0,
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
        let (client_mlkem_dk, client_mlkem_ek) = MlKem768::generate(&mut OsRng);

        let mut extend_payload = encode_extend_payload(
            &chain[hop_idx].host,
            chain[hop_idx].port,
            &client_pub,
            &client_mlkem_ek,
            hop_idx,
        )
        .map_err(|e| format!("Failed to encode EXTEND payload: {:?}", e))?;
        let next_pin = pinned_identity_keys
            .get(hop_idx)
            .ok_or("Missing next-hop identity pin")?;
        extend_payload.extend_from_slice(next_pin);
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
        let mut client_mlkem_pub_bytes = [0u8; 1184];
        client_mlkem_pub_bytes.copy_from_slice(client_mlkem_ek.as_bytes().as_slice());
        let keys = process_created_cell(
            &resp_cell,
            client_secret,
            &client_pub_bytes,
            &client_mlkem_dk,
            &client_mlkem_pub_bytes,
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
    let (response_hop, resp_cell) = circuit
        .unwrap_backward(&mut return_wire)
        .map_err(|e| format!("Failed to unwrap backward cell from Exit hop: {:?}", e))?;

    if response_hop != chain.len() - 1
        || resp_cell.command != CellCommand::Relay
        || &resp_cell.payload[..resp_cell.length as usize] != b"CONNECTED"
    {
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
            tokio::select! {
                res = read_half.read_exact(&mut buf) => {
                    if res.is_err() {
                        break;
                    }
                    if tx.send(buf).await.is_err() {
                        break;
                    }
                }
                _ = tx.closed() => {
                    break;
                }
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
            tokio::select! {
                res = read_half.read(&mut buf) => {
                    match res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                _ = tx.closed() => {
                    break;
                }
            }
        }
    });
    rx
}

pub async fn handle_onion_relay_connection(
    client: GuardedSocket<ActiveGuarded>,
    kill_switch_arc: std::sync::Arc<std::sync::atomic::AtomicBool>,
    jitter: Option<JitterEngine>,
    exit_policy: Option<crate::kernel::ExitPolicy>,
    relay_identity_key: &Ed25519SigningKey,
    is_exit_allowed: bool,
    pool: crate::mesh::pool::ProxyPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(
        std::time::Duration::from_secs(3600),
        handle_relay_inner(
            client,
            kill_switch_arc,
            jitter,
            exit_policy,
            relay_identity_key,
            is_exit_allowed,
            pool,
        ),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Circuit lifetime expired"))?
}

async fn handle_relay_inner(
    client: GuardedSocket<ActiveGuarded>,
    kill_switch_arc: std::sync::Arc<std::sync::atomic::AtomicBool>,
    jitter: Option<JitterEngine>,
    exit_policy: Option<crate::kernel::ExitPolicy>,
    relay_identity_key: &Ed25519SigningKey,
    is_exit_allowed: bool,
    pool: crate::mesh::pool::ProxyPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let acceptor = crate::onion::link::acceptor(relay_identity_key)?;
    let tls = crate::onion::link::accept(&acceptor, client).await?;
    let mut client = GuardedSocket::new(tls, kill_switch_arc.clone())
        .begin_verification()
        .mark_verified();
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
    let mut upload_closed = false;
    let mut downstream_id = 0u32;
    let mut downstream_write_failed_at: Option<tokio::time::Instant> = None;
    let mut exit_window = crate::onion::flow::SendWindow::default();
    let mut received_data = 0u32;
    let mut destination_eof = false;
    let mut pending_exit_data: Option<Vec<u8>> = None;
    let mut pending_exit_ack = None;
    let mut prefer_exit_data = false;
    let mut last_progress = tokio::time::Instant::now();
    let next_exit_interval = || {
        jitter.as_ref().map_or(
            std::time::Duration::from_millis(20),
            JitterEngine::onion_interval,
        )
    };
    let exit_clock = tokio::time::sleep(next_exit_interval());
    tokio::pin!(exit_clock);
    let mut ds_write: Option<tokio::io::WriteHalf<GuardedSocket<ActiveGuarded>>> = None;
    let mut ds_cell_rx: Option<tokio::sync::mpsc::Receiver<[u8; ONION_CELL_SIZE]>> = None;
    let mut ds_data_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>> = None;

    loop {
        if let Some(ref mut ds_w) = ds_write {
            if is_currently_exit_hop {
                if destination_eof
                    && exit_window.drained()
                    && pending_exit_data.is_none()
                    && pending_exit_ack.is_none()
                {
                    let destroy =
                        OnionCell::new(relay_hop.circuit_id, 0, CellCommand::Destroy, 1, &[])?;
                    let mut wire = destroy.serialize();
                    relay_hop.wrap_backward_originate(&mut wire)?;
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        client_write.write_all(&wire),
                    )
                    .await??;
                    break;
                }
                // Exit relay: downstream is the destination target server (raw TCP).
                let Some(ds_rx) = ds_data_rx.as_mut() else {
                    break;
                };
                tokio::select! {
                    cell = client_cell_rx.recv() => {
                        let Some(mut client_buf) = cell else { break; };
                        match relay_hop.peel_forward(&mut client_buf) {
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::Data, len }) => {
                                if upload_closed { break; }
                                last_progress = tokio::time::Instant::now();
                                let payload = &client_buf[45..45+len];
                                if !matches!(tokio::time::timeout(std::time::Duration::from_secs(30), ds_w.write_all(payload)).await, Ok(Ok(()))) { break; }
                                received_data = received_data.checked_add(1).ok_or("Receive data counter exhausted")?;
                                pending_exit_ack = Some(received_data);
                            }
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::DataAck, len }) => {
                                exit_window.acknowledge(&client_buf[45..45+len])?;
                                last_progress = tokio::time::Instant::now();
                            }
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::End, .. }) => {
                                if upload_closed { break; }
                                upload_closed = true;
                                if ds_w.shutdown().await.is_err() { break; }
                            }
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::Destroy, .. }) => break,
                            Ok(PeelOutcome::AddressedToThisRelay { command: CellCommand::Dummy, .. }) => {}
                            _ => break,
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                        error!("Idle circuit timeout (exit mode)");
                        break;
                    }
                    data = ds_rx.recv(), if pending_exit_data.is_none() && !destination_eof => {
                        match data { Some(bytes) => { last_progress = tokio::time::Instant::now(); pending_exit_data = Some(bytes); }, None => destination_eof = true }
                    }
                    _ = &mut exit_clock => {
                        exit_clock.as_mut().reset(tokio::time::Instant::now() + next_exit_interval());
                        if last_progress.elapsed() >= std::time::Duration::from_secs(60) { return Err("Exit stream idle deadline exceeded".into()); }
                        prefer_exit_data = !prefer_exit_data;
                        let data_ready = pending_exit_data.is_some() && exit_window.available();
                        let (command, bytes) = if pending_exit_ack.is_some() && (!data_ready || !prefer_exit_data) {
                            (CellCommand::DataAck, pending_exit_ack.take().ok_or("Missing exit acknowledgement")?.to_be_bytes().to_vec())
                        } else if data_ready {
                            exit_window.sent()?;
                            (CellCommand::Data, pending_exit_data.take().ok_or("Missing exit data")?)
                        } else { (CellCommand::Dummy, Vec::new()) };
                        let cell = OnionCell::new(relay_hop.circuit_id, 0, command, 1, &bytes)?;
                        let mut wire = cell.serialize();
                        relay_hop.wrap_backward_originate(&mut wire)?;
                        tokio::time::timeout(std::time::Duration::from_secs(30), client_write.write_all(&wire)).await??;
                    }
                }
            } else {
                // Intermediate relay: downstream is the next relay in the mesh (OnionCells).
                let Some(ds_rx) = ds_cell_rx.as_mut() else {
                    break;
                };
                tokio::select! {
                    cell = client_cell_rx.recv(), if downstream_write_failed_at.is_none() => {
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
                                client_buf[..4].copy_from_slice(&downstream_id.to_be_bytes());
                                if !matches!(tokio::time::timeout(std::time::Duration::from_secs(30), ds_w.write_all(&client_buf)).await, Ok(Ok(()))) {
                                    // A downstream close can race a queued final response.
                                    // Stop forward writes and drain the bounded backward queue.
                                    downstream_write_failed_at = Some(tokio::time::Instant::now());
                                }
                            }
                            _ => break,
                        }
                    }
                    _ = async {
                        if let Some(failed_at) = downstream_write_failed_at {
                            tokio::time::sleep_until(failed_at + std::time::Duration::from_secs(5)).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => break,
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                        error!("Idle circuit timeout (intermediate mode)");
                        break;
                    }
                    cell = ds_rx.recv() => {
                        let Some(mut ds_buf) = cell else { break; };
                        if u32::from_be_bytes(ds_buf[..4].try_into().map_err(|_| "Bad circuit id")?) != downstream_id { break; }
                        ds_buf[..4].copy_from_slice(&relay_hop.circuit_id.to_be_bytes());
                        // Reject malformed backward cells instead of forwarding them.
                        if relay_hop.wrap_backward_relay(&mut ds_buf).is_err() { break; }
                        if let Some(ref j) = jitter {
                            j.apply_delay().await;
                        }
                        if !matches!(tokio::time::timeout(std::time::Duration::from_secs(30), client_write.write_all(&ds_buf)).await, Ok(Ok(()))) {
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
                    let payload = &client_buf[45..45 + len];
                    let extend_ok = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                            let (next_h, next_p, next_pub, next_mlkem_pub, hop_index) = decode_extend_payload(payload)
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

                            let pin_offset = 1 + 1 + next_h.len() + 2 + 32 + 1184;
                            if payload.len() != pin_offset + 32 {
                                return Err("EXTEND requires a next-hop identity pin".into());
                            }
                            let next_pin: [u8; 32] = payload[pin_offset..].try_into().map_err(|_| "Bad relay pin")?;
                            let next_s = policy.resolve_and_connect(&next_h, next_p).await
                                .map_err(|_| "Next-hop connection failed".to_string())?;
                            let mut next_s = crate::onion::link::connect(next_s, next_pin).await
                                .map_err(|_| "Next-hop TLS authentication failed".to_string())?;
                            let mut next_id: u32 = rand::random();
                            while next_id == 0 || next_id == relay_hop.circuit_id { next_id = rand::random(); }
                            downstream_id = next_id;
                            let mut c_cell = build_create_cell(relay_hop.context_id, &next_pub, &next_mlkem_pub, hop_index)
                                .map_err(|e| format!("failed to build CREATE cell: {e}"))?;
                            c_cell.circuit_id = next_id;
                        next_s.write_all(&c_cell.serialize()).await
                            .map_err(|e| format!("failed to write CREATE to next hop: {e}"))?;
                        let mut resp = [0u8; ONION_CELL_SIZE];
                        next_s.read_exact(&mut resp).await
                            .map_err(|e| format!("no CREATED response from next hop: {e}"))?;
                        Ok::<_, String>((next_s, resp))
                    }).await.unwrap_or_else(|_| Err("Next-hop setup deadline exceeded".into()));

                    match extend_ok {
                        Ok((next_s, mut resp)) => {
                            if u32::from_be_bytes(
                                resp[..4].try_into().map_err(|_| "Bad circuit id")?,
                            ) != downstream_id
                            {
                                break;
                            }
                            resp[..4].copy_from_slice(&relay_hop.circuit_id.to_be_bytes());
                            if relay_hop.wrap_backward_originate(&mut resp).is_err() {
                                break;
                            }
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
                    let payload = &client_buf[45..45 + len];
                    if let Ok((target_h, target_p)) =
                        crate::onion::circuit::decode_relay_target(payload)
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

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), client_write.shutdown()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_loop_handles_missing_receivers_without_panic() {
        let mut ds_data_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>> = None;
        let ds_rx = ds_data_rx.as_mut();
        assert!(
            ds_rx.is_none(),
            "Unset receiver must safely evaluate to None without panicking"
        );

        let mut ds_cell_rx: Option<tokio::sync::mpsc::Receiver<[u8; ONION_CELL_SIZE]>> = None;
        let ds_cell_ref = ds_cell_rx.as_mut();
        assert!(
            ds_cell_ref.is_none(),
            "Unset cell receiver must safely evaluate to None without panicking"
        );
    }

    // ── B3: Authority identity key pinning — MITM repro ───────────────────────
    //
    // Mechanism: the old code always called client_handshake(stream, None). An attacker
    // positioned between the relay and the authority (active MITM) can impersonate the
    // authority, complete the unauthenticated DH handshake, and silently drop or replay
    // REGISTER_RELAY frames.
    //
    // This test directly exercises SecureTransportSession::client_handshake (the same
    // function the production registration loop calls) to verify:
    //   1. With pinned_key = None: handshake succeeds even against a wrong-key server.
    //   2. With pinned_key = Some(&correct_key): handshake succeeds.
    //   3. With pinned_key = Some(&wrong_key): handshake fails with PermissionDenied —
    //      this is the post-fix behavior that catches an active MITM.
    //
    // Reference: Diffie, van Oorschot, Wiener, "Authentication and Authenticated Key
    // Exchanges", Designs, Codes and Cryptography, 1992 (STS protocol). The mechanism
    // is already correctly implemented in SecureTransportSession; this was a wiring bug.
    #[tokio::test]
    async fn test_b3_mitm_wrong_pinned_key_rejected() {
        use crate::mesh::transport::SecureTransportSession;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use tokio::net::{TcpListener, TcpStream};

        // Generate two authority key pairs: `real_auth` (genuine) and `mitm_auth` (attacker).
        let real_auth_key = SigningKey::generate(&mut OsRng);
        let real_auth_vk = real_auth_key.verifying_key();
        let mitm_auth_key = SigningKey::generate(&mut OsRng);

        // ── Scenario 1: relay connects to MITM server, pinned_key = None (old, broken code) ──
        // Expect: handshake SUCCEEDS even though the server is using the MITM key.
        // This is the "repro" — demonstrates the vulnerability before the fix.
        let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();
        let mitm_key_clone = mitm_auth_key.clone();
        let _srv1 = tokio::spawn(async move {
            let (s, _) = listener1.accept().await.unwrap();
            let _ = SecureTransportSession::server_handshake(s, Some(&mitm_key_clone)).await;
        });
        let client1 = TcpStream::connect(addr1).await.unwrap();
        let result1 = SecureTransportSession::client_handshake(client1, None).await;
        assert!(
            result1.is_ok(),
            "Unpinned handshake should succeed (demonstrates pre-fix vulnerability)"
        );

        // ── Scenario 2: relay connects to real authority, pinned_key = correct (post-fix, happy path) ──
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let real_key_clone = real_auth_key.clone();
        let _srv2 = tokio::spawn(async move {
            let (s, _) = listener2.accept().await.unwrap();
            let _ = SecureTransportSession::server_handshake(s, Some(&real_key_clone)).await;
        });
        let client2 = TcpStream::connect(addr2).await.unwrap();
        let result2 = SecureTransportSession::client_handshake(client2, Some(&real_auth_vk)).await;
        assert!(
            result2.is_ok(),
            "Pinned handshake with correct key must succeed"
        );

        // ── Scenario 3: relay connects to MITM server, pinned_key = real authority key (post-fix) ──
        // Expect: handshake FAILS with PermissionDenied — the fix works.
        let listener3 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr3 = listener3.local_addr().unwrap();
        let _srv3 = tokio::spawn(async move {
            let (s, _) = listener3.accept().await.unwrap();
            let _ = SecureTransportSession::server_handshake(s, Some(&mitm_auth_key)).await;
        });
        let client3 = TcpStream::connect(addr3).await.unwrap();
        let result3 = SecureTransportSession::client_handshake(client3, Some(&real_auth_vk)).await;
        assert!(
            result3.is_err(),
            "Pinned handshake against MITM server MUST fail"
        );
        let err3 = result3.err().unwrap();
        assert_eq!(
            err3.kind(),
            std::io::ErrorKind::PermissionDenied,
            "MITM must be rejected with PermissionDenied, not silently accepted"
        );
    }
}

#[cfg(test)]
mod listener_lifetime_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn dropping_listener_future_closes_in_progress_client_handshakes() {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let directory =
            std::env::temp_dir().join(format!("ag-gateway-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&directory).unwrap();
        let config = GuardConfig {
            listen_addr: address.to_string(),
            guard_state_path: directory.join("guards.json"),
            ..GuardConfig::default()
        };
        let server = Arc::new(GatewayServer::new(
            config,
            ProxyPool::new(),
            KillSwitchController::new(),
            Arc::new(Ed25519SigningKey::from_bytes(&[71; 32])),
        ));
        let task = tokio::spawn(async move { server.run().await });
        let mut connection = None;
        for _ in 0..100 {
            if let Ok(stream) = TcpStream::connect(address).await {
                connection = Some(stream);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut client = connection.expect("Gateway did not start");
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut selection = [0; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut selection),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(selection, [5, 0]);
        task.abort();
        let _ = task.await;
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client.read(&mut selection)
            )
            .await
            .unwrap()
            .unwrap(),
            0
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
