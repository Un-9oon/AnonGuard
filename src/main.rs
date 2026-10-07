#![deny(dead_code, unused_variables)]
#![forbid(unsafe_code)]

//! Standalone CLI daemon for the AnonGuard engine.

use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, warn};

use anonguard::core::GuardConfig;
use anonguard::gateway::GatewayServer;
use anonguard::kernel::KillSwitchController;
use anonguard::mesh::{ProxyPool, DEFAULT_POW_DIFFICULTY};

#[derive(Parser, Debug)]
#[command(
    name = "anonguard-daemon",
    version = "0.2.0",
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

    /// Enable statistical RMT (Wigner-surmise) traffic-timing morphing. This is a
    /// classical statistical technique from random matrix theory, not quantum computing.
    #[arg(long = "rmt-morphing", visible_aliases = ["rmt", "quantum"], default_value_t = false)]
    rmt_morphing: bool,

    /// Statistical RMT ensemble type: "goe" (Gaussian Orthogonal) or "gue" (Gaussian Unitary)
    #[arg(
        long = "rmt-ensemble",
        visible_alias = "quantum-ensemble",
        default_value = "goe"
    )]
    rmt_ensemble: String,

    /// Enable background traffic chaffing (decoy TLS streams)
    #[arg(long, default_value_t = false)]
    chaffing: bool,

    /// Run as a SOCKS5 relay node (bypasses proxy pool and connects directly)
    #[arg(short, long, default_value_t = false)]
    relay: bool,

    /// Run as a Directory Authority Tracker (legacy mode)
    #[arg(long, default_value_t = false)]
    tracker: bool,

    /// Run as a Cryptographic Directory Authority Node (M-of-N consensus)
    #[arg(long, default_value_t = false)]
    authority: bool,

    /// Directory Authority Identifier (e.g. auth-zurich)
    #[arg(long, default_value = "auth-primary")]
    authority_id: String,

    /// Comma-separated list of Directory Authority endpoints
    #[arg(long)]
    authorities: Option<String>,

    /// Comma-separated list of Directory Authority public keys (e.g. auth-primary:hex_key,...)
    #[arg(long)]
    authority_keys: Option<String>,

    /// Quorum threshold for Directory Authority consensus
    #[arg(long, default_value_t = 1)]
    quorum_threshold: usize,

    /// Enable 3-hop Layered Onion Encryption (Sphinx / Tor-style cell peeling)
    #[arg(long, default_value_t = false)]
    onion: bool,

    /// Enforce BGP /16 Subnet Diversity across circuit hops (Sybil resistance)
    #[arg(long, default_value_t = true)]
    enforce_subnet_diversity: bool,

    /// Run as a Reverse Relay Node (Volunteer mode behind NAT)
    #[arg(long, default_value_t = false)]
    reverse_relay: bool,

    /// Tracker URL to announce this relay to (e.g. http://1.2.3.4:8080)
    #[arg(long)]
    announce: Option<String>,

    /// Allow open, unauthenticated plain SOCKS5 proxying when running in relay mode (off by default)
    #[arg(long, default_value_t = false)]
    allow_open_socks5: bool,

    /// Allow exit relays to connect to private/loopback networks (off by default to prevent SSRF)
    #[arg(long, default_value_t = false)]
    allow_private_exit: bool,

    /// Acknowledge insecure configuration
    #[arg(long, default_value_t = false)]
    i_know_this_is_insecure: bool,
    #[arg(long, default_value_t = false)]
    is_exit: bool,

    /// Apply OS/kernel-level nftables firewall kill switch (Linux only, requires root/CAP_NET_ADMIN)
    #[cfg(target_os = "linux")]
    #[arg(long, default_value_t = false)]
    enable_firewall_killswitch: bool,

    /// Registration PoW difficulty in leading zero bits (see mesh::sybil::DEFAULT_POW_DIFFICULTY)
    #[arg(long, default_value_t = DEFAULT_POW_DIFFICULTY)]
    pow_difficulty: u32,

    /// Number of connection failures per second required to trip the kill switch.
    /// Lower values are more sensitive (fewer false-negatives but more false-positive trips);
    /// higher values give a larger window before fail-closed engages.
    #[arg(long, default_value_t = 5)]
    killswitch_trip_threshold: usize,

    /// Tracker URL to fetch active nodes from (e.g. http://1.2.3.4:8080)
    #[arg(long)]
    fetch_from: Option<String>,

    /// Path to persist the relay's long-term Ed25519 identity key
    #[arg(long)]
    identity_key_path: Option<PathBuf>,

    /// Path to persist entry guard pins (must be writable by the daemon user)
    #[arg(long)]
    guard_state_path: Option<PathBuf>,

    /// Refuse to start if hardware/kernel-level fail-closed enforcement (Linux nftables) is unavailable
    #[arg(long, default_value_t = false)]
    strict_fail_closed: bool,

    /// Expose Prometheus metrics endpoint on local address (e.g. 127.0.0.1:9052)
    #[arg(long)]
    metrics_addr: Option<String>,

    /// Print current daemon health status summary and exit
    #[arg(long, default_value_t = false)]
    status: bool,
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn load_or_create_identity_key(path: &std::path::Path) -> ed25519_dalek::SigningKey {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use zeroize::Zeroize;

    if path.exists() {
        match std::fs::read(path) {
            Ok(mut bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(mut arr) => {
                    let key = ed25519_dalek::SigningKey::from_bytes(&arr);
                    arr.zeroize();
                    bytes.zeroize();
                    return key;
                }
                Err(_) => {
                    bytes.zeroize();
                    error!(
                        "FATAL: Identity key file {:?} is corrupt (expected 32 bytes, got {}). \
                        Delete it to generate a fresh key — existing relays will need to \
                        re-handshake after the change.",
                        path,
                        bytes.len()
                    );
                    std::process::exit(1);
                }
            },
            Err(e) => {
                error!("FATAL: Cannot read identity key file {:?}: {}", path, e);
                std::process::exit(1);
            }
        }
    }

    // Key file does not exist — create it with strict permissions
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            error!("FATAL: Cannot create key directory {:?}: {}", parent, e);
            std::process::exit(1);
        }
    }
    let mut temp_path = path.to_path_buf();
    temp_path.set_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut f = match options.open(&temp_path) {
        Ok(f) => f,
        Err(e) => {
            error!(
                "FATAL: Cannot create temporary identity key file {:?}: {}",
                temp_path, e
            );
            std::process::exit(1);
        }
    };
    if let Err(e) = f.write_all(&key.to_bytes()) {
        error!(
            "FATAL: Cannot write temporary identity key file {:?}: {}",
            temp_path, e
        );
        let _ = std::fs::remove_file(&temp_path);
        std::process::exit(1);
    }
    if let Err(e) = f.sync_all() {
        error!(
            "FATAL: Cannot sync temporary identity key file {:?}: {}",
            temp_path, e
        );
        let _ = std::fs::remove_file(&temp_path);
        std::process::exit(1);
    }

    // Belt-and-suspenders: set permissions explicitly in case umask interfered
    #[cfg(unix)]
    if let Err(e) = std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)) {
        error!(
            "FATAL: Cannot set permissions on temporary identity key file {:?}: {}",
            temp_path, e
        );
        let _ = std::fs::remove_file(&temp_path);
        std::process::exit(1);
    }

    // Atomic rename
    if let Err(e) = std::fs::rename(&temp_path, path) {
        error!(
            "FATAL: Cannot atomically rename identity key file to {:?}: {}",
            path, e
        );
        let _ = std::fs::remove_file(&temp_path);
        std::process::exit(1);
    }
    key
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if let Err(err) = anonguard::kernel::check_fail_closed_guarantee(
        cfg!(target_os = "linux"),
        args.strict_fail_closed,
    ) {
        error!("{}", err);
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    if args.strict_fail_closed && !args.enable_firewall_killswitch {
        return Err("--strict-fail-closed requires --enable-firewall-killswitch".into());
    }

    if args.status {
        println!("=== AnonGuard Daemon Status ===");
        println!("Version: 0.2.0");

        let identity_path = args.identity_key_path.unwrap_or_else(|| {
            let mut p =
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
            p.push(".local/share/anonguard/identity.key");
            p
        });
        if identity_path.exists() {
            println!("Identity: PRESENT (daemon health not checked)");
        } else {
            println!("Identity: MISSING (daemon health not checked)");
        }

        println!(
            "Fail-Closed Guarantee: {}",
            if cfg!(target_os = "linux") {
                "AVAILABLE ON LINUX; installation not checked"
            } else {
                "APPLICATION-LAYER ONLY"
            }
        );
        return Ok(());
    }

    if args.onion && args.authorities.is_none() && args.pool.is_none() && args.proxy.is_none() {
        return Err("Onion mode requires configured directory authorities or a relay pool".into());
    }
    if !args.jitter_lambda.is_finite() || args.jitter_lambda <= 0.0 {
        return Err("--jitter-lambda must be finite and positive".into());
    }
    if !matches!(args.rmt_ensemble.to_lowercase().as_str(), "goe" | "gue") {
        return Err("--rmt-ensemble must be goe or gue".into());
    }
    if args.authorities.is_some() && (args.authority_keys.is_none() || args.quorum_threshold == 0) {
        return Err(
            "Directory authorities require pinned keys and a positive quorum threshold".into(),
        );
    }

    if let Some(ref addr_str) = args.metrics_addr {
        match addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                if let Err(e) = anonguard::observability::init_prometheus(addr) {
                    warn!(
                        "Failed to initialize Prometheus metrics endpoint on {}: {}",
                        addr_str, e
                    );
                }
            }
            Err(e) => {
                error!("Invalid --metrics-addr '{}': {}", addr_str, e);
            }
        }
    }

    info!(
        version = "0.2.0",
        listen_addr = %args.listen,
        "[AnonGuard] Starting Research-Grade Anonymity Gateway..."
    );

    #[cfg(target_os = "linux")]
    if args.enable_firewall_killswitch {
        let (proxy_ip, proxy_port) = match args.listen.split_once(':') {
            Some((ip, p)) => (ip, p.parse::<u16>().unwrap_or(9050)),
            None => ("127.0.0.1", 9050),
        };
        let netns = anonguard::kernel::NetnsConfig::new("anonguard", proxy_ip, proxy_port);
        match netns.apply_nftables_rules() {
            Ok(_) => {
                info!("Successfully applied OS/kernel-level nftables firewall killswitch");
            }
            Err(e) => {
                return Err(
                    format!("Requested kernel firewall could not be installed: {e}").into(),
                );
            }
        }
    }

    let directory_authorities = if let Some(ref auths) = args.authorities {
        auths.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        Vec::new()
    };

    let mut trusted_authorities: std::collections::HashMap<String, ed25519_dalek::VerifyingKey> =
        std::collections::HashMap::new();
    if let Some(ref keys_str) = args.authority_keys {
        for entry in keys_str.split(',') {
            let (id_or_addr, key_hex) = entry
                .trim()
                .rsplit_once(':')
                .ok_or("Invalid authority key: expected id:64_HEX_KEY")?;
            let id = id_or_addr.trim().to_string();
            if id.is_empty() {
                return Err("Authority key identifier must not be empty".into());
            }
            let bytes = decode_hex_32(key_hex.trim()).ok_or("Invalid authority key hex")?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
            if trusted_authorities.insert(id, vk).is_some() {
                return Err("Duplicate authority key identifier".into());
            }
        }
    }
    if !directory_authorities.is_empty() && args.quorum_threshold > trusted_authorities.len() {
        return Err("Quorum threshold exceeds the number of trusted authority keys".into());
    }

    let config = GuardConfig {
        listen_addr: args.listen.clone(),
        enable_jitter: args.jitter,
        jitter_lambda: args.jitter_lambda,
        enable_chaos: args.chaos,
        chaos_sigma: args.chaos_sigma,
        chaos_rho: args.chaos_rho,
        chaos_beta: args.chaos_beta,
        enable_rmt_morphing: args.rmt_morphing,
        enable_chaffing: args.chaffing,
        rmt_ensemble: args.rmt_ensemble.clone(),
        enable_onion_routing: args.onion,
        enforce_subnet_diversity: args.enforce_subnet_diversity,
        authority_mode: args.authority,
        authority_id: args.authority_id.clone(),
        directory_authorities,
        relay_mode: args.relay,
        allow_open_socks5: args.allow_open_socks5,
        allow_private_exit: args.allow_private_exit,
        is_exit: args.is_exit,
        reverse_relay_mode: args.reverse_relay,
        tracker_url: args.fetch_from.clone(),
        #[cfg(target_os = "linux")]
        enable_firewall_killswitch: args.enable_firewall_killswitch,
        #[cfg(not(target_os = "linux"))]
        enable_firewall_killswitch: false,
        pow_difficulty: args.pow_difficulty,
        identity_key_path: args.identity_key_path.unwrap_or_else(|| {
            let mut p = std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/anonguard"));
            p.push(".local/share/anonguard/identity.key");
            p
        }),
        guard_state_path: args.guard_state_path.unwrap_or_else(|| {
            let mut p = std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."));
            p.push(".local/share/anonguard/guards.json");
            p
        }),
        ..GuardConfig::default()
    };

    if (config.allow_open_socks5 || config.allow_private_exit) && !args.i_know_this_is_insecure {
        error!("FATAL: You have enabled an insecure configuration flag (allow-open-socks5 or allow-private-exit).");
        error!("This can lead to severe security and privacy compromises.");
        error!("If you are absolutely sure you know what you are doing, re-run with --i-know-this-is-insecure.");
        std::process::exit(1);
    }

    if args.i_know_this_is_insecure {
        warn!("=========================================================================");
        warn!("WARNING: RUNNING IN INSECURE MODE. DO NOT USE THIS IN PRODUCTION.");
        warn!("=========================================================================");
    }

    #[cfg(target_os = "linux")]
    let firewall_enabled = args.enable_firewall_killswitch;
    #[cfg(not(target_os = "linux"))]
    let firewall_enabled = false;

    if args.authority {
        let authority = anonguard::mesh::DirectoryAuthority::with_persistent_key(
            args.authority_id,
            args.listen,
            args.pow_difficulty,
            config.identity_key_path,
        );
        let res = tokio::select! {
            r = authority.run() => r,
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal (Ctrl+C)");
                Ok(())
            }
        };
        #[cfg(target_os = "linux")]
        if firewall_enabled {
            let _ = anonguard::kernel::NetnsConfig::flush_nftables_rules();
        }
        return res;
    }

    if args.tracker {
        let tracker =
            anonguard::mesh::TrackerServer::with_difficulty(args.listen, args.pow_difficulty);
        let res = tokio::select! {
            r = tracker.run() => r,
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal (Ctrl+C)");
                Ok(())
            }
        };
        #[cfg(target_os = "linux")]
        if firewall_enabled {
            let _ = anonguard::kernel::NetnsConfig::flush_nftables_rules();
        }
        return res;
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
            let pow_difficulty = args.pow_difficulty;
            let node_id = format!("relay-{}", my_listen);
            tokio::spawn(async move {
                let host_port = tracker_url.trim_start_matches("http://");
                loop {
                    let now = anonguard::mesh::sybil::current_timestamp_secs();
                    let nonce = match anonguard::mesh::sybil::solve_pow_bounded(
                        &node_id,
                        now,
                        pow_difficulty,
                    ) {
                        Some(n) => n,
                        None => {
                            tracing::error!("Failed to solve PoW within bounds. CPU too slow or difficulty too high!");
                            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                            continue;
                        }
                    };
                    let line = format!("REGISTER_REVERSE {} {} {}\n", node_id, now, nonce);

                    if let Ok(mut stream) = tokio::net::TcpStream::connect(host_port).await {
                        use tokio::io::AsyncWriteExt;
                        let _ = stream.write_all(line.as_bytes()).await;
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
        // Wire Multi-Authority Consensus retrieval & cryptographic quorum verification
        if !config.directory_authorities.is_empty() {
            let pool_clone = pool.clone();
            let auth_endpoints = config.directory_authorities.clone();
            let auth_keys = trusted_authorities.clone();
            let quorum_thresh = if args.quorum_threshold == 0
                && !config.directory_authorities.is_empty()
            {
                warn!("--quorum-threshold 0 is unsafe when --authorities is set; clamping to 1");
                1
            } else {
                args.quorum_threshold
            };

            tokio::spawn(async move {
                loop {
                    // Fix for Critical Bug #1 ("directory trust is effectively 1-of-N"):
                    //
                    // Each Directory Authority only ever signs the ConsensusDocument it built
                    // from its own local view, so no single authority's GET_CONSENSUS response
                    // can carry more than one valid signature. Previously this loop broke out
                    // as soon as ANY one authority answered, meaning `quorum_threshold >= 2`
                    // could never actually be satisfied — the "M-of-N" consensus model
                    // silently degraded to trusting whichever single authority answered first.
                    //
                    // The fix: query every configured authority in this round, fetch each
                    // one's self-signed document, and merge together the documents that agree
                    // on content (same digest — see `ConsensusDocument::merge_signatures_from`)
                    // into one multi-signed document *before* running `verify_quorum` against
                    // it. Only after that merge does `quorum_threshold` mean anything real.
                    let mut fetched_docs: Vec<(String, anonguard::mesh::ConsensusDocument)> =
                        Vec::new();

                    for endpoint in &auth_endpoints {
                        let (auth_id_opt, raw_addr) =
                            if let Some((id, addr)) = endpoint.split_once('@') {
                                (Some(id.trim()), addr.trim())
                            } else {
                                (None, endpoint.as_str())
                            };
                        let host_port = raw_addr.trim_start_matches("http://");
                        let pinned_key = if let Some(aid) = auth_id_opt {
                            auth_keys.get(aid).or_else(|| auth_keys.get(host_port))
                        } else {
                            auth_keys.get(host_port).or_else(|| auth_keys.get(endpoint))
                        };

                        if !auth_keys.is_empty() && pinned_key.is_none() {
                            tracing::error!(
                                endpoint = %endpoint,
                                "Rejected Directory Authority: --authority-keys is configured but no matching key was found for this specific endpoint"
                            );
                            continue;
                        }

                        match tokio::net::TcpStream::connect(host_port).await {
                            Ok(stream) => {
                                match anonguard::mesh::SecureTransportSession::client_handshake(
                                    stream, pinned_key,
                                )
                                .await
                                {
                                    Ok(mut session) => {
                                        // The handshake already verifies `pinned_key` strictly if it is `Some`.
                                        // We no longer need the weak `auth_keys.values().any` check here, which
                                        // was vulnerable to cross-authority MITM.

                                        if session.write_frame(b"GET_CONSENSUS").await.is_ok() {
                                            if let Ok(frame) = session.read_frame().await {
                                                if let Ok(doc) = serde_json::from_slice::<
                                                    anonguard::mesh::ConsensusDocument,
                                                >(
                                                    &frame
                                                ) {
                                                    fetched_docs.push((endpoint.clone(), doc));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            endpoint = %endpoint,
                                            "[AnonGuard Consensus] Secure transport handshake with Directory Authority failed"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    endpoint = %endpoint,
                                    "[AnonGuard Consensus] Failed to connect to Directory Authority"
                                );
                            }
                        }
                    }

                    let docs: Vec<anonguard::mesh::ConsensusDocument> =
                        fetched_docs.iter().map(|(_, doc)| doc.clone()).collect();
                    let now = anonguard::mesh::current_timestamp_secs();

                    let mut quorum_reached = false;
                    match pool_clone
                        .load_from_multi_consensus(&docs, &auth_keys, quorum_thresh, now)
                        .await
                    {
                        Ok(loaded) => {
                            tracing::info!(
                                loaded = loaded,
                                responders = docs.len(),
                                "[AnonGuard Consensus] Verified M-of-N consensus (intersection across authorities) and loaded active relays"
                            );
                            quorum_reached = true;
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "[AnonGuard Consensus] Failed to load relays from directory consensus"
                            );
                        }
                    }
                    if !quorum_reached && !fetched_docs.is_empty() {
                        tracing::warn!(
                            responders = fetched_docs.len(),
                            threshold = quorum_thresh,
                            "[AnonGuard Consensus] No consensus candidate reached quorum this round"
                        );
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                }
            });
        }

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
                                // Clear existing nodes and add new authenticated ones
                                for line in body.lines() {
                                    let trimmed = line.trim();
                                    if !trimmed.is_empty() {
                                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                                        let reverse_uri = if parts.len() >= 2 {
                                            format!("reverse://{}@{}:0", parts[1], parts[0])
                                        } else {
                                            format!("reverse://{}:0", parts[0])
                                        };
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

    let kill_switch = KillSwitchController::with_threshold(
        args.killswitch_trip_threshold,
        std::time::Duration::from_secs(1),
    );
    let relay_identity_key =
        std::sync::Arc::new(load_or_create_identity_key(&config.identity_key_path));
    let gateway = GatewayServer::new(config, pool, kill_switch, relay_identity_key);

    let run_res = tokio::select! {
        res = async {
            if args.reverse_relay {
                if let Some(tracker_url) = args.announce {
                    // Generate a cryptographically random Node ID (fix #15: was ms%10000 — too short)
                    let node_id = format!("node-{:016x}", rand::random::<u64>());
                    gateway.run_reverse_relay(&tracker_url, &node_id).await
                } else {
                    tracing::error!("--announce <tracker_url> is required for --reverse-relay");
                    Ok(())
                }
            } else {
                gateway.run().await
            }
        } => res,
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C), terminating gracefully...");
            Ok(())
        }
        _ = async {
            #[cfg(target_os = "linux")]
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut sig) = signal(SignalKind::terminate()) {
                    sig.recv().await;
                } else {
                    // If we can't register SIGTERM, just block forever so the other arms fire
                    std::future::pending::<()>().await;
                }
            }
            #[cfg(not(target_os = "linux"))]
            std::future::pending::<()>().await;
        } => {
            info!("Received SIGTERM, terminating gracefully...");
            Ok(())
        }
    };

    #[cfg(target_os = "linux")]
    if firewall_enabled {
        info!("Flushing OS/kernel-level nftables firewall kill switch...");
        match anonguard::kernel::NetnsConfig::flush_nftables_rules() {
            Ok(_) => info!("Successfully flushed nftables rules and lifted network lock"),
            Err(e) => warn!(
                "Failed to flush nftables rules on exit (run 'nft delete table inet anonguard_filter' manually): {}",
                e
            ),
        }
    }

    run_res
}
