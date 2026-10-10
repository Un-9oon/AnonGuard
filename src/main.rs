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
    /// Create or validate a private identity key, print its public pin, and exit without networking
    #[arg(long, requires = "identity_key_path", conflicts_with_all = [
        "status", "relay", "authority", "tracker", "reverse_relay", "onion",
        "pool", "proxy", "authorities", "authority_keys", "metrics_addr", "strict_fail_closed"
    ])]
    initialize_identity: bool,
    /// Local address to bind the gateway listener
    #[arg(short, long, default_value = "127.0.0.1:9050")]
    listen: String,

    /// Reachable relay IP:port in signed descriptors; does not configure NAT or bind this address
    #[arg(long, requires = "relay", conflicts_with = "unlisted_bridge")]
    advertise_address: Option<std::net::SocketAddr>,

    /// Path to a text file containing proxy endpoints (one per line)
    #[arg(short, long)]
    pool: Option<PathBuf>,

    /// Inline proxy to load immediately (e.g. socks5://127.0.0.1:1080)
    #[arg(long)]
    proxy: Option<String>,

    /// Enable experimental multiplexed sessions with coordinated padding
    #[arg(long, requires = "onion", conflicts_with_all = ["relay", "authority", "reverse_relay", "tracker", "jitter", "chaos", "rmt_morphing", "chaffing"])]
    padded_sessions: bool,

    /// Shared padding policy; research profiles have no established anonymity benefit
    #[arg(long, requires = "padded_sessions", default_value = "balanced", value_parser = ["balanced", "strict", "research-rmt", "research-poisson"])]
    privacy_profile: String,

    /// Minimum onion circuit length (guard, middle relays, exit)
    #[arg(long, requires = "onion", default_value_t = 3, value_parser = clap::value_parser!(u8).range(3..=8))]
    min_hops: u8,

    /// Maximum randomized onion circuit length; bounded by eligible relays
    #[arg(long, requires = "onion", default_value_t = 5, value_parser = clap::value_parser!(u8).range(3..=8))]
    max_hops: u8,

    /// Enable Poisson timing jitter (experimental traffic-analysis protection)
    #[arg(long, default_value_t = false)]
    jitter: bool,

    /// Rate parameter (lambda) for Poisson timing jitter
    #[arg(long, default_value_t = 0.05)]
    jitter_lambda: f64,

    /// Enable experimental deterministic Lorenz morphing; no proven anonymity benefit
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
    #[arg(
        long = "rmt-morphing",
        visible_alias = "rmt",
        alias = "quantum",
        default_value_t = false
    )]
    rmt_morphing: bool,

    /// Statistical RMT ensemble type: "goe" (Gaussian Orthogonal) or "gue" (Gaussian Unitary)
    #[arg(
        long = "rmt-ensemble",
        alias = "quantum-ensemble",
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

    /// Quorum-signed offline identity retirement policy; applied at restart
    #[arg(long, requires = "authorities", conflicts_with_all = ["initialize_identity", "status", "tracker", "reverse_relay", "fetch_from", "allow_open_socks5", "pool", "proxy"])]
    revocation_policy: Option<PathBuf>,

    /// Quorum threshold for Directory Authority consensus
    #[arg(long, default_value_t = 1)]
    quorum_threshold: usize,

    /// Enable bounded multihop onion encryption with identity-bound relay keys
    #[arg(long, default_value_t = false)]
    onion: bool,

    /// JSON entry transport bindings; requires onion gateway mode (no direct fallback)
    #[arg(long, requires = "onion", conflicts_with_all = ["relay", "authority", "reverse_relay", "initialize_identity", "tracker", "status"])]
    bridge_transports: Option<PathBuf>,

    /// Use independently provisioned unlisted entries, with protected authority bootstrap
    #[arg(long, requires_all = ["bridge_transports", "authority_transports"], conflicts_with_all = ["pool", "proxy", "fetch_from"])]
    private_bridges: bool,

    /// PT bindings for every pinned directory authority; no direct bootstrap fallback
    #[arg(long, requires_all = ["onion", "authorities"], conflicts_with_all = ["relay", "authority", "reverse_relay", "initialize_identity", "tracker", "status", "fetch_from"])]
    authority_transports: Option<PathBuf>,

    /// Unlisted non-exit relay behind a separately supervised PT and loopback backend
    #[arg(long, requires_all = ["relay", "authorities"], conflicts_with_all = ["is_exit", "allow_open_socks5", "announce", "reverse_relay", "authority", "tracker", "initialize_identity"])]
    unlisted_bridge: bool,

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

    /// Linux namespace used for protected applications (not the host transport).
    #[cfg(target_os = "linux")]
    #[arg(long, default_value = "anonguard")]
    namespace_name: String,
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    namespace_proxy: bool,
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    namespace_socket: Option<PathBuf>,

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

    /// Path to persist the relay's long-term composite identity key
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

fn load_or_create_identity_key(path: &std::path::Path) -> anonguard::crypto::identity::SigningKey {
    match anonguard::core::storage::load_or_create_signing_key(path) {
        Ok(key) => key,
        Err(e) => {
            error!(
                "FATAL: Cannot load or persist identity key {:?}: {}",
                path, e
            );
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if args.initialize_identity {
        #[cfg(target_os = "linux")]
        if args.namespace_proxy || args.enable_firewall_killswitch {
            return Err("Identity initialization cannot be combined with namespace startup".into());
        }
        let path = args
            .identity_key_path
            .as_ref()
            .ok_or("Identity path required")?;
        let key = anonguard::core::storage::load_or_create_signing_key(path)?;
        println!(
            "{}",
            serde_json::json!({ "protocol_version": 6, "identity_suite": "Ed25519+ML-DSA-65", "public_key_hybrid_pin": hex::encode(key.verifying_key().to_bytes()), "public_key_hybrid": hex::encode(key.hybrid().public_key().encode()) })
        );
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if args.namespace_proxy {
        let endpoint: std::net::SocketAddr = args.listen.parse()?;
        let socket = args
            .namespace_socket
            .as_ref()
            .ok_or("Namespace proxy requires its private socket")?;
        let config = anonguard::kernel::NetnsConfig::new(
            args.namespace_name,
            endpoint.ip().to_string(),
            endpoint.port(),
        );
        anonguard::kernel::netns::run_namespace_proxy(&config, socket).await?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.enable_firewall_killswitch
        && (args.relay || args.authority || args.tracker || args.reverse_relay)
    {
        return Err("Application namespace isolation is only supported in gateway mode".into());
    }

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
    let listener: std::net::SocketAddr = args
        .listen
        .parse()
        .map_err(|_| "Listener must be a numeric IP:port")?;
    if !args.relay
        && !args.authority
        && !args.tracker
        && !args.reverse_relay
        && !listener.ip().is_loopback()
        && !args.allow_open_socks5
    {
        return Err(
            "A public gateway listener requires explicit --allow-open-socks5 authorization".into(),
        );
    }
    if args.min_hops > args.max_hops {
        return Err("--min-hops must not exceed --max-hops".into());
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

    let directory_authorities = if let Some(ref auths) = args.authorities {
        auths.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        Vec::new()
    };

    let mut trusted_authorities: std::collections::HashMap<
        String,
        anonguard::crypto::identity::VerifyingKey,
    > = std::collections::HashMap::new();
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
            let vk = anonguard::crypto::identity::VerifyingKey::from_bytes(&bytes)
                .map_err(|_| "Invalid or duplicate directory identity pin")?;
            if trusted_authorities.insert(id, vk).is_some() {
                return Err("Duplicate authority key identifier".into());
            }
        }
    }
    if directory_authorities.len() > 16 {
        return Err("At most 16 directory authorities are supported".into());
    }
    if !directory_authorities.is_empty()
        && args.quorum_threshold < (2 * directory_authorities.len()) / 3 + 1
    {
        return Err("Directory quorum must exceed two thirds of configured authorities".into());
    }
    if !directory_authorities.is_empty() && args.quorum_threshold > trusted_authorities.len() {
        return Err("Quorum threshold exceeds the number of trusted authority keys".into());
    }

    let mut authority_identity_keys = Vec::new();
    let mut authority_endpoints = Vec::new();
    let mut bound_authorities = std::collections::HashMap::new();
    let mut authority_peers = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for endpoint in &directory_authorities {
        let (id, addr) = endpoint
            .split_once('@')
            .ok_or("Authority endpoint must be identity@address")?;
        if id.is_empty() || addr.is_empty() {
            return Err("Empty authority identity or address".into());
        }
        let addr = addr.trim_start_matches("http://");
        let key = trusted_authorities
            .get(id)
            .or_else(|| trusted_authorities.get(addr))
            .ok_or("Every authority endpoint requires a matching pinned key")?;
        if !seen_keys.insert(key.to_bytes()) {
            return Err("Authority endpoints must have distinct signing keys".into());
        }
        authority_endpoints.push(anonguard::core::config::AuthorityEndpoint {
            identity: id.to_string(),
            address: addr.to_string(),
            public_key: key.to_bytes(),
        });
        if bound_authorities.insert(id.to_string(), *key).is_some() {
            return Err("Duplicate authority endpoint identity".into());
        }
        authority_identity_keys.push(key.to_bytes());
        authority_peers.push((addr.to_string(), Some(*key)));
    }

    // Validate the same bounded endpoint/pin contract for every daemon role,
    // including authorities that return before the directory refresh loop starts.
    if !authority_endpoints.is_empty() {
        anonguard::mesh::PinnedDirectoryClient::new(
            authority_endpoints.clone(),
            args.quorum_threshold,
        )?;
    }

    let authority_transports = args
        .authority_transports
        .as_ref()
        .map(|path| anonguard::onion::transport::load_authorities(path))
        .transpose()?;
    if let Some(bindings) = authority_transports.as_ref() {
        anonguard::mesh::PinnedDirectoryClient::new(
            authority_endpoints.clone(),
            args.quorum_threshold,
        )?
        .with_transports(bindings.clone())?;
    }
    if args.unlisted_bridge
        && !args
            .listen
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|address| address.ip().is_loopback())
    {
        return Err("Unlisted bridge backend must listen on numeric loopback".into());
    }

    let config = GuardConfig {
        padded_sessions: args.padded_sessions,
        privacy_profile: args.privacy_profile.clone(),
        min_chain_length: if args.onion {
            usize::from(args.min_hops)
        } else {
            GuardConfig::default().min_chain_length
        },
        max_chain_length: if args.onion {
            usize::from(args.max_hops)
        } else {
            GuardConfig::default().max_chain_length
        },
        private_bridges: args.private_bridges,
        unlisted_bridge: args.unlisted_bridge,
        bridge_transports: args
            .bridge_transports
            .as_ref()
            .map(|path| anonguard::onion::transport::load_bridges(path))
            .transpose()?
            .unwrap_or_default(),
        listen_addr: args.listen.clone(),
        relay_advertise_address: args.advertise_address,
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
        authority_identity_keys,
        authority_endpoints,
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

    if args.revocation_policy.is_some() && !(args.onion || args.relay || args.authority) {
        return Err("Identity retirement requires an authenticated onion routing role".into());
    }
    let retirement_journal = if args.authority {
        config.identity_key_path.with_extension("revocation.json")
    } else {
        config.guard_state_path.with_extension("revocation.json")
    };
    let revoked = anonguard::core::revocation::load_and_commit(
        args.revocation_policy.as_deref(),
        &retirement_journal,
        &bound_authorities,
        args.quorum_threshold,
    )?;
    if config
        .authority_endpoints
        .iter()
        .any(|endpoint| revoked.contains(&endpoint.public_key))
        || config
            .bridge_transports
            .iter()
            .any(|binding| revoked.contains(&binding.identity))
    {
        return Err(
            "Configured authority or private bridge identity is retired; update authenticated pins"
                .into(),
        );
    }

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

    if args.authority {
        let mut authority = anonguard::mesh::DirectoryAuthority::with_persistent_key(
            args.authority_id,
            args.listen,
            args.pow_difficulty,
            config.identity_key_path,
        )
        .with_revoked_identities(revoked.clone());
        if revoked.contains(&authority.verifying_key().to_bytes()) {
            return Err("Local authority identity is retired".into());
        }
        if let Some(own) = config
            .authority_endpoints
            .iter()
            .find(|endpoint| endpoint.identity == authority.authority_id)
        {
            if own.public_key != authority.verifying_key().to_bytes() {
                return Err(
                    "Authority identity key does not match its configured bootstrap pin".into(),
                );
            }
        }
        authority.peer_authorities = authority_peers;
        let res = tokio::select! {
            r = authority.run() => r,
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal (Ctrl+C)");
                Ok(())
            }
        };
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
        return res;
    }

    let relay_identity_key =
        std::sync::Arc::new(load_or_create_identity_key(&config.identity_key_path));
    if revoked.contains(&relay_identity_key.verifying_key().to_bytes()) {
        return Err("Local routing identity is retired".into());
    }
    let pool = ProxyPool::with_revoked_identities(revoked.clone());
    pool.init_guard_state(config.guard_state_path.clone())
        .await?;

    if let Some(file_path) = args.pool {
        match pool.load_file(&file_path).await {
            Ok(count) => {
                info!(count = count, path = %file_path.display(), "[AnonGuard] Loaded proxies from file")
            }
            Err(e) => return Err(format!("Configured proxy file rejected: {e}").into()),
        }
    }

    if let Some(inline) = args.proxy {
        pool.add_proxy(&inline)
            .await
            .map_err(|_| "Invalid --proxy endpoint")?;
        info!("[AnonGuard] Added inline proxy to pool");
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

    if !args.reverse_relay {
        // Wire Multi-Authority Consensus retrieval & cryptographic quorum verification
        if !config.directory_authorities.is_empty() {
            let mut client = anonguard::mesh::PinnedDirectoryClient::new(
                config.authority_endpoints.clone(),
                args.quorum_threshold,
            )?;
            if let Some(bindings) = authority_transports {
                client = client.with_transports(bindings)?;
            }
            let pool_clone = pool.clone();
            tokio::spawn(async move {
                let mut retry_seconds = 1;
                loop {
                    let delay = match client.refresh(&pool_clone).await {
                        Ok(loaded) => {
                            retry_seconds = 1;
                            tracing::info!(
                                loaded,
                                "[AnonGuard Consensus] Loaded certified directory snapshot"
                            );
                            std::time::Duration::from_secs(60)
                        }
                        Err(error) => {
                            tracing::warn!(%error, "[AnonGuard Consensus] Directory refresh rejected; retained state remains subject to expiry");
                            let delay = std::time::Duration::from_secs(retry_seconds)
                                + std::time::Duration::from_millis(rand::random::<u64>() % 251);
                            retry_seconds = (retry_seconds * 2).min(30);
                            delay
                        }
                    };
                    tokio::time::sleep(delay).await;
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
    #[cfg(target_os = "linux")]
    let gateway_state_path = config.guard_state_path.clone();
    #[cfg(target_os = "linux")]
    let gateway_kill = kill_switch.clone();
    let gateway = GatewayServer::new(config, pool, kill_switch, relay_identity_key);

    #[cfg(target_os = "linux")]
    let mut isolation = if args.enable_firewall_killswitch {
        let endpoint: std::net::SocketAddr = args.listen.parse()?;
        let namespace = anonguard::kernel::NetnsConfig::new(
            args.namespace_name,
            endpoint.ip().to_string(),
            endpoint.port(),
        );
        let socket = args
            .namespace_socket
            .unwrap_or_else(|| gateway_state_path.with_extension("proxy.sock"));
        Some(anonguard::kernel::netns::start_isolation(
            &namespace,
            &socket,
            gateway_kill.clone(),
            &std::env::current_exe()?,
        )?)
    } else {
        None
    };

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
        failure = async {
            #[cfg(target_os = "linux")]
            if let Some(handle) = isolation.as_mut() { return handle.wait_failure().await; }
            std::future::pending::<std::io::Result<()>>().await
        } => failure.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
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

    run_res
}
