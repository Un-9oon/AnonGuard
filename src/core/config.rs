//! Configuration structures for AnonGuard policies and runtime parameters.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Strict kill-switch: if true, immediately drop all traffic if proxy fails
    pub strict_killswitch: bool,
    /// Enforce remote DNS resolution (SOCKS5h FQDN framing)
    pub enforce_remote_dns: bool,
    /// Disable IPv6 socket allocation
    pub disable_ipv6: bool,
    /// Enable Poisson timing jitter to defeat flow correlation
    pub enable_jitter: bool,
    /// Jitter rate parameter (lambda for exponential distribution)
    pub jitter_lambda: f64,
    /// Enable Chaotic Attractor Morphing
    pub enable_chaos: bool,
    pub chaos_sigma: f64,
    pub chaos_rho: f64,
    pub chaos_beta: f64,
    /// Enable Quantum Chaos (RMT) Morphing
    pub enable_quantum: bool,
    pub quantum_ensemble: String,
    /// Enable MTU chunk padding
    pub enable_padding: bool,
    /// Padding block size in bytes (e.g. 512, 1024, 1460)
    pub padding_block_size: usize,
    /// TLS JA4 emulation profile (e.g. "chrome_120", "firefox_124")
    pub ja4_profile: String,
    /// Minimum number of proxies to chain
    pub min_chain_length: usize,
    /// Maximum number of proxies to chain
    pub max_chain_length: usize,
    /// Run as a native SOCKS5 relay node
    pub relay_mode: bool,
    /// Allow open, unauthenticated plain SOCKS5 proxying when in relay mode (default: false for security)
    pub allow_open_socks5: bool,
    /// Allow exit relays to connect to private/loopback networks (default: false to prevent SSRF)
    pub allow_private_exit: bool,
    pub is_exit: bool,
    pub reverse_relay_mode: bool,
    pub tracker_url: Option<String>,
    /// Enable 3-hop layered onion encryption (Sphinx/Tor-style cell peeling)
    pub enable_onion_routing: bool,
    /// Enforce BGP /16 subnet diversity across circuit hops (Sybil resistance)
    pub enforce_subnet_diversity: bool,
    /// Run as a Directory Authority consensus node
    pub authority_mode: bool,
    pub authority_id: String,
    /// List of trusted Directory Authority endpoints for consensus verification
    pub directory_authorities: Vec<String>,
    /// Gateway listen address
    pub listen_addr: String,
    /// Apply OS/kernel-level nftables firewall kill switch (Linux with root/CAP_NET_ADMIN)
    pub enable_firewall_killswitch: bool,
    /// Registration PoW difficulty in leading zero bits
    pub pow_difficulty: u32,
    /// Path to persist the relay's long-term Ed25519 identity key
    pub identity_key_path: std::path::PathBuf,
    /// Path to persist the client's Entry Guards (Hop 0 pins)
    pub guard_state_path: std::path::PathBuf,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            strict_killswitch: true,
            enforce_remote_dns: true,
            disable_ipv6: true,
            enable_jitter: false,
            jitter_lambda: 0.05,
            enable_chaos: false,
            chaos_sigma: 10.0,
            chaos_rho: 28.0,
            chaos_beta: 8.0 / 3.0,
            enable_quantum: false,
            quantum_ensemble: "goe".to_string(),
            enable_padding: false,
            padding_block_size: 512,
            ja4_profile: "chrome_120".to_string(),
            min_chain_length: 1,
            max_chain_length: 3,
            relay_mode: false,
            allow_open_socks5: false,
            allow_private_exit: false,
            is_exit: false,
            reverse_relay_mode: false,
            tracker_url: None,
            enable_onion_routing: false,
            enforce_subnet_diversity: true,
            authority_mode: false,
            authority_id: "authority-default".to_string(),
            directory_authorities: Vec::new(),
            listen_addr: "127.0.0.1:9050".to_string(),
            enable_firewall_killswitch: false,
            pow_difficulty: 20,
            identity_key_path: std::path::PathBuf::from("/etc/anonguard/identity.key"),
            guard_state_path: std::path::PathBuf::from("/etc/anonguard/guards.json"),
        }
    }
}
