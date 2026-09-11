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
    /// Gateway listen address
    pub listen_addr: String,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            strict_killswitch: true,
            enforce_remote_dns: true,
            disable_ipv6: true,
            enable_jitter: false,
            jitter_lambda: 0.05,
            enable_padding: false,
            padding_block_size: 512,
            ja4_profile: "chrome_120".to_string(),
            min_chain_length: 1,
            max_chain_length: 3,
            relay_mode: false,
            listen_addr: "127.0.0.1:9050".to_string(),
        }
    }
}
