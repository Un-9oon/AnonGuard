//! Sybil Attack Defense & Network Diversification Subsystem.
//!
//! Provides cryptographic Proof-of-Work (PoW) verification for node registration
//! and enforces BGP/CIDR subnet diversity across 3-hop circuits.
//! Includes a NonceRegistry to prevent PoW nonce replay within the validity window.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_POW_DIFFICULTY: u32 = 26; // 28 leading zero bits (default production difficulty)
pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300; // 5 minutes window (reduced from 10 to limit replay)

#[derive(Debug, PartialEq, Eq)]
pub enum SybilError {
    InvalidProofOfWork,
    ExpiredTimestamp(u64),
    SubnetCollision([u8; 2]),
    Ipv6SubnetCollision([u8; 4]),
    DuplicateNode(String),
    UnresolvableHost(String),
}

impl std::fmt::Display for SybilError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProofOfWork => write!(
                f,
                "Cryptographic Proof-of-Work invalid or insufficient difficulty"
            ),
            Self::ExpiredTimestamp(ts) => write!(
                f,
                "PoW registration challenge timestamp expired or drifted: {}",
                ts
            ),
            Self::SubnetCollision(prefix) => write!(
                f,
                "Sybil detection: Circuit nodes collide on /16 subnet prefix {}.{}",
                prefix[0], prefix[1]
            ),
            Self::Ipv6SubnetCollision(prefix) => write!(
                f,
                "Sybil detection: Circuit nodes collide on IPv6 /32 subnet prefix {:02x}{:02x}:{:02x}{:02x}::/32",
                prefix[0], prefix[1], prefix[2], prefix[3]
            ),
            Self::DuplicateNode(host) => write!(
                f,
                "Sybil detection: Duplicate node address in circuit: {}",
                host
            ),
            Self::UnresolvableHost(host) => write!(
                f,
                "Sybil detection: Unresolvable or non-IP node address in circuit: {}",
                host
            ),
        }
    }
}

impl std::error::Error for SybilError {}

/// Tracks recently-seen PoW nonces to prevent replay within the validity window.
/// Entries are automatically purged when they fall outside MAX_TIMESTAMP_DRIFT_SECS.
pub struct NonceRegistry {
    /// Maps (node_id, nonce) -> timestamp of first observation
    seen: Mutex<HashMap<(String, u64), u64>>,
}

impl NonceRegistry {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if a nonce has been seen before for the given node_id.
    /// If not seen, records it and returns false ("not a replay").
    /// If already seen, returns true ("replay detected").
    pub fn check_and_record(&self, node_id: &str, nonce: u64, current_time: u64) -> bool {
        let mut seen = self.seen.lock().unwrap();

        // Purge expired entries (outside 2x the drift window for safety)
        let expiry_threshold = current_time.saturating_sub(MAX_TIMESTAMP_DRIFT_SECS * 2);
        seen.retain(|_, ts| *ts > expiry_threshold);

        if seen.len() > 100_000 {
            // Hard bound reached to prevent OOM
            return true; // Deny new PoW temporarily
        }

        let key = (node_id.to_string(), nonce);
        if seen.contains_key(&key) {
            return true; // Replay detected
        }
        seen.insert(key, current_time);
        false // First time seen
    }
}

impl Default for NonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifies a relay's cryptographic Proof-of-Work challenge.
pub fn verify_pow(
    node_id: &str,
    timestamp: u64,
    nonce: u64,
    difficulty_bits: u32,
    current_time: u64,
) -> bool {
    // 1. Freshness check
    let diff = current_time.abs_diff(timestamp);

    if diff > MAX_TIMESTAMP_DRIFT_SECS {
        return false;
    }

    // 2. Hash computation: SHA256(node_id || timestamp || nonce)
    let mut hasher = Sha256::new();
    hasher.update(node_id.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(nonce.to_be_bytes());
    let hash = hasher.finalize();

    // 3. Verify leading zero bits
    count_leading_zero_bits(&hash) >= difficulty_bits
}

/// Solves a Proof-of-Work challenge for a given node identity.
pub fn solve_pow_bounded(node_id: &str, timestamp: u64, difficulty_bits: u32) -> Option<u64> {
    let mut nonce: u64 = 0;
    while nonce < 10_000_000 {
        let mut hasher = Sha256::new();
        hasher.update(node_id.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(nonce.to_be_bytes());
        let hash = hasher.finalize();

        if count_leading_zero_bits(&hash) >= difficulty_bits {
            return Some(nonce);
        }
        nonce = nonce.wrapping_add(1);
    }
    None
}

fn count_leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut zeros = 0;
    for &b in bytes {
        if b == 0 {
            zeros += 8;
        } else {
            zeros += b.leading_zeros();
            break;
        }
    }
    zeros
}

pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extracts the /16 IPv4 subnet prefix [oct1, oct2] if host is an IPv4 address.
pub fn extract_ipv4_subnet_16(host: &str) -> Option<[u8; 2]> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let octets = ip.octets();
        Some([octets[0], octets[1]])
    } else {
        None
    }
}

/// Extracts the /32 IPv6 subnet prefix (first 4 bytes) if host is an IPv6 address.
/// /32 represents a typical ISP or large data center allocation block.
pub fn extract_ipv6_subnet_32(host: &str) -> Option<[u8; 4]> {
    let ip_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_str.parse::<Ipv6Addr>() {
        let octets = ip.octets();
        Some([octets[0], octets[1], octets[2], octets[3]])
    } else {
        None
    }
}

/// Enforces that all nodes in an onion circuit originate from distinct /16 CIDR subnets (IPv4)
/// or distinct /32 CIDR subnets (IPv6) and distinct host addresses, preventing single-ISP or
/// single-datacenter Sybil attacks.
pub fn validate_circuit_diversity(hosts: &[&str]) -> Result<(), SybilError> {
    let mut seen_ipv4_subnets: Vec<[u8; 2]> = Vec::new();
    let mut seen_ipv6_subnets: Vec<[u8; 4]> = Vec::new();
    let mut seen_hosts: Vec<&str> = Vec::new();

    for &host in hosts {
        // Check for duplicate exact host
        if seen_hosts.contains(&host) {
            return Err(SybilError::DuplicateNode(host.to_string()));
        }
        seen_hosts.push(host);

        // Try to parse as IP
        let ip_str = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    let subnet = [octets[0], octets[1]];
                    if seen_ipv4_subnets.contains(&subnet) {
                        return Err(SybilError::SubnetCollision(subnet));
                    }
                    seen_ipv4_subnets.push(subnet);
                }
                std::net::IpAddr::V6(ipv6) => {
                    // Check if it's an IPv4-mapped IPv6 address (::ffff:a.b.c.d)
                    if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                        let octets = ipv4.octets();
                        let subnet = [octets[0], octets[1]];
                        if seen_ipv4_subnets.contains(&subnet) {
                            return Err(SybilError::SubnetCollision(subnet));
                        }
                        seen_ipv4_subnets.push(subnet);
                    } else if let Some(ipv4) = ipv6.to_ipv4() {
                        // Also check IPv4-compatible (::a.b.c.d)
                        let octets = ipv4.octets();
                        let subnet = [octets[0], octets[1]];
                        if seen_ipv4_subnets.contains(&subnet) {
                            return Err(SybilError::SubnetCollision(subnet));
                        }
                        seen_ipv4_subnets.push(subnet);
                    } else {
                        let octets = ipv6.octets();
                        let subnet = [octets[0], octets[1], octets[2], octets[3]];
                        if seen_ipv6_subnets.contains(&subnet) {
                            return Err(SybilError::Ipv6SubnetCollision(subnet));
                        }
                        seen_ipv6_subnets.push(subnet);
                    }
                }
            }
        } else {
            // Reject non-IP hostnames
            return Err(SybilError::UnresolvableHost(host.to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_work_solver_and_verifier() {
        let node_id = "ed25519_node_alpha_998124";
        let now = current_timestamp_secs();
        let difficulty = 12; // 12 bits for fast test execution

        let nonce =
            solve_pow_bounded(node_id, now, difficulty).expect("Failed to solve PoW within bounds");
        assert!(verify_pow(node_id, now, nonce, difficulty, now));

        // Tampering with node_id should fail
        assert!(!verify_pow(
            "ed25519_node_tampered",
            now,
            nonce,
            difficulty,
            now
        ));

        // Expired timestamp should fail
        assert!(!verify_pow(node_id, now - 1000, nonce, difficulty, now));
    }

    #[test]
    fn test_circuit_subnet_diversity() {
        // Valid diverse circuit across 3 distinct /16 subnets
        let diverse_circuit = ["198.51.100.1", "203.0.113.5", "192.0.2.8"];
        assert!(validate_circuit_diversity(&diverse_circuit).is_ok());

        // Colliding circuit sharing 198.51.0.0/16
        let colliding_circuit = ["198.51.10.1", "198.51.80.25", "203.0.113.5"];
        let err = validate_circuit_diversity(&colliding_circuit).unwrap_err();
        assert_eq!(err, SybilError::SubnetCollision([198, 51]));

        // Duplicate node address
        let duplicate_circuit = ["198.51.10.1", "203.0.113.5", "198.51.10.1"];
        let err2 = validate_circuit_diversity(&duplicate_circuit).unwrap_err();
        assert_eq!(err2, SybilError::DuplicateNode("198.51.10.1".to_string()));

        // Valid diverse IPv6 circuit across 3 distinct /32 subnets
        let diverse_ipv6_circuit = ["2001:0db8::1", "2001:0db9::2", "2001:0dba::3"];
        assert!(validate_circuit_diversity(&diverse_ipv6_circuit).is_ok());

        // Colliding IPv6 circuit sharing 2001:0db8::/32
        let colliding_ipv6_circuit = ["2001:0db8:85a3::1", "2001:0db8:1234::2", "2001:0db9::3"];
        let err_ipv6 = validate_circuit_diversity(&colliding_ipv6_circuit).unwrap_err();
        assert_eq!(
            err_ipv6,
            SybilError::Ipv6SubnetCollision([0x20, 0x01, 0x0d, 0xb8])
        );

        // Ensure bracketed IPv6 works
        let colliding_bracketed = ["[2001:0db8::1]", "2001:db8:ffff::2", "2001:0db9::3"];
        let err_bracket = validate_circuit_diversity(&colliding_bracketed).unwrap_err();
        assert_eq!(
            err_bracket,
            SybilError::Ipv6SubnetCollision([0x20, 0x01, 0x0d, 0xb8])
        );
    }
}
