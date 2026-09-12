//! Sybil Attack Defense & Network Diversification Subsystem.
//!
//! Provides cryptographic Proof-of-Work (PoW) verification for node registration
//! and enforces BGP/CIDR subnet diversity across 3-hop circuits.

use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_POW_DIFFICULTY: u32 = 16; // 16 leading zero bits
pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 600; // 10 minutes window

#[derive(Debug, PartialEq, Eq)]
pub enum SybilError {
    InvalidProofOfWork,
    ExpiredTimestamp(u64),
    SubnetCollision([u8; 2]),
    DuplicateNode(String),
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
            Self::DuplicateNode(host) => write!(
                f,
                "Sybil detection: Duplicate node address in circuit: {}",
                host
            ),
        }
    }
}

impl std::error::Error for SybilError {}

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
pub fn solve_pow(node_id: &str, timestamp: u64, difficulty_bits: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(node_id.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(nonce.to_be_bytes());
        let hash = hasher.finalize();

        if count_leading_zero_bits(&hash) >= difficulty_bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
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

/// Enforces that all nodes in an onion circuit originate from distinct /16 CIDR subnets
/// and distinct host addresses, preventing single-ISP or single-datacenter Sybil attacks.
pub fn validate_circuit_diversity(hosts: &[&str]) -> Result<(), SybilError> {
    let mut seen_subnets: Vec<[u8; 2]> = Vec::new();
    let mut seen_hosts: Vec<&str> = Vec::new();

    for &host in hosts {
        // Check for duplicate exact host
        if seen_hosts.contains(&host) {
            return Err(SybilError::DuplicateNode(host.to_string()));
        }
        seen_hosts.push(host);

        // Check for /16 subnet prefix collision
        if let Some(subnet) = extract_ipv4_subnet_16(host) {
            if seen_subnets.contains(&subnet) {
                return Err(SybilError::SubnetCollision(subnet));
            }
            seen_subnets.push(subnet);
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

        let nonce = solve_pow(node_id, now, difficulty);
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
    }
}
