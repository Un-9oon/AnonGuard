//! High-concurrency proxy pool with auto-rotation on block.

use rand::seq::SliceRandom;
use rand::Rng;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::mesh::node::ProxyNode;

#[derive(Clone)]
pub struct ProxyPool {
    nodes: Arc<RwLock<Vec<ProxyNode>>>,
    cursor: Arc<AtomicUsize>,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(Vec::new())),
            cursor: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Adds a proxy from string representation.
    pub async fn add_proxy(&self, raw: &str) -> Result<(), String> {
        let mut node = ProxyNode::parse(raw)?;
        node.enforce_remote_dns();
        let mut list = self.nodes.write().await;
        list.push(node);
        Ok(())
    }

    /// Loads proxies line-by-line from a text file.
    pub async fn load_file(&self, path: impl AsRef<Path>) -> Result<usize, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open proxy file: {}", e))?;
        let reader = BufReader::new(file);
        let mut loaded = 0;

        for l in reader.lines().map_while(Result::ok) {
            let trimmed = l.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && self.add_proxy(trimmed).await.is_ok()
            {
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    /// Loads authenticated relays from a Directory Authority Consensus Document,
    /// strictly enforcing Directory Authority signature quorum, timestamp validity,
    /// and individual relay Ed25519 identity bindings.
    pub async fn load_from_consensus(
        &self,
        doc: &crate::mesh::consensus::ConsensusDocument,
        authorities: &std::collections::HashMap<String, ed25519_dalek::VerifyingKey>,
        quorum_threshold: usize,
        current_time: u64,
    ) -> Result<usize, String> {
        if !doc.verify_quorum(authorities, quorum_threshold, current_time) {
            return Err("Directory consensus document quorum verification failed".to_string());
        }

        let mut loaded = 0;
        for relay in &doc.relays {
            if !relay.verify_identity() {
                continue; // Skip relays with invalid or missing cryptographic identity signatures
            }
            let scheme = if relay.host.starts_with("reverse://") {
                relay.host.clone()
            } else {
                format!("socks5://{}:{}", relay.host, relay.port)
            };
            if self.add_proxy(&scheme).await.is_ok() {
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    /// Retrieves the next alive proxy using round-robin rotation.
    pub async fn get_next(&self) -> Option<ProxyNode> {
        let list = self.nodes.read().await;
        let count = list.len();
        if count == 0 {
            return None;
        }

        // Try up to count times to find an alive node
        for _ in 0..count {
            let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
            if list[idx].is_alive {
                return Some(list[idx].clone());
            }
        }

        // Fallback: return any node if all are marked down
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        Some(list[idx].clone())
    }

    /// Retrieves a random chain of unique healthy proxies
    pub async fn get_random_chain(&self, min_hops: usize, max_hops: usize) -> Vec<ProxyNode> {
        let list = self.nodes.read().await;
        let mut healthy: Vec<ProxyNode> = list.iter().filter(|n| n.is_alive).cloned().collect();

        // Fallback if all are marked dead (for testing/fault tolerance)
        if healthy.is_empty() {
            healthy = list.clone();
        }

        if healthy.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::thread_rng();
        let max_possible = healthy.len().min(max_hops);
        let min_possible = min_hops.min(max_possible);

        // Ensure path_len is at least 1 if possible
        let path_len = if min_possible < max_possible {
            rng.gen_range(min_possible..=max_possible)
        } else {
            min_possible.max(1).min(healthy.len())
        };

        healthy.shuffle(&mut rng);
        healthy.into_iter().take(path_len).collect()
    }

    /// Retrieves a random chain of proxies that strictly enforces BGP /16 subnet diversity
    /// to defeat Sybil attacks and correlation by colluding single-provider nodes.
    pub async fn get_diverse_onion_chain(
        &self,
        min_hops: usize,
        max_hops: usize,
        enforce_diversity: bool,
    ) -> Vec<ProxyNode> {
        let list = self.nodes.read().await;
        let mut healthy: Vec<ProxyNode> = list.iter().filter(|n| n.is_alive).cloned().collect();

        if healthy.is_empty() {
            healthy = list.clone();
        }

        if healthy.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::thread_rng();
        let max_possible = healthy.len().min(max_hops);
        let min_possible = min_hops.min(max_possible);

        let path_len = if min_possible < max_possible {
            rng.gen_range(min_possible..=max_possible)
        } else {
            min_possible.max(1).min(healthy.len())
        };

        healthy.shuffle(&mut rng);

        if !enforce_diversity {
            return healthy.into_iter().take(path_len).collect();
        }

        let mut selected: Vec<ProxyNode> = Vec::new();
        for candidate in healthy {
            if selected.len() >= path_len {
                break;
            }

            let mut test_hosts: Vec<&str> = selected.iter().map(|n| n.host.as_str()).collect();
            test_hosts.push(&candidate.host);

            if crate::mesh::sybil::validate_circuit_diversity(&test_hosts).is_ok() {
                selected.push(candidate);
            }
        }

        // If strict diversity filtered too aggressively, fall back to whatever diverse nodes we gathered
        selected
    }

    /// Rotates away from a blocked proxy and returns a fresh healthy node.
    pub async fn rotate_on_block(&self, blocked_url: &str) -> Option<ProxyNode> {
        let mut list = self.nodes.write().await;
        for node in list.iter_mut() {
            if node.raw_url == blocked_url {
                node.failure_count += 1;
                if node.failure_count >= 3 {
                    node.is_alive = false;
                }
                break;
            }
        }
        drop(list);
        self.get_next().await
    }

    pub async fn total_count(&self) -> usize {
        self.nodes.read().await.len()
    }

    pub async fn alive_count(&self) -> usize {
        self.nodes
            .read()
            .await
            .iter()
            .filter(|n| n.is_alive)
            .count()
    }
}

impl Default for ProxyPool {
    fn default() -> Self {
        Self::new()
    }
}
