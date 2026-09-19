//! High-concurrency proxy pool with auto-rotation on block.

use indexmap::IndexMap;
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
    /// Keyed by "host:port" — inserting the same key overwrites, preventing duplicates (#6).
    nodes: Arc<RwLock<IndexMap<String, ProxyNode>>>,
    cursor: Arc<AtomicUsize>,
    /// Maps "host:port" -> Ed25519 identity key from the directory consensus.
    /// Only populated when nodes are loaded via `load_from_consensus`.
    identity_keys: Arc<RwLock<IndexMap<String, [u8; 32]>>>,
    /// Persistent entry guard state for the client.
    guard_state: Arc<RwLock<crate::mesh::guards::GuardState>>,
    /// Path to the persistent entry guards file.
    guard_state_path: Arc<RwLock<Option<std::path::PathBuf>>>,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(IndexMap::new())),
            cursor: Arc::new(AtomicUsize::new(0)),
            identity_keys: Arc::new(RwLock::new(IndexMap::new())),
            guard_state: Arc::new(RwLock::new(crate::mesh::guards::GuardState::new())),
            guard_state_path: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn init_guard_state(&self, path: std::path::PathBuf) {
        let state = crate::mesh::guards::GuardState::load(&path);
        *self.guard_state.write().await = state;
        *self.guard_state_path.write().await = Some(path);
    }

    /// Adds a proxy from string representation, deduplicating by host:port.
    pub async fn add_proxy(&self, raw: &str) -> Result<(), String> {
        let mut node = ProxyNode::parse(raw)?;
        node.enforce_remote_dns();
        let key = format!("{}:{}", node.host, node.port);
        let mut list = self.nodes.write().await;
        list.insert(key, node);
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
    ///
    /// Performs a **full replace** of consensus-sourced entries so stale relays are
    /// evicted on each refresh cycle (fixes #6 pool never evicts).
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

        // Full replace: clear old consensus entries and repopulate from fresh document
        let mut list = self.nodes.write().await;
        let mut id_keys = self.identity_keys.write().await;
        list.retain(|_, n| !n.raw_url.starts_with("socks5://") && !n.raw_url.starts_with("reverse://"));
        id_keys.clear();

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
            if let Ok(mut node) = ProxyNode::parse(&scheme) {
                node.enforce_remote_dns();
                // Carry the is_exit flag from the consensus descriptor into the ProxyNode
                node.is_exit = relay.is_exit;
                let key = format!("{}:{}", node.host, node.port);
                // Store identity key keyed by "host:port" for circuit handshake binding
                id_keys.insert(key.clone(), relay.identity_key_ed25519);
                list.insert(key, node);
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    /// Checks if a given host:port is a known mesh target from the consensus.
    pub async fn is_mesh_target(&self, host: &str, port: u16) -> bool {
        let id_keys = self.identity_keys.read().await;
        id_keys.contains_key(&format!("{}:{}", host, port))
    }

    /// Returns the pinned Ed25519 identity keys for each node in a chain, in order.
    /// Nodes loaded from text files (not consensus) will return `[0u8; 32]` (zeroed),
    /// which `build_telescopic_circuit` will reject — enforcing consensus-sourced routing.
    pub async fn get_identity_keys(&self, chain: &[ProxyNode]) -> Vec<[u8; 32]> {
        let id_keys = self.identity_keys.read().await;
        chain
            .iter()
            .map(|n| {
                let key_id = format!("{}:{}", n.host, n.port);
                id_keys.get(&key_id).copied().unwrap_or([0u8; 32])
            })
            .collect()
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
            if let Some(node) = list.get_index(idx).map(|(_, v)| v) {
                if node.is_alive {
                    return Some(node.clone());
                }
            }
        }

        // Fallback: return any node if all are marked down
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % count;
        list.get_index(idx).map(|(_, v)| v.clone())
    }

    /// Retrieves a random chain of unique healthy proxies
    pub async fn get_random_chain(&self, min_hops: usize, max_hops: usize) -> Vec<ProxyNode> {
        let list = self.nodes.read().await;
        let mut healthy: Vec<ProxyNode> = list.values().filter(|n| n.is_alive).cloned().collect();

        // Fallback if all are marked dead (for testing/fault tolerance)
        if healthy.is_empty() {
            healthy = list.values().cloned().collect();
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
    ///
    /// When `require_exit_at_last` is true (the default for onion routing), the final hop
    /// is chosen only from relays that carry `is_exit == true` in the consensus descriptor.
    /// This enforces Bug #4 (V-02): a circuit is rejected at build time rather than silently
    /// using a non-exit relay as the exit hop.
    pub async fn get_diverse_onion_chain(
        &self,
        min_hops: usize,
        max_hops: usize,
        enforce_diversity: bool,
    ) -> Vec<ProxyNode> {
        self.get_diverse_onion_chain_with_exit(min_hops, max_hops, enforce_diversity, true).await
    }

    /// Internal builder with explicit exit-enforcement flag.
    pub async fn get_diverse_onion_chain_with_exit(
        &self,
        min_hops: usize,
        max_hops: usize,
        enforce_diversity: bool,
        require_exit_at_last: bool,
    ) -> Vec<ProxyNode> {
        let list = self.nodes.read().await;
        let all_healthy: Vec<ProxyNode> = {
            let v: Vec<ProxyNode> = list.values().filter(|n| n.is_alive).cloned().collect();
            if v.is_empty() { list.values().cloned().collect() } else { v }
        };

        if all_healthy.is_empty() {
            return Vec::new();
        }

        let path_len = {
            let mut rng = rand::thread_rng();
            let max_possible = all_healthy.len().min(max_hops);
            let min_possible = min_hops.min(max_possible);

            if min_possible < max_possible {
                rng.gen_range(min_possible..=max_possible)
            } else {
                min_possible.max(1).min(all_healthy.len())
            }
        };

        // Separate exit-capable and non-exit relay pools
        let (exit_nodes, middle_nodes): (Vec<ProxyNode>, Vec<ProxyNode>) = if require_exit_at_last {
            all_healthy.into_iter().partition(|n| n.is_exit)
        } else {
            (all_healthy.clone(), all_healthy)
        };

        if require_exit_at_last && exit_nodes.is_empty() {
            tracing::warn!("No exit-capable relays available in the pool — cannot build a valid circuit");
            return Vec::new();
        }

        // Build the non-exit portion of the chain (path_len - 1 middle hops)
        let middle_count = if require_exit_at_last { path_len.saturating_sub(1) } else { path_len };
        let mut pool_for_middles = if require_exit_at_last {
            middle_nodes
        } else {
            // When not requiring exit at last, all nodes are eligible everywhere
            let list_vals: Vec<ProxyNode> = list.values().filter(|n| n.is_alive).cloned().collect();
            if list_vals.is_empty() { list.values().cloned().collect() } else { list_vals }
        };
        
        {
            let mut rng = rand::thread_rng();
            pool_for_middles.shuffle(&mut rng);
        }

        let mut selected: Vec<ProxyNode> = Vec::new();

        // 1. Pick or assign Persistent Entry Guard (Hop 0)
        if middle_count > 0 {
            let mut guard_state = self.guard_state.write().await;
            let mut guard_node = None;
            
            // Look for an existing healthy guard in our pinned state
            for g_id in &guard_state.guards {
                if let Some(n) = pool_for_middles.iter().find(|n| format!("{}:{}", n.host, n.port) == *g_id) {
                    guard_node = Some(n.clone());
                    break;
                }
            }

            if let Some(guard) = guard_node {
                selected.push(guard.clone());
                pool_for_middles.retain(|n| format!("{}:{}", n.host, n.port) != format!("{}:{}", guard.host, guard.port));
            } else {
                // Assign a new pinned guard and save to disk
                if let Some(new_guard) = pool_for_middles.first().cloned() {
                    let g_id = format!("{}:{}", new_guard.host, new_guard.port);
                    guard_state.guards.push(g_id);
                    if guard_state.guards.len() > 3 {
                        guard_state.guards.remove(0); // Keep max 3 persistent guards to prevent bloating
                    }
                    if let Some(path) = self.guard_state_path.read().await.as_ref() {
                        guard_state.save(path);
                    }
                    selected.push(new_guard.clone());
                    pool_for_middles.remove(0);
                }
            }
        }

        // 2. Select remaining middle hops
        if !enforce_diversity {
            let remaining = middle_count.saturating_sub(selected.len());
            selected.extend(pool_for_middles.into_iter().take(remaining));
        } else {
            for candidate in pool_for_middles {
                if selected.len() >= middle_count {
                    break;
                }
                let mut test_hosts: Vec<&str> = selected.iter().map(|n| n.host.as_str()).collect();
                test_hosts.push(&candidate.host);
                if crate::mesh::sybil::validate_circuit_diversity(&test_hosts).is_ok() {
                    selected.push(candidate);
                }
            }
        }

        // Append the exit hop
        if require_exit_at_last {
            let mut exit_pool = exit_nodes;
            {
                let mut rng = rand::thread_rng();
                exit_pool.shuffle(&mut rng);
            }
            // Pick the first exit node that passes diversity (if enforced)
            for exit_candidate in exit_pool {
                if enforce_diversity {
                    let mut test_hosts: Vec<&str> = selected.iter().map(|n| n.host.as_str()).collect();
                    test_hosts.push(&exit_candidate.host);
                    if crate::mesh::sybil::validate_circuit_diversity(&test_hosts).is_ok() {
                        selected.push(exit_candidate);
                        break;
                    }
                } else {
                    selected.push(exit_candidate);
                    break;
                }
            }
        }

        selected
    }

    /// Rotates away from a blocked proxy and returns a fresh healthy node.
    pub async fn rotate_on_block(&self, blocked_url: &str) -> Option<ProxyNode> {
        let mut list = self.nodes.write().await;
        for node in list.values_mut() {
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
            .values()
            .filter(|n| n.is_alive)
            .count()
    }
}

impl Default for ProxyPool {
    fn default() -> Self {
        Self::new()
    }
}
