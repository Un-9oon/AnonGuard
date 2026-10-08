//! High-concurrency proxy pool with auto-rotation on block.

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[tokio::test]
    async fn entry_transport_allowlist_cannot_fall_back_to_other_guards() {
        let pool = ProxyPool::new();
        for (address, pin, exit) in [
            ("1.1.1.1", [1; 32], false),
            ("2.1.1.1", [2; 32], false),
            ("3.1.1.1", [3; 32], true),
        ] {
            pool.add_proxy(&format!("socks5://{address}:9001"))
                .await
                .unwrap();
            let endpoint = format!("{address}:9001");
            pool.identity_keys
                .write()
                .await
                .insert(endpoint.clone(), pin);
            pool.nodes.write().await.get_mut(&endpoint).unwrap().is_exit = exit;
        }
        let chain = pool
            .get_onion_chain_with_entry_pins(3, 3, true, true, &[[2; 32]])
            .await;
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].host, "2.1.1.1");
        assert!(pool
            .get_onion_chain_with_entry_pins(3, 3, true, true, &[[1; 32]])
            .await
            .is_empty());
        pool.note_guard_link_failure([2; 32]).await;
        assert!(pool
            .get_onion_chain_with_entry_pins(3, 3, true, true, &[[2; 32]])
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn private_entry_is_local_only_and_requires_fresh_certified_hops() {
        let pool = ProxyPool::new();
        for (address, pin, exit) in [("2.1.1.1", [2; 32], false), ("3.1.1.1", [3; 32], true)] {
            pool.add_proxy(&format!("socks5://{address}:9001"))
                .await
                .unwrap();
            let endpoint = format!("{address}:9001");
            pool.identity_keys
                .write()
                .await
                .insert(endpoint.clone(), pin);
            pool.nodes.write().await.get_mut(&endpoint).unwrap().is_exit = exit;
        }
        let binding = crate::onion::transport::BridgeTransport {
            identity: ed25519_dalek::SigningKey::from_bytes(&[41; 32])
                .verifying_key()
                .to_bytes(),
            proxy: "127.0.0.1:31000".parse().unwrap(),
            bridge: "1.1.1.1:443".parse().unwrap(),
            arguments: std::collections::BTreeMap::from([("cert".into(), "fixture".into())]),
        };
        assert!(pool
            .get_private_bridge_chain(std::slice::from_ref(&binding), true)
            .await
            .is_empty());
        pool.consensus_deadline.store(
            crate::mesh::current_timestamp_secs() + 60,
            Ordering::Release,
        );
        let chain = pool
            .get_private_bridge_chain(std::slice::from_ref(&binding), true)
            .await;
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].host, "1.1.1.1");
        assert!(!pool.is_mesh_target("1.1.1.1", 443).await);
        assert_eq!(
            pool.get_identity_keys(&chain).await,
            vec![[0; 32], [2; 32], [3; 32]]
        );
        let mut changed = binding.clone();
        changed.identity = [42; 32];
        assert!(pool
            .get_private_bridge_chain(&[changed], true)
            .await
            .is_empty());
        pool.consensus_deadline.store(1, Ordering::Release);
        assert!(pool
            .get_private_bridge_chain(&[binding], true)
            .await
            .is_empty());
    }
}

use indexmap::IndexMap;
use rand::seq::SliceRandom;
use rand::Rng;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::mesh::node::ProxyNode;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct AcceptedSnapshot {
    epoch: u64,
    digest: [u8; 32],
}

#[derive(Clone)]
pub struct ProxyPool {
    initialization: Arc<tokio::sync::Mutex<()>>,
    revoked: Arc<std::collections::HashSet<[u8; 32]>>,
    /// Keyed by "host:port" — inserting the same key overwrites, preventing duplicates (#6).
    nodes: Arc<RwLock<IndexMap<String, ProxyNode>>>,
    cursor: Arc<AtomicUsize>,
    guard_cooldowns: Arc<RwLock<std::collections::HashMap<[u8; 32], tokio::time::Instant>>>,
    consensus_deadline: Arc<AtomicU64>,
    accepted_snapshot: Arc<RwLock<Option<AcceptedSnapshot>>>,
    snapshot_path: Arc<RwLock<Option<std::path::PathBuf>>>,
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
        Self::with_revoked_identities(std::collections::HashSet::new())
    }

    /// Immutable retirement policy installed before any directory or listener.
    pub fn with_revoked_identities(revoked: std::collections::HashSet<[u8; 32]>) -> Self {
        Self {
            initialization: Arc::new(tokio::sync::Mutex::new(())),
            revoked: Arc::new(revoked),
            nodes: Arc::new(RwLock::new(IndexMap::new())),
            cursor: Arc::new(AtomicUsize::new(0)),
            guard_cooldowns: Arc::new(RwLock::new(std::collections::HashMap::new())),
            consensus_deadline: Arc::new(AtomicU64::new(0)),
            accepted_snapshot: Arc::new(RwLock::new(None)),
            snapshot_path: Arc::new(RwLock::new(None)),
            identity_keys: Arc::new(RwLock::new(IndexMap::new())),
            guard_state: Arc::new(RwLock::new(crate::mesh::guards::GuardState::new())),
            guard_state_path: Arc::new(RwLock::new(None)),
        }
    }

    fn directory_expired(&self) -> bool {
        let deadline = self.consensus_deadline.load(Ordering::Acquire);
        deadline != 0 && crate::mesh::current_timestamp_secs() >= deadline
    }

    pub async fn init_guard_state(&self, path: std::path::PathBuf) -> Result<(), String> {
        let _initialization = self.initialization.lock().await;
        if let Some(existing) = self.guard_state_path.read().await.as_ref() {
            return if existing == &path {
                Ok(())
            } else {
                Err("Pool state path cannot change after initialization".into())
            };
        }
        let snapshot_path = path.with_extension("consensus.json");
        let accepted = match crate::core::storage::read_bounded_file(&snapshot_path, 4096) {
            Ok(bytes) => {
                let state = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("Invalid directory rollback state: {e}"))?;
                Some(state)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("Cannot read directory rollback state: {e}")),
        };
        let state = crate::mesh::guards::GuardState::load_checked(&path)?;
        // Do not publish rollback state or paths when guard loading fails.
        *self.accepted_snapshot.write().await = accepted;
        *self.snapshot_path.write().await = Some(snapshot_path);
        *self.guard_state.write().await = state;
        *self.guard_state_path.write().await = Some(path);
        Ok(())
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

    /// Validates a complete proxy file before publishing any endpoints.
    /// Returns the number of distinct endpoints admitted from that file.
    pub async fn load_file(&self, path: impl AsRef<Path>) -> Result<usize, String> {
        let bytes = crate::core::storage::read_bounded_file(path.as_ref(), 1024 * 1024)
            .map_err(|e| format!("Failed to read proxy file: {e}"))?;
        let reader = BufReader::new(bytes.as_slice());
        let mut staged = IndexMap::new();

        for (index, line) in reader.lines().enumerate() {
            let l =
                line.map_err(|e| format!("Failed to read proxy file line {}: {e}", index + 1))?;
            let trimmed = l.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // URL parser diagnostics can include credentials; expose the line only.
            let mut node = ProxyNode::parse(trimmed)
                .map_err(|_| format!("Invalid proxy on line {}", index + 1))?;
            node.enforce_remote_dns();
            staged.insert(format!("{}:{}", node.host, node.port), node);
        }
        let loaded = staged.len();
        self.nodes.write().await.extend(staged);
        Ok(loaded)
    }

    /// Loads authenticated relays from a set of Directory Authority Consensus Documents,
    /// accepting only a quorum-signed canonical snapshot, never mixed descriptor votes.
    pub async fn load_from_multi_consensus(
        &self,
        docs: &[crate::mesh::consensus::ConsensusDocument],
        authorities: &std::collections::HashMap<String, ed25519_dalek::VerifyingKey>,
        quorum_threshold: usize,
        current_time: u64,
    ) -> Result<usize, String> {
        if quorum_threshold == 0 || quorum_threshold > authorities.len() {
            return Err("Invalid consensus quorum threshold".into());
        }
        let unique_keys: std::collections::HashSet<_> =
            authorities.values().map(|k| k.to_bytes()).collect();
        if unique_keys.len() != authorities.len() {
            return Err("Authority signing keys must be independent".into());
        }
        // Only signatures over exactly the same canonical snapshot may combine.
        let mut snapshots: std::collections::HashMap<
            [u8; 32],
            crate::mesh::consensus::ConsensusDocument,
        > = std::collections::HashMap::new();
        for doc in docs {
            if doc.relays.len() > crate::mesh::consensus::MAX_DIRECTORY_RELAYS
                || doc.signatures.len() > 16
                || doc.valid_after >= doc.valid_until
                || current_time < doc.valid_after
                || current_time >= doc.valid_until
            {
                continue;
            }
            let digest = doc.compute_digest();
            snapshots
                .entry(digest)
                .and_modify(|d| {
                    d.merge_signatures_from(doc);
                })
                .or_insert_with(|| doc.clone());
        }
        let mut candidates: Vec<_> = snapshots
            .into_values()
            .filter(|d| d.verify_quorum(authorities, quorum_threshold, current_time))
            .collect();
        candidates.sort_by_key(|d| std::cmp::Reverse(d.valid_after));
        let selected = candidates
            .first()
            .ok_or("No canonical directory snapshot reached quorum")?;
        if candidates.iter().any(|d| {
            d.valid_after == selected.valid_after && d.compute_digest() != selected.compute_digest()
        }) {
            return Err("Conflicting quorum-signed directory snapshots for one epoch".into());
        }
        let digest = selected.compute_digest();
        let mut accepted = self.accepted_snapshot.write().await;
        if let Some(previous) = accepted.as_ref() {
            if selected.valid_after < previous.epoch
                || (selected.valid_after == previous.epoch && digest != previous.digest)
            {
                return Err("Directory rollback or same-epoch equivocation rejected".into());
            }
        }
        let final_relays = selected.relays.clone();
        if final_relays.is_empty() || final_relays.iter().any(|r| !r.verify_identity()) {
            return Err("Directory must contain valid signed relay descriptors".into());
        }
        let deadline = selected.valid_until;
        // An endpoint must not ambiguously represent different signed identities.
        let mut endpoints = std::collections::HashMap::new();
        for relay in &final_relays {
            let endpoint = (relay.host.clone(), relay.port);
            if let Some(previous) = endpoints.insert(endpoint, relay.identity_key_ed25519) {
                if previous != relay.identity_key_ed25519 {
                    return Err("Conflicting relay identities at the same endpoint".into());
                }
            }
        }

        // Parse everything before publishing; invalid descriptors cannot partially replace state.
        let mut replacement = IndexMap::new();
        let mut replacement_keys = IndexMap::new();
        let mut identities = std::collections::HashSet::new();
        let mut signing_keys = std::collections::HashSet::new();
        for relay in final_relays {
            if !identities.insert(relay.node_id.clone())
                || !signing_keys.insert(relay.identity_key_ed25519)
            {
                return Err("Duplicate relay identifier in directory snapshot".into());
            }
            if self.revoked.contains(&relay.identity_key_ed25519) {
                continue;
            }
            let endpoint = if relay.host.starts_with("reverse://") {
                relay.host.clone()
            } else if relay.host.contains(':') {
                format!("socks5://[{}]:{}", relay.host, relay.port)
            } else {
                format!("socks5://{}:{}", relay.host, relay.port)
            };
            let mut node = ProxyNode::parse(&endpoint)?;
            node.enforce_remote_dns();
            node.is_exit = relay.is_exit;
            let key = format!("{}:{}", node.host, node.port);
            if replacement.contains_key(&key) {
                return Err("Duplicate endpoint in directory snapshot".into());
            }
            replacement_keys.insert(key.clone(), relay.identity_key_ed25519);
            replacement.insert(key, node);
        }
        let next = AcceptedSnapshot {
            epoch: selected.valid_after,
            digest,
        };
        if replacement.is_empty() {
            return Err("Directory contains no non-retired relays".into());
        }
        if let Some(path) = self.snapshot_path.read().await.as_ref() {
            let bytes = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
            crate::core::storage::atomic_write(path, &bytes)
                .map_err(|e| format!("Cannot persist directory rollback state: {e}"))?;
        }
        let mut list = self.nodes.write().await;
        let mut id_keys = self.identity_keys.write().await;
        let loaded = replacement.len();
        *list = replacement;
        *id_keys = replacement_keys;
        *accepted = Some(next);
        self.consensus_deadline.store(deadline, Ordering::Release);
        Ok(loaded)
    }

    /// Checks if a given host:port is a known mesh target from the consensus.
    pub async fn is_mesh_target(&self, host: &str, port: u16) -> bool {
        if self.directory_expired() {
            return false;
        }
        let id_keys = self.identity_keys.read().await;
        id_keys.contains_key(&format!("{}:{}", host, port))
    }

    /// Returns the pinned Ed25519 identity keys for each node in a chain, in order.
    /// Nodes loaded from text files (not consensus) will return `[0u8; 32]` (zeroed),
    /// which `build_telescopic_circuit` will reject — enforcing consensus-sourced routing.
    pub async fn get_identity_keys(&self, chain: &[ProxyNode]) -> Vec<[u8; 32]> {
        if self.directory_expired() {
            return vec![[0; 32]; chain.len()];
        }
        let id_keys = self.identity_keys.read().await;
        chain
            .iter()
            .map(|n| {
                let key_id = format!("{}:{}", n.host, n.port);
                id_keys.get(&key_id).copied().unwrap_or([0u8; 32])
            })
            .collect()
    }

    /// Only entry-link failures cause a cooldown; downstream failures never rotate guards.
    pub async fn note_guard_link_failure(&self, identity: [u8; 32]) {
        let now = tokio::time::Instant::now();
        let mut cooldowns = self.guard_cooldowns.write().await;
        cooldowns.retain(|_, until| *until > now);
        cooldowns.insert(identity, now + std::time::Duration::from_secs(60));
    }

    /// Retrieves the next alive proxy using round-robin rotation.
    pub async fn get_next(&self) -> Option<ProxyNode> {
        if self.directory_expired() {
            return None;
        }
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
        if self.directory_expired() {
            return Vec::new();
        }
        let list = self.nodes.read().await;
        let mut healthy: Vec<ProxyNode> = list.values().filter(|n| n.is_alive).cloned().collect();

        // Fallback if all are marked dead (for testing/fault tolerance)
        if healthy.is_empty() {
            healthy = list.values().cloned().collect();
        }

        if min_hops == 0 || max_hops < min_hops || healthy.len() < min_hops {
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

    /// Retrieves a chain enforcing IPv4 /16 and IPv6 /32 address-prefix diversity.
    /// Prefix diversity is a selection constraint, not proof of independent operators
    /// or resistance to Sybil attacks and traffic correlation.
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
        self.get_diverse_onion_chain_with_exit(min_hops, max_hops, enforce_diversity, true)
            .await
    }

    /// Internal builder with explicit exit-enforcement flag.
    pub async fn get_diverse_onion_chain_with_exit(
        &self,
        min_hops: usize,
        max_hops: usize,
        enforce_diversity: bool,
        require_exit_at_last: bool,
    ) -> Vec<ProxyNode> {
        self.get_onion_chain_with_entry_pins(
            min_hops,
            max_hops,
            enforce_diversity,
            require_exit_at_last,
            &[],
        )
        .await
    }

    /// An independently provisioned private entry followed by two certified hops.
    /// Private metadata remains local and is never inserted into the public pool.
    pub async fn get_private_bridge_chain(
        &self,
        bindings: &[crate::onion::transport::BridgeTransport],
        enforce_diversity: bool,
    ) -> Vec<ProxyNode> {
        if bindings.is_empty()
            || bindings
                .iter()
                .any(|binding| self.revoked.contains(&binding.identity))
            || self.consensus_deadline.load(Ordering::Acquire) == 0
            || self.directory_expired()
        {
            return Vec::new();
        }
        let list = self.nodes.read().await;
        let keys = self.identity_keys.read().await;
        let cooldowns = self.guard_cooldowns.read().await;
        let mut state = self.guard_state.write().await;
        if state.guards.is_empty() {
            let previous = state.clone();
            for binding in bindings.iter().take(3) {
                let endpoint = format!("{}:{}", binding.bridge.ip(), binding.bridge.port());
                state.guards.push(endpoint.clone());
                state.identities.insert(endpoint, binding.identity);
            }
            if let Some(path) = self.guard_state_path.read().await.as_ref() {
                if state.save_checked(path).is_err() {
                    *state = previous;
                    return Vec::new();
                }
            }
        }
        let binding = state.guards.iter().find_map(|endpoint| {
            bindings.iter().find(|binding| {
                *endpoint == format!("{}:{}", binding.bridge.ip(), binding.bridge.port())
                    && state.identities.get(endpoint) == Some(&binding.identity)
                    && cooldowns
                        .get(&binding.identity)
                        .is_none_or(|until| *until <= tokio::time::Instant::now())
            })
        });
        let Some(binding) = binding else {
            return Vec::new();
        };
        let entry = match ProxyNode::parse(&format!("socks5://{}", binding.bridge)) {
            Ok(entry) => entry,
            Err(_) => return Vec::new(),
        };
        let mut candidates: Vec<_> = list
            .values()
            .filter(|node| {
                node.is_alive
                    && keys
                        .get(&format!("{}:{}", node.host, node.port))
                        .is_some_and(|pin| {
                            *pin != [0; 32]
                                && !bindings.iter().any(|binding| binding.identity == *pin)
                        })
                    && !bindings
                        .iter()
                        .any(|binding| binding.bridge.ip().to_string() == node.host)
            })
            .cloned()
            .collect();
        candidates.shuffle(&mut rand::thread_rng());
        for middle in candidates.iter().filter(|node| !node.is_exit) {
            for exit in candidates.iter().filter(|node| node.is_exit) {
                if middle.host == exit.host && middle.port == exit.port {
                    continue;
                }
                if enforce_diversity
                    && crate::mesh::sybil::validate_circuit_diversity(&[
                        entry.host.as_str(),
                        middle.host.as_str(),
                        exit.host.as_str(),
                    ])
                    .is_err()
                {
                    continue;
                }
                return vec![entry, middle.clone(), exit.clone()];
            }
        }
        Vec::new()
    }

    /// Mandatory entry allowlist for provisioned transport mode. Existing guards
    /// outside this set fail closed; switching profiles needs separate guard state.
    pub async fn get_onion_chain_with_entry_pins(
        &self,
        min_hops: usize,
        max_hops: usize,
        enforce_diversity: bool,
        require_exit_at_last: bool,
        entry_pins: &[[u8; 32]],
    ) -> Vec<ProxyNode> {
        if self.directory_expired() {
            return Vec::new();
        }
        let list = self.nodes.read().await;
        let identities = self.identity_keys.read().await;
        let cooldowns = self.guard_cooldowns.read().await;
        let all_healthy: Vec<ProxyNode> = {
            let v: Vec<ProxyNode> = list
                .values()
                .filter(|n| {
                    n.is_alive
                        && identities
                            .get(&format!("{}:{}", n.host, n.port))
                            .and_then(|key| cooldowns.get(key))
                            .is_none_or(|until| *until <= tokio::time::Instant::now())
                })
                .cloned()
                .collect();
            v
        };
        drop(cooldowns);
        drop(identities);

        if min_hops == 0 || max_hops < min_hops || all_healthy.len() < min_hops {
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
            tracing::warn!(
                "No exit-capable relays available in the pool — cannot build a valid circuit"
            );
            return Vec::new();
        }

        // Build the non-exit portion of the chain (path_len - 1 middle hops)
        let middle_count = if require_exit_at_last {
            path_len.saturating_sub(1)
        } else {
            path_len
        };
        let mut pool_for_middles = middle_nodes;

        {
            let mut rng = rand::thread_rng();
            pool_for_middles.shuffle(&mut rng);
        }

        let mut selected: Vec<ProxyNode> = Vec::new();

        // A fixed small guard set prevents repeated failures from forcing unlimited rotation.
        if middle_count > 0 {
            let keys = self.identity_keys.read().await;
            let mut state = self.guard_state.write().await;
            let previous = state.clone();
            if state.guards.is_empty() {
                for node in pool_for_middles
                    .iter()
                    .filter(|node| {
                        entry_pins.is_empty()
                            || keys
                                .get(&format!("{}:{}", node.host, node.port))
                                .is_some_and(|pin| entry_pins.contains(pin))
                    })
                    .take(3)
                {
                    let endpoint = format!("{}:{}", node.host, node.port);
                    if let Some(key) = keys.get(&endpoint) {
                        state.identities.insert(endpoint.clone(), *key);
                    }
                    state.guards.push(endpoint);
                }
                if let Some(path) = self.guard_state_path.read().await.as_ref() {
                    if state.save_checked(path).is_err() {
                        *state = previous;
                        return Vec::new();
                    }
                }
            }
            let guard = state.guards.iter().find_map(|endpoint| {
                pool_for_middles
                    .iter()
                    .find(|node| {
                        let candidate = format!("{}:{}", node.host, node.port);
                        match state.identities.get(endpoint) {
                            Some(pin) => {
                                keys.get(&candidate) == Some(pin)
                                    && (entry_pins.is_empty() || entry_pins.contains(pin))
                            }
                            None => {
                                entry_pins.is_empty() && keys.is_empty() && &candidate == endpoint
                            }
                        }
                    })
                    .cloned()
            });
            let Some(guard) = guard else {
                return Vec::new();
            };
            pool_for_middles.retain(|node| node.host != guard.host || node.port != guard.port);
            selected.push(guard);
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
                    let mut test_hosts: Vec<&str> =
                        selected.iter().map(|n| n.host.as_str()).collect();
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

        if selected.len() != path_len {
            return Vec::new();
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

#[cfg(test)]
mod initialization_tests {
    use super::*;

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("anonguard-init-{:032x}", rand::random::<u128>()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn invalid_guard_state_does_not_publish_rollback_state_or_paths() {
        let directory = Directory::new();
        let path = directory.0.join("guards.json");
        let state = AcceptedSnapshot {
            epoch: 99,
            digest: [7; 32],
        };
        std::fs::write(
            path.with_extension("consensus.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        std::fs::write(&path, b"{invalid").unwrap();
        let pool = ProxyPool::new();
        assert!(pool.init_guard_state(path.clone()).await.is_err());
        assert!(pool.accepted_snapshot.read().await.is_none());
        assert!(pool.snapshot_path.read().await.is_none());
        assert!(pool.guard_state_path.read().await.is_none());
        crate::mesh::guards::GuardState::new()
            .save_checked(&path)
            .unwrap();
        pool.init_guard_state(path.clone()).await.unwrap();
        assert_eq!(
            pool.accepted_snapshot.read().await.as_ref().unwrap().epoch,
            99
        );
        assert_eq!(pool.guard_state_path.read().await.as_ref(), Some(&path));
    }

    #[tokio::test]
    async fn concurrent_initialization_cannot_switch_state_paths() {
        let directory = Directory::new();
        let pool = ProxyPool::new();
        let first = directory.0.join("first.json");
        let second = directory.0.join("second.json");
        let (one, two) = tokio::join!(
            pool.init_guard_state(first.clone()),
            pool.init_guard_state(second.clone())
        );
        assert_ne!(one.is_ok(), two.is_ok());
        let accepted = if one.is_ok() { first } else { second };
        assert_eq!(pool.guard_state_path.read().await.as_ref(), Some(&accepted));
        assert_eq!(
            pool.snapshot_path.read().await.as_ref(),
            Some(&accepted.with_extension("consensus.json"))
        );
    }
}
