//! High-concurrency proxy pool with auto-rotation on block.

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

        for line in reader.lines() {
            if let Ok(l) = line {
                let trimmed = l.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    if self.add_proxy(trimmed).await.is_ok() {
                        loaded += 1;
                    }
                }
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
        self.nodes.read().await.iter().filter(|n| n.is_alive).count()
    }
}

impl Default for ProxyPool {
    fn default() -> Self {
        Self::new()
    }
}
