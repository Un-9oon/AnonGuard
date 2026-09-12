use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

// In-memory directory of active nodes: NodeID -> ReverseNodeEntry
#[derive(Clone)]
pub struct ReverseNodeEntry {
    pub auth_token: String,
    pub streams: Arc<Mutex<Vec<TcpStream>>>,
}

type Directory = Arc<RwLock<HashMap<String, ReverseNodeEntry>>>;

pub struct TrackerServer {
    listen_addr: String,
    directory: Directory,
}

impl TrackerServer {
    pub fn new(listen_addr: String) -> Self {
        Self {
            listen_addr,
            directory: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("Rendezvous Tracker listening on {}", self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let dir = self.directory.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, dir).await {
                    warn!("Tracker connection from {} failed: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_connection(stream: TcpStream, directory: Directory) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).await?;

    let cmd = first_line.trim().to_string();

    if cmd.starts_with("REGISTER_REVERSE") {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.len() >= 4 {
            let (node_id, auth_token, ts_str, nonce_str) = if parts.len() >= 5 {
                (
                    parts[1].to_string(),
                    parts[2].to_string(),
                    parts[3],
                    parts[4],
                )
            } else {
                (parts[1].to_string(), String::new(), parts[2], parts[3])
            };

            let timestamp: u64 = match ts_str.parse() {
                Ok(ts) => ts,
                Err(_) => {
                    warn!("Invalid timestamp in REGISTER_REVERSE: {}", ts_str);
                    use tokio::io::AsyncWriteExt;
                    let mut s = reader.into_inner();
                    let _ = s.write_all(b"ERROR_INVALID_TIMESTAMP\n").await;
                    return Ok(());
                }
            };
            let nonce: u64 = match nonce_str.parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!("Invalid nonce in REGISTER_REVERSE: {}", nonce_str);
                    use tokio::io::AsyncWriteExt;
                    let mut s = reader.into_inner();
                    let _ = s.write_all(b"ERROR_INVALID_NONCE\n").await;
                    return Ok(());
                }
            };

            let now = crate::mesh::sybil::current_timestamp_secs();
            if !crate::mesh::sybil::verify_pow(
                &node_id,
                timestamp,
                nonce,
                crate::mesh::sybil::DEFAULT_POW_DIFFICULTY,
                now,
            ) {
                warn!(
                    "Rejected unauthenticated REGISTER_REVERSE for node {} (invalid PoW)",
                    node_id
                );
                use tokio::io::AsyncWriteExt;
                let mut s = reader.into_inner();
                let _ = s.write_all(b"ERROR_INVALID_POW\n").await;
                return Ok(());
            }

            let mut dir = directory.write().await;
            if let Some(existing) = dir.get(&node_id) {
                if !existing.auth_token.is_empty()
                    && !auth_token.is_empty()
                    && existing.auth_token != auth_token
                {
                    warn!(
                        "Rejected REGISTER_REVERSE for node {} (auth token mismatch/hijacking attempt)",
                        node_id
                    );
                    use tokio::io::AsyncWriteExt;
                    let mut s = reader.into_inner();
                    let _ = s.write_all(b"ERROR_AUTH_TOKEN_MISMATCH\n").await;
                    return Ok(());
                }
            }

            info!(
                "Registered reverse connection for authenticated Node: {}",
                node_id
            );

            // Extract the underlying stream out of the BufReader
            let raw_stream = reader.into_inner();

            let entry = dir.entry(node_id).or_insert_with(|| ReverseNodeEntry {
                auth_token,
                streams: Arc::new(Mutex::new(Vec::new())),
            });
            entry.streams.lock().await.push(raw_stream);
        } else {
            warn!("Rejected malformed REGISTER_REVERSE (missing PoW credentials)");
            use tokio::io::AsyncWriteExt;
            let mut s = reader.into_inner();
            let _ = s.write_all(b"ERROR_POW_REQUIRED\n").await;
            return Ok(());
        }
    } else if cmd.starts_with("CONNECT_REVERSE") {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.len() >= 2 {
            let node_id = parts[1].to_string();
            let provided_token = parts.get(2).copied().unwrap_or("");

            let entry_opt = {
                let dir = directory.read().await;
                dir.get(&node_id).cloned()
            };

            if let Some(entry) = entry_opt {
                if !entry.auth_token.is_empty() && entry.auth_token != provided_token {
                    warn!(
                        "Rejected unauthorized CONNECT_REVERSE for node {} (token mismatch)",
                        node_id
                    );
                    use tokio::io::AsyncWriteExt;
                    reader
                        .into_inner()
                        .write_all(b"ERROR_UNAUTHORIZED\n")
                        .await?;
                    return Ok(());
                }

                let popped_stream = entry.streams.lock().await.pop();

                if let Some(mut target_stream) = popped_stream {
                    info!("Bridging connection to authorized Node: {}", node_id);
                    let mut client_stream = reader.into_inner();
                    // Tell the client we are ready
                    use tokio::io::AsyncWriteExt;
                    client_stream.write_all(b"OK\n").await?;
                    let _ =
                        tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await;
                } else {
                    use tokio::io::AsyncWriteExt;
                    reader.into_inner().write_all(b"ERROR_NO_STREAMS\n").await?;
                }
            } else {
                use tokio::io::AsyncWriteExt;
                reader
                    .into_inner()
                    .write_all(b"ERROR_NODE_NOT_FOUND\n")
                    .await?;
            }
        }
    } else if cmd.starts_with("GET /nodes") {
        let dir = directory.read().await;
        // Return nodes that have at least 1 stream available
        let mut nodes = Vec::new();
        for (id, entry) in dir.iter() {
            if !entry.streams.lock().await.is_empty() {
                if !entry.auth_token.is_empty() {
                    nodes.push(format!("{} {}", id, entry.auth_token));
                } else {
                    nodes.push(id.clone());
                }
            }
        }
        nodes.sort();
        let body = nodes.join("\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        use tokio::io::AsyncWriteExt;
        reader.into_inner().write_all(response.as_bytes()).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tracker_pow_authentication() {
        let directory: Directory = Arc::new(RwLock::new(HashMap::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dir_clone = directory.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, dir_clone).await;
        });

        // 1. Send unauthenticated registration without PoW
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"REGISTER_REVERSE node1\n").await.unwrap();
        let mut resp = [0u8; 64];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("ERROR_POW_REQUIRED"));

        // 2. Send registration with valid PoW
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let dir_clone2 = directory.clone();
        tokio::spawn(async move {
            let (stream, _) = listener2.accept().await.unwrap();
            let _ = handle_connection(stream, dir_clone2).await;
        });

        let mut client2 = TcpStream::connect(addr2).await.unwrap();
        let now = crate::mesh::sybil::current_timestamp_secs();
        let nonce =
            crate::mesh::sybil::solve_pow("node2", now, crate::mesh::sybil::DEFAULT_POW_DIFFICULTY);
        let msg = format!("REGISTER_REVERSE node2 secret_auth_123 {} {}\n", now, nonce);
        client2.write_all(msg.as_bytes()).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let dir = directory.read().await;
        assert!(dir.contains_key("node2"));
        let entry = dir.get("node2").unwrap();
        assert_eq!(entry.auth_token, "secret_auth_123");
        assert_eq!(entry.streams.lock().await.len(), 1);
        drop(dir);

        // 3. Test unauthorized CONNECT_REVERSE rejection
        let listener3 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr3 = listener3.local_addr().unwrap();
        let dir_clone3 = directory.clone();
        tokio::spawn(async move {
            let (stream, _) = listener3.accept().await.unwrap();
            let _ = handle_connection(stream, dir_clone3).await;
        });

        let mut attacker = TcpStream::connect(addr3).await.unwrap();
        attacker
            .write_all(b"CONNECT_REVERSE node2 wrong_token\n")
            .await
            .unwrap();
        let mut err_resp = [0u8; 64];
        let n = attacker.read(&mut err_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&err_resp[..n]).contains("ERROR_UNAUTHORIZED"));
    }
}
