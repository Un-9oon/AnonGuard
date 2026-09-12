use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

// In-memory directory of active nodes: NodeID -> Pool of open TcpStreams
type StreamPool = Arc<Mutex<Vec<TcpStream>>>;
type Directory = Arc<RwLock<HashMap<String, StreamPool>>>;

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
            let node_id = parts[1].to_string();
            let timestamp: u64 = match parts[2].parse() {
                Ok(ts) => ts,
                Err(_) => {
                    warn!("Invalid timestamp in REGISTER_REVERSE: {}", parts[2]);
                    use tokio::io::AsyncWriteExt;
                    let mut s = reader.into_inner();
                    let _ = s.write_all(b"ERROR_INVALID_TIMESTAMP\n").await;
                    return Ok(());
                }
            };
            let nonce: u64 = match parts[3].parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!("Invalid nonce in REGISTER_REVERSE: {}", parts[3]);
                    use tokio::io::AsyncWriteExt;
                    let mut s = reader.into_inner();
                    let _ = s.write_all(b"ERROR_INVALID_NONCE\n").await;
                    return Ok(());
                }
            };

            let now = crate::mesh::sybil::current_timestamp_secs();
            if !crate::mesh::sybil::verify_pow(&node_id, timestamp, nonce, 12, now) {
                warn!(
                    "Rejected unauthenticated REGISTER_REVERSE for node {} (invalid PoW)",
                    node_id
                );
                use tokio::io::AsyncWriteExt;
                let mut s = reader.into_inner();
                let _ = s.write_all(b"ERROR_INVALID_POW\n").await;
                return Ok(());
            }

            info!("Registered reverse connection for authenticated Node: {}", node_id);

            // Extract the underlying stream out of the BufReader
            let raw_stream = reader.into_inner();

            let mut dir = directory.write().await;
            let pool = dir
                .entry(node_id)
                .or_insert_with(|| Arc::new(Mutex::new(Vec::new())));
            pool.lock().await.push(raw_stream);
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

            let pool_opt = {
                let dir = directory.read().await;
                dir.get(&node_id).cloned()
            };

            if let Some(pool) = pool_opt {
                let popped_stream = pool.lock().await.pop();

                if let Some(mut target_stream) = popped_stream {
                    info!("Bridging connection to Node: {}", node_id);
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
        // Only return nodes that have at least 1 stream available
        let mut nodes = Vec::new();
        for (id, pool) in dir.iter() {
            if !pool.lock().await.is_empty() {
                nodes.push(id.clone());
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
        let nonce = crate::mesh::sybil::solve_pow("node2", now, 12);
        let msg = format!("REGISTER_REVERSE node2 {} {}\n", now, nonce);
        client2.write_all(msg.as_bytes()).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let dir = directory.read().await;
        assert!(dir.contains_key("node2"));
        assert_eq!(dir.get("node2").unwrap().lock().await.len(), 1);
    }
}
