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

pub const DEFAULT_MAX_TRACKER_CONNECTIONS: usize = 512;

pub struct TrackerServer {
    listen_addr: String,
    directory: Directory,
    pub pow_difficulty: u32,
    connection_semaphore: Arc<tokio::sync::Semaphore>,
}

impl TrackerServer {
    pub fn new(listen_addr: String) -> Self {
        Self::with_difficulty(listen_addr, crate::mesh::sybil::DEFAULT_POW_DIFFICULTY)
    }

    pub fn with_difficulty(listen_addr: String, pow_difficulty: u32) -> Self {
        Self {
            listen_addr,
            directory: Arc::new(RwLock::new(HashMap::new())),
            pow_difficulty,
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(
                DEFAULT_MAX_TRACKER_CONNECTIONS,
            )),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!(
            "Rendezvous Tracker listening on {} (max {} concurrent connections)",
            self.listen_addr, DEFAULT_MAX_TRACKER_CONNECTIONS
        );

        loop {
            let (stream, addr) = listener.accept().await?;
            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        "Tracker DoS defense: max concurrent limit ({}) reached, dropped connection from {}",
                        DEFAULT_MAX_TRACKER_CONNECTIONS, addr
                    );
                    continue;
                }
            };
            let dir = self.directory.clone();
            let pow_difficulty = self.pow_difficulty;
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_connection(stream, dir, pow_difficulty).await {
                    warn!("Tracker connection from {} failed: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    directory: Directory,
    pow_difficulty: u32,
) -> std::io::Result<()> {
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
            if !crate::mesh::sybil::verify_pow(&node_id, timestamp, nonce, pow_difficulty, now) {
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
                if !existing.auth_token.is_empty() && existing.auth_token != auth_token {
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
        // Return active node IDs only — NEVER leak secret auth_tokens to unauthenticated discovery callers
        let mut nodes = Vec::new();
        for (id, entry) in dir.iter() {
            if !entry.streams.lock().await.is_empty() {
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
        let test_difficulty = 12;
        let directory: Directory = Arc::new(RwLock::new(HashMap::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dir_clone = directory.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_connection(stream, dir_clone, test_difficulty).await;
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
            let _ = handle_connection(stream, dir_clone2, test_difficulty).await;
        });

        let mut client2 = TcpStream::connect(addr2).await.unwrap();
        let now = crate::mesh::sybil::current_timestamp_secs();
        let nonce = crate::mesh::sybil::solve_pow("node2", now, test_difficulty);
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
            let _ = handle_connection(stream, dir_clone3, test_difficulty).await;
        });

        let mut attacker = TcpStream::connect(addr3).await.unwrap();
        attacker
            .write_all(b"CONNECT_REVERSE node2 wrong_token\n")
            .await
            .unwrap();
        let mut err_resp = [0u8; 64];
        let n = attacker.read(&mut err_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&err_resp[..n]).contains("ERROR_UNAUTHORIZED"));

        // 4. Test REGISTER_REVERSE hijacking with empty token is strictly rejected
        let listener4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr4 = listener4.local_addr().unwrap();
        let dir_clone4 = directory.clone();
        tokio::spawn(async move {
            let (stream, _) = listener4.accept().await.unwrap();
            let _ = handle_connection(stream, dir_clone4, test_difficulty).await;
        });

        let mut attacker2 = TcpStream::connect(addr4).await.unwrap();
        let nonce_atk = crate::mesh::sybil::solve_pow("node2", now, test_difficulty);
        let msg_atk = format!("REGISTER_REVERSE node2 {} {}\n", now, nonce_atk);
        attacker2.write_all(msg_atk.as_bytes()).await.unwrap();
        let mut err_resp2 = [0u8; 64];
        let n2 = attacker2.read(&mut err_resp2).await.unwrap();
        assert!(String::from_utf8_lossy(&err_resp2[..n2]).contains("ERROR_AUTH_TOKEN_MISMATCH"));

        // 5. Test GET /nodes discovery NEVER leaks the secret auth_token
        let listener5 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr5 = listener5.local_addr().unwrap();
        let dir_clone5 = directory.clone();
        tokio::spawn(async move {
            let (stream, _) = listener5.accept().await.unwrap();
            let _ = handle_connection(stream, dir_clone5, test_difficulty).await;
        });

        let mut discoverer = TcpStream::connect(addr5).await.unwrap();
        discoverer
            .write_all(b"GET /nodes HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut disc_resp = [0u8; 512];
        let nd = discoverer.read(&mut disc_resp).await.unwrap();
        let disc_text = String::from_utf8_lossy(&disc_resp[..nd]);
        assert!(disc_text.contains("node2"));
        assert!(
            !disc_text.contains("secret_auth_123"),
            "GET /nodes must NEVER leak secret auth_token!"
        );

        // 6. Test authorized CONNECT_REVERSE succeeds with correct token
        let listener6 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr6 = listener6.local_addr().unwrap();
        let dir_clone6 = directory.clone();
        tokio::spawn(async move {
            let (stream, _) = listener6.accept().await.unwrap();
            let _ = handle_connection(stream, dir_clone6, test_difficulty).await;
        });

        let mut auth_client = TcpStream::connect(addr6).await.unwrap();
        auth_client
            .write_all(b"CONNECT_REVERSE node2 secret_auth_123\n")
            .await
            .unwrap();
        let mut ok_resp = [0u8; 64];
        let nok = auth_client.read(&mut ok_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&ok_resp[..nok]).contains("OK"));
    }
}
