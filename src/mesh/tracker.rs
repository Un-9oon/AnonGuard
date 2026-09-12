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
        if parts.len() >= 2 {
            let node_id = parts[1].to_string();
            info!("Registered reverse connection for Node: {}", node_id);

            // Extract the underlying stream out of the BufReader
            let raw_stream = reader.into_inner();

            let mut dir = directory.write().await;
            let pool = dir
                .entry(node_id)
                .or_insert_with(|| Arc::new(Mutex::new(Vec::new())));
            pool.lock().await.push(raw_stream);
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
