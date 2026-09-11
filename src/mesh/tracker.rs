use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// In-memory directory of active nodes: IP -> Last Seen
type Directory = Arc<RwLock<HashMap<String, Instant>>>;

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
        info!("Directory Authority (Tracker) listening on {}", self.listen_addr);

        // Spawn a background task to prune dead nodes
        let dir_clone = self.directory.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let mut dir = dir_clone.write().await;
                let now = Instant::now();
                dir.retain(|_, last_seen| now.duration_since(*last_seen).as_secs() < 90);
            }
        });

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

async fn handle_connection(mut stream: TcpStream, directory: Directory) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).await?;

    if first_line.starts_with("POST /register") {
        // Simple protocol: Body is the exact socks5 URI.
        let mut body = vec![0; 1024];
        let n = reader.read(&mut body).await?;
        let req_str = String::from_utf8_lossy(&body[..n]);
        
        // Find the body (after \r\n\r\n)
        if let Some(idx) = req_str.find("\r\n\r\n") {
            let proxy_uri = req_str[idx + 4..].trim().to_string();
            if proxy_uri.starts_with("socks5://") {
                directory.write().await.insert(proxy_uri.clone(), Instant::now());
                info!("Registered active node: {}", proxy_uri);
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        }
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;

    } else if first_line.starts_with("GET /nodes") {
        let dir = directory.read().await;
        let mut nodes: Vec<String> = dir.keys().cloned().collect();
        nodes.sort();
        let body = nodes.join("\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
    } else {
        let response = "HTTP/1.1 404 Not Found\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }

    Ok(())
}
