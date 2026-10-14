//! Pinned hybrid TLS rendezvous. Waiting registrations own their sockets and
//! admission permits until handoff, EOF or a bounded lifetime.
use crate::crypto::identity::SigningKey;
use std::{collections::HashMap, io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Mutex, OwnedSemaphorePermit, Semaphore},
};

type Stream = tokio_rustls::server::TlsStream<TcpStream>;
type Handoff = oneshot::Sender<(Stream, OwnedSemaphorePermit)>;
struct Waiting {
    id: u64,
    request: oneshot::Sender<Handoff>,
}
struct Entry {
    token: String,
    waiting: Vec<Waiting>,
}
type Directory = Arc<Mutex<HashMap<String, Entry>>>;
pub const DEFAULT_MAX_TRACKER_CONNECTIONS: usize = 512;
const MAX_WAITING: usize = 128;
const MAX_PER_NODE: usize = 3;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
// Fits all 128 waiting node IDs (128 bytes each plus separators).
const MAX_CONTROL: usize = 32 * 1024;

pub async fn read_control<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<String> {
    read_control_with_timeout(stream, CONTROL_TIMEOUT).await
}
pub async fn read_control_wait<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<String> {
    read_control_with_timeout(stream, WAIT_TIMEOUT + CONTROL_TIMEOUT).await
}
async fn read_control_with_timeout<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> io::Result<String> {
    tokio::time::timeout(timeout, async {
        let size = stream.read_u32().await? as usize;
        if size == 0 || size > MAX_CONTROL {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid tracker control length",
            ));
        }
        let mut data = vec![0; size];
        stream.read_exact(&mut data).await?;
        String::from_utf8(data).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid tracker control UTF-8")
        })
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Tracker control timed out"))?
}
pub async fn write_control<S: AsyncWrite + Unpin>(stream: &mut S, value: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_CONTROL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid tracker control length",
        ));
    }
    tokio::time::timeout(CONTROL_TIMEOUT, async {
        stream.write_u32(value.len() as u32).await?;
        stream.write_all(value.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Tracker write timed out"))?
}
fn valid_node(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= 128
        && node
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn tokens_match(a: &str, b: &str) -> bool {
    subtle::ConstantTimeEq::ct_eq(a.as_bytes(), b.as_bytes()).unwrap_u8() == 1
}
pub struct TrackerServer {
    listen_addr: String,
    pub pow_difficulty: u32,
    identity: SigningKey,
    connection_semaphore: Arc<Semaphore>,
    nonce_registry: Arc<crate::mesh::sybil::NonceRegistry>,
}
impl TrackerServer {
    pub fn new(listen_addr: String) -> Self {
        Self::with_difficulty(listen_addr, crate::mesh::sybil::DEFAULT_POW_DIFFICULTY)
    }
    pub fn with_difficulty(listen_addr: String, pow_difficulty: u32) -> Self {
        Self {
            listen_addr,
            pow_difficulty,
            identity: SigningKey::generate(&mut rand::rngs::OsRng),
            connection_semaphore: Arc::new(Semaphore::new(DEFAULT_MAX_TRACKER_CONNECTIONS)),
            nonce_registry: Arc::new(crate::mesh::sybil::NonceRegistry::new()),
        }
    }
    pub fn with_identity(mut self, identity: SigningKey) -> Self {
        self.identity = identity;
        self
    }
    pub fn identity_pin(&self) -> [u8; 32] {
        self.identity.verifying_key().to_bytes()
    }
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.run_listener(TcpListener::bind(&self.listen_addr).await?)
            .await
    }
    pub async fn run_listener(
        &self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory: Directory = Arc::new(Mutex::new(HashMap::new()));
        let waiting = Arc::new(Semaphore::new(MAX_WAITING));
        let acceptor = Arc::new(crate::onion::link::tracker_acceptor(&self.identity)?);
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            while tasks.try_join_next().is_some() {}
            let (stream, _) = listener.accept().await?;
            let Ok(permit) = self.connection_semaphore.clone().try_acquire_owned() else {
                continue;
            };
            let (directory, waiting, acceptor, registry) = (
                directory.clone(),
                waiting.clone(),
                acceptor.clone(),
                self.nonce_registry.clone(),
            );
            let difficulty = self.pow_difficulty;
            tasks.spawn(async move {
                if let Ok(stream) = crate::onion::link::accept_tracker(&acceptor, stream).await {
                    let _ = handle(stream, directory, waiting, registry, difficulty, permit).await;
                }
            });
        }
    }
}
async fn handle(
    mut stream: Stream,
    directory: Directory,
    waiting: Arc<Semaphore>,
    registry: Arc<crate::mesh::sybil::NonceRegistry>,
    difficulty: u32,
    permit: OwnedSemaphorePermit,
) -> io::Result<()> {
    let command = read_control(&mut stream).await?;
    let parts: Vec<_> = command.split_whitespace().collect();
    match parts.as_slice() {
        ["REGISTER_REVERSE", node, token, timestamp, nonce]
            if valid_node(node) && valid_token(token) =>
        {
            let now = crate::mesh::sybil::current_timestamp_secs();
            let valid = timestamp
                .parse::<u64>()
                .ok()
                .zip(nonce.parse::<u64>().ok())
                .is_some_and(|(ts, n)| {
                    crate::mesh::sybil::verify_pow(node, ts, n, difficulty, now)
                        && !registry.check_and_record(node, n, now)
                });
            if !valid {
                return write_control(&mut stream, "ERROR_INVALID_POW").await;
            }
            let Ok(wait_permit) = waiting.try_acquire_owned() else {
                return write_control(&mut stream, "ERROR_BUSY").await;
            };
            let id = rand::random::<u64>();
            let (request, mut receive) = oneshot::channel();
            let error = {
                let mut dir = directory.lock().await;
                let entry = dir.entry(node.to_string()).or_insert_with(|| Entry {
                    token: token.to_string(),
                    waiting: Vec::new(),
                });
                if !tokens_match(&entry.token, token) {
                    Some("ERROR_UNAUTHORIZED")
                } else if entry.waiting.len() >= MAX_PER_NODE {
                    Some("ERROR_BUSY")
                } else {
                    entry.waiting.push(Waiting { id, request });
                    None
                }
            };
            if let Some(error) = error {
                return write_control(&mut stream, error).await;
            }
            // Always remove the registration even when writing its ACK fails.
            let result = async {
                write_control(&mut stream, "REGISTERED").await?;
                let mut byte = [0u8; 1];
                let target = tokio::select! {
                    target=&mut receive => target.ok(),
                    _=stream.read(&mut byte)=>None,
                    _=tokio::time::sleep(WAIT_TIMEOUT)=>None,
                };
                if let Some(target) = target {
                    write_control(&mut stream, "READY").await?;
                    let _ = target.send((stream, permit));
                }
                Ok(())
            }
            .await;
            let mut dir = directory.lock().await;
            if let Some(entry) = dir.get_mut(*node) {
                entry.waiting.retain(|slot| slot.id != id);
                if entry.waiting.is_empty() {
                    dir.remove(*node);
                }
            }
            drop(wait_permit);
            result
        }
        ["CONNECT_REVERSE", node, token] if valid_node(node) && valid_token(token) => {
            let selected = {
                let mut dir = directory.lock().await;
                match dir.get_mut(*node) {
                    Some(entry) if tokens_match(&entry.token, token) => entry.waiting.pop(),
                    _ => None,
                }
            };
            let Some(selected) = selected else {
                return write_control(&mut stream, "ERROR_UNAVAILABLE").await;
            };
            let (target, receive) = oneshot::channel();
            if selected.request.send(target).is_err() {
                return write_control(&mut stream, "ERROR_UNAVAILABLE").await;
            }
            let Ok(Ok((mut relay, _relay_permit))) =
                tokio::time::timeout(CONTROL_TIMEOUT, receive).await
            else {
                return write_control(&mut stream, "ERROR_UNAVAILABLE").await;
            };
            write_control(&mut stream, "OK").await?;
            let _ = tokio::time::timeout(
                Duration::from_secs(3600),
                tokio::io::copy_bidirectional(&mut stream, &mut relay),
            )
            .await;
            Ok(())
        }
        ["NODES"] => {
            let mut nodes: Vec<_> = directory
                .lock()
                .await
                .iter()
                .filter(|(_, entry)| !entry.waiting.is_empty())
                .map(|(node, _)| node.clone())
                .collect();
            nodes.sort();
            // Bounded listing; capabilities are never advertised.
            let result = nodes.join("\n");
            write_control(
                &mut stream,
                if result.is_empty() { "EMPTY" } else { &result },
            )
            .await
        }
        _ => write_control(&mut stream, "ERROR_INVALID_COMMAND").await,
    }
}
