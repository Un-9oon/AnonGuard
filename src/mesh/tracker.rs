//! Pinned hybrid TLS rendezvous. Waiting registrations own their sockets and
//! admission permits until handoff, EOF or a bounded lifetime.
use super::admission::{SourceAdmission, TokenBucket};
use crate::crypto::identity::{Signature, SigningKey, VerifyingKey, PROOF_SIZE};
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
/// Separate from long-lived waiting/tunnel slots: unauthenticated peers must
/// not occupy every connection with concurrent expensive hybrid handshakes.
pub const DEFAULT_MAX_TRACKER_HANDSHAKES: usize = 16;
pub const MAX_TRACKER_HANDSHAKES_PER_SOURCE: usize = super::admission::SOURCE_SLOTS;
const HANDSHAKE_BURST: u32 = 32;
const HANDSHAKE_REFILL: Duration = Duration::from_micros(62_500);
const MAX_WAITING: usize = 128;
const MAX_PER_NODE: usize = 3;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
// Fits all 128 canonical node IDs, composite registration proofs and separators.
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
    valid_token(node)
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

fn registration_message(command: &str, challenge: &[u8; 32], exporter: &[u8; 32]) -> Vec<u8> {
    let mut message = b"AnonGuard-tracker-registration-v2\0".to_vec();
    message.extend_from_slice(&(command.len() as u32).to_be_bytes());
    message.extend_from_slice(command.as_bytes());
    message.extend_from_slice(challenge);
    message.extend_from_slice(exporter);
    message
}

/// Prove ownership of the canonical composite node ID on this exact TLS channel.
/// The returned control response may be an explicit refusal; never retries or
/// reinterprets an older registration protocol.
pub async fn register_reverse<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut tokio_rustls::client::TlsStream<S>,
    identity: &SigningKey,
    token: &str,
    timestamp: u64,
    nonce: u64,
) -> io::Result<String> {
    if !valid_token(token) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid capability",
        ));
    }
    let node = hex::encode(identity.verifying_key().to_bytes());
    let command = format!("REGISTER_REVERSE {node} {token} {timestamp} {nonce}");
    write_control(stream, &command).await?;
    let response = read_control(stream).await?;
    let Some(encoded) = response.strip_prefix("AUTH_CHALLENGE ") else {
        return Ok(response);
    };
    let challenge: [u8; 32] = hex::decode(encoded)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid registration challenge")
        })?;
    let mut exporter = [0; 32];
    stream
        .get_ref()
        .1
        .export_keying_material(
            &mut exporter,
            b"AnonGuard-tracker-registration-v2",
            Some(&challenge),
        )
        .map_err(|e| io::Error::other(e.to_string()))?;
    let proof = identity.sign(&registration_message(&command, &challenge, &exporter));
    write_control(stream, &hex::encode(proof.to_bytes())).await?;
    read_control(stream).await
}
pub struct TrackerServer {
    listen_addr: String,
    pub pow_difficulty: u32,
    identity: SigningKey,
    connection_semaphore: Arc<Semaphore>,
    handshake_semaphore: Arc<Semaphore>,
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
            handshake_semaphore: Arc::new(Semaphore::new(DEFAULT_MAX_TRACKER_HANDSHAKES)),
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
        let registration_budget = Arc::new(Semaphore::new(DEFAULT_MAX_TRACKER_HANDSHAKES));
        let acceptor = Arc::new(crate::onion::link::tracker_acceptor(&self.identity)?);
        let mut tasks = tokio::task::JoinSet::new();
        let mut handshake_rate = TokenBucket::new(
            HANDSHAKE_BURST,
            HANDSHAKE_REFILL,
            tokio::time::Instant::now(),
        );
        let mut sources = SourceAdmission::new();
        let mut source_sweep = tokio::time::interval(Duration::from_secs(30));
        source_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            while tasks.try_join_next().is_some() {}
            let (stream, peer) = tokio::select! {
                accepted = listener.accept() => accepted?,
                _ = source_sweep.tick() => {
                    sources.sweep(tokio::time::Instant::now());
                    continue;
                }
            };
            let Ok(permit) = self.connection_semaphore.clone().try_acquire_owned() else {
                continue;
            };
            // Never enqueue accepted unauthenticated sockets behind a permit.
            let Ok(handshake_permit) = self.handshake_semaphore.clone().try_acquire_owned() else {
                continue;
            };
            let now = tokio::time::Instant::now();
            // Reject exhausted global budget before allocating source accounting.
            // Source refusal must not spend global rate credit.
            if !handshake_rate.available(now) {
                continue;
            }
            let Some(source_permit) = sources.try_admit(peer.ip(), now) else {
                continue;
            };
            if !handshake_rate.take(now) {
                continue;
            }
            let (directory, waiting, acceptor, registry) = (
                directory.clone(),
                waiting.clone(),
                acceptor.clone(),
                self.nonce_registry.clone(),
            );
            let difficulty = self.pow_difficulty;
            let registration_budget = registration_budget.clone();
            tasks.spawn(async move {
                let authenticated = crate::onion::link::accept_tracker(&acceptor, stream).await;
                // Waiting registrations and active tunnels have their own bounds.
                drop((handshake_permit, source_permit));
                if let Ok(stream) = authenticated {
                    let _ = handle(
                        stream,
                        directory,
                        waiting,
                        registry,
                        difficulty,
                        permit,
                        registration_budget,
                    )
                    .await;
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
    registration_budget: Arc<Semaphore>,
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
                });
            if !valid {
                return write_control(&mut stream, "ERROR_INVALID_POW").await;
            }
            let Ok(proof_permit) = registration_budget.try_acquire_owned() else {
                return write_control(&mut stream, "ERROR_BUSY").await;
            };
            let challenge = rand::random::<[u8; 32]>();
            write_control(
                &mut stream,
                &format!("AUTH_CHALLENGE {}", hex::encode(challenge)),
            )
            .await?;
            let encoded = read_control(&mut stream).await?;
            // Bound before allocating or decoding a proof; verify the composite
            // pin before allowing either directory ownership or nonce mutation.
            if encoded.len() != PROOF_SIZE * 2 {
                return write_control(&mut stream, "ERROR_UNAUTHORIZED").await;
            }
            let mut exporter = [0; 32];
            stream
                .get_ref()
                .1
                .export_keying_material(
                    &mut exporter,
                    b"AnonGuard-tracker-registration-v2",
                    Some(&challenge),
                )
                .map_err(|e| io::Error::other(e.to_string()))?;
            let authenticated = (|| -> io::Result<()> {
                let bytes = hex::decode(encoded).map_err(io::Error::other)?;
                let pin: [u8; 32] = hex::decode(node)
                    .map_err(io::Error::other)?
                    .try_into()
                    .map_err(|_| io::Error::other("Invalid node pin"))?;
                VerifyingKey::from_bytes(&pin)?.verify_strict(
                    &registration_message(&command, &challenge, &exporter),
                    &Signature::from_slice(&bytes)?,
                )
            })();
            if authenticated.is_err() {
                return write_control(&mut stream, "ERROR_UNAUTHORIZED").await;
            }
            let nonce = nonce.parse::<u64>().map_err(io::Error::other)?;
            if registry.check_and_record(node, nonce, now) {
                return write_control(&mut stream, "ERROR_INVALID_POW").await;
            }
            drop(proof_permit);
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

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn completed_or_failed_handshake_churn_cannot_reset_rate_budget() {
        let start = tokio::time::Instant::now();
        let mut rate = TokenBucket::new(HANDSHAKE_BURST, HANDSHAKE_REFILL, start);
        for _ in 0..HANDSHAKE_BURST {
            assert!(rate.take(start));
        }
        for _ in 0..1000 {
            assert!(!rate.take(start));
        }
        assert!(!rate.take(start + HANDSHAKE_REFILL - Duration::from_nanos(1)));
        assert!(rate.take(start + HANDSHAKE_REFILL));
        assert!(!rate.take(start + HANDSHAKE_REFILL));
        // A long idle period restores a bounded burst, never an unbounded credit.
        let later = start + Duration::from_secs(3600);
        for _ in 0..HANDSHAKE_BURST {
            assert!(rate.take(later));
        }
        assert!(!rate.take(later));
    }
}
