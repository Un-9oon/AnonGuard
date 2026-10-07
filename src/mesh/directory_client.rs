//! Bounded parallel directory requests with endpoint-specific identity pins.
use crate::core::config::AuthorityEndpoint;
use crate::mesh::{ConsensusDocument, ProxyPool, SecureTransportSession};
use ed25519_dalek::VerifyingKey;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::net::TcpStream;

pub struct PinnedDirectoryClient {
    endpoints: Vec<AuthorityEndpoint>,
    trusted: HashMap<String, VerifyingKey>,
    quorum: usize,
    rpc_timeout: Duration,
}

impl PinnedDirectoryClient {
    pub fn new(endpoints: Vec<AuthorityEndpoint>, quorum: usize) -> Result<Self, String> {
        if endpoints.is_empty()
            || endpoints.len() > 16
            || quorum < (2 * endpoints.len()) / 3 + 1
            || quorum > endpoints.len()
        {
            return Err(
                "Directory client requires 1..16 authorities and a quorum exceeding two thirds"
                    .into(),
            );
        }
        let mut trusted = HashMap::new();
        let mut keys = HashSet::new();
        let mut addresses = HashSet::new();
        for endpoint in &endpoints {
            if endpoint.identity.is_empty()
                || endpoint.identity.len() > 128
                || endpoint.address.is_empty()
                || endpoint.address.len() > 512
                || endpoint
                    .address
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                || !addresses.insert(endpoint.address.clone())
                || !keys.insert(endpoint.public_key)
            {
                return Err(
                    "Directory endpoints require distinct addresses, identities and signing keys"
                        .into(),
                );
            }
            let key = VerifyingKey::from_bytes(&endpoint.public_key).map_err(|e| e.to_string())?;
            if key.is_weak() || trusted.insert(endpoint.identity.clone(), key).is_some() {
                return Err("Invalid or duplicate directory identity pin".into());
            }
        }
        Ok(Self {
            endpoints,
            trusted,
            quorum,
            rpc_timeout: Duration::from_secs(15),
        })
    }

    async fn fetch_snapshots(&self) -> Vec<ConsensusDocument> {
        let replies = futures::future::join_all(self.endpoints.iter().map(|endpoint| async move {
            let pinned = &self.trusted[&endpoint.identity];
            let request = async {
                let socket = TcpStream::connect(endpoint.address.as_str()).await?;
                let mut session = SecureTransportSession::client_handshake(socket, Some(pinned)).await?;
                session.write_frame(b"GET_CONSENSUS").await?;
                let frame = session.read_frame().await?;
                let snapshot: ConsensusDocument = serde_json::from_slice(&frame)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                if snapshot.relays.len() > crate::mesh::consensus::MAX_DIRECTORY_RELAYS
                    || snapshot.signatures.len() > 16
                {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Directory snapshot exceeds limits"));
                }
                Ok(snapshot)
            };
            match tokio::time::timeout(self.rpc_timeout, request).await {
                Ok(Ok(snapshot)) => Some(snapshot),
                Ok(Err(error)) => {
                    tracing::warn!(identity = %endpoint.identity, %error, "Directory request failed");
                    None
                }
                Err(_) => {
                    tracing::warn!(identity = %endpoint.identity, "Directory request deadline exceeded");
                    None
                }
            }
        })).await;
        replies.into_iter().flatten().collect()
    }

    /// Collect all bounded replies before admission so conflicting certificates
    /// retain the same fail-closed treatment as rollback and invalid descriptors.
    pub async fn refresh(&self, pool: &ProxyPool) -> Result<usize, String> {
        let snapshots = self.fetch_snapshots().await;
        pool.load_from_multi_consensus(
            &snapshots,
            &self.trusted,
            self.quorum,
            crate::mesh::sybil::current_timestamp_secs(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::RelayDescriptor;
    use ed25519_dalek::SigningKey;
    use tokio::net::TcpListener;

    fn snapshot(host: &str) -> ConsensusDocument {
        let now = crate::mesh::sybil::current_timestamp_secs();
        let key = SigningKey::from_bytes(&[91; 32]);
        let mut relay = RelayDescriptor::new(
            "relay".into(),
            host.into(),
            9001,
            [1; 32],
            key.verifying_key().to_bytes(),
            true,
            1,
            now,
        );
        relay.sign_with_key(&key);
        ConsensusDocument::new((now / 300) * 300, (now / 300) * 300 + 600, vec![relay])
    }

    async fn mock(identity: String, key: SigningKey, reply: Option<Vec<u8>>) -> AuthorityEndpoint {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = AuthorityEndpoint {
            identity,
            address: listener.local_addr().unwrap().to_string(),
            public_key: key.verifying_key().to_bytes(),
        };
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(mut session) =
                SecureTransportSession::server_handshake(socket, Some(&key)).await
            {
                if session.read_frame().await.is_err() {
                    return;
                }
                if let Some(reply) = reply {
                    let _ = session.write_frame(&reply).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }
        });
        endpoint
    }

    #[test]
    fn configuration_cannot_alias_votes_or_weaken_quorum() {
        let endpoints: Vec<_> = (0..4)
            .map(|i| AuthorityEndpoint {
                identity: format!("a{i}"),
                address: format!("127.0.0.1:{}", 9000 + i),
                public_key: SigningKey::from_bytes(&[i as u8 + 1; 32])
                    .verifying_key()
                    .to_bytes(),
            })
            .collect();
        for quorum in [0, 1, 2, 5] {
            assert!(PinnedDirectoryClient::new(endpoints.clone(), quorum).is_err());
        }
        assert!(PinnedDirectoryClient::new(vec![], 1).is_err());
        assert!(PinnedDirectoryClient::new(vec![endpoints[0].clone(); 17], 12).is_err());
        for case in 0..7 {
            let mut altered = endpoints.clone();
            match case {
                0 => altered[1].identity = altered[0].identity.clone(),
                1 => altered[1].public_key = altered[0].public_key,
                2 => altered[1].address = altered[0].address.clone(),
                3 => altered[0].identity.clear(),
                4 => altered[0].address = "host\0:9001".into(),
                5 => altered[0].public_key = [0; 32],
                _ => altered[0].address.clear(),
            }
            assert!(PinnedDirectoryClient::new(altered, 3).is_err());
        }
        assert!(PinnedDirectoryClient::new(endpoints, 3).is_ok());
    }

    #[tokio::test]
    async fn valid_partial_votes_combine_despite_one_wrong_endpoint_pin() {
        let mut endpoints = Vec::new();
        let template = snapshot("1.1.1.1");
        for i in 0..4 {
            let key = SigningKey::from_bytes(&[i + 1; 32]);
            let id = format!("a{i}");
            let mut doc = template.clone();
            doc.sign_with_authority(&id, &key);
            let mut endpoint = mock(id, key, Some(serde_json::to_vec(&doc).unwrap())).await;
            if i == 3 {
                endpoint.public_key = SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes();
            }
            endpoints.push(endpoint);
        }
        let mut client = PinnedDirectoryClient::new(endpoints, 3).unwrap();
        client.rpc_timeout = Duration::from_secs(2);
        let pool = ProxyPool::new();
        assert_eq!(client.refresh(&pool).await.unwrap(), 1);
        assert!(pool.is_mesh_target("1.1.1.1", 9001).await);
    }

    #[tokio::test]
    async fn stalled_authorities_share_a_bounded_parallel_deadline() {
        let mut endpoints = Vec::new();
        for i in 0..4 {
            endpoints.push(mock(format!("a{i}"), SigningKey::from_bytes(&[i + 1; 32]), None).await);
        }
        let mut client = PinnedDirectoryClient::new(endpoints, 3).unwrap();
        client.rpc_timeout = Duration::from_secs(1);
        let started = std::time::Instant::now();
        assert!(client.refresh(&ProxyPool::new()).await.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "Peer deadlines ran serially"
        );
    }

    #[tokio::test]
    async fn conflicting_certificates_are_collected_and_rejected_before_publication() {
        let keys: Vec<_> = (1..=4).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let mut first = snapshot("1.1.1.1");
        let mut second = first.clone();
        second.relays = snapshot("2.2.2.2").relays;
        for (i, key) in keys.iter().enumerate().take(3) {
            first.sign_with_authority(&format!("a{i}"), key);
            second.sign_with_authority(&format!("a{i}"), key);
        }
        let mut endpoints = Vec::new();
        for (i, key) in keys.into_iter().enumerate() {
            let reply = if i % 2 == 0 { &first } else { &second };
            endpoints.push(
                mock(
                    format!("a{i}"),
                    key,
                    Some(serde_json::to_vec(reply).unwrap()),
                )
                .await,
            );
        }
        let client = PinnedDirectoryClient::new(endpoints, 3).unwrap();
        let pool = ProxyPool::new();
        assert!(client
            .refresh(&pool)
            .await
            .unwrap_err()
            .contains("Conflicting"));
        assert_eq!(pool.total_count().await, 0);
    }

    #[tokio::test]
    async fn malformed_and_oversized_snapshots_do_not_replace_existing_pool_state() {
        for oversized in [false, true] {
            let key = SigningKey::from_bytes(&[1; 32]);
            let bytes = if oversized {
                let mut doc = snapshot("1.1.1.1");
                doc.relays =
                    vec![doc.relays[0].clone(); crate::mesh::consensus::MAX_DIRECTORY_RELAYS + 1];
                serde_json::to_vec(&doc).unwrap()
            } else {
                b"{truncated".to_vec()
            };
            let endpoint = mock("a".into(), key, Some(bytes)).await;
            let client = PinnedDirectoryClient::new(vec![endpoint], 1).unwrap();
            let pool = ProxyPool::new();
            pool.add_proxy("socks5://127.0.0.1:9002").await.unwrap();
            assert!(client.refresh(&pool).await.is_err());
            assert_eq!(pool.total_count().await, 1);
        }
    }
}
