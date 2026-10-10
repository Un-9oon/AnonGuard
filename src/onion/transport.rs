//! SOCKS5 client for an independently supervised pluggable transport.
//! This returns a byte stream; callers must still authenticate the AnonGuard link.

use std::{collections::BTreeMap, io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Locally provisioned entry transport binding. This is never a directory record.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTransport {
    pub identity: [u8; 32],
    pub proxy: SocketAddr,
    pub bridge: SocketAddr,
    pub arguments: BTreeMap<String, String>,
}

// Do not expose bridge certificates or addresses through GuardConfig debug logs.
impl std::fmt::Debug for BridgeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeTransport { provisioned: true }")
    }
}

pub fn load_bridges(path: &std::path::Path) -> io::Result<Vec<BridgeTransport>> {
    load_bindings(path, 3)
}

/// Same wire contract for individually pinned authority bootstrap transports.
pub fn load_authorities(path: &std::path::Path) -> io::Result<Vec<BridgeTransport>> {
    load_bindings(path, 16)
}

fn load_bindings(path: &std::path::Path, maximum: usize) -> io::Result<Vec<BridgeTransport>> {
    let bytes = crate::core::storage::read_bounded_file(path, 65536)?;
    let bridges: Vec<BridgeTransport> =
        serde_json::from_slice(&bytes).map_err(|_| invalid("Invalid bridge configuration JSON"))?;
    if bridges.is_empty() || bridges.len() > maximum {
        return Err(invalid("Invalid number of transport bindings"));
    }
    let mut identities = std::collections::HashSet::new();
    let mut endpoints = std::collections::HashSet::new();
    for entry in &bridges {
        if crate::crypto::identity::VerifyingKey::from_bytes(&entry.identity)
            .map_or(true, |key| key.is_weak())
            || !identities.insert(entry.identity)
            || !endpoints.insert(entry.bridge)
            || !entry.proxy.ip().is_loopback()
            || entry.proxy.port() == 0
            || entry.bridge.port() == 0
            || entry.bridge.ip().is_unspecified()
            || entry.bridge.ip().is_multicast()
        {
            return Err(invalid("Invalid or duplicate bridge transport binding"));
        }
        encode_arguments(&entry.arguments)?;
    }
    Ok(bridges)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Encode PT v1 per-connection arguments, escaping delimiters before joining.
/// The conservative 254-byte limit avoids ambiguous multi-field splitting.
pub fn encode_arguments(arguments: &BTreeMap<String, String>) -> io::Result<Vec<u8>> {
    if arguments.is_empty() {
        return Err(invalid("Transport arguments are required"));
    }
    let escape = |value: &str| -> String {
        let mut result = String::new();
        for c in value.chars() {
            if matches!(c, '\\' | '=' | ';') {
                result.push('\\');
            }
            result.push(c);
        }
        result
    };
    let mut encoded = Vec::new();
    for (key, value) in arguments {
        if key.is_empty() || key.chars().chain(value.chars()).any(char::is_control) {
            return Err(invalid("Invalid transport argument"));
        }
        if !encoded.is_empty() {
            encoded.push(b';');
        }
        encoded.extend_from_slice(escape(key).as_bytes());
        encoded.push(b'=');
        encoded.extend_from_slice(escape(value).as_bytes());
        if encoded.len() > 254 {
            return Err(invalid("Transport arguments exceed 254 bytes"));
        }
    }
    Ok(encoded)
}

/// Connect only through a numeric loopback PT endpoint, with a bounded handshake.
/// There is deliberately no direct connection or local DNS fallback.
pub async fn connect(
    proxy: SocketAddr,
    bridge: SocketAddr,
    arguments: &BTreeMap<String, String>,
) -> io::Result<TcpStream> {
    if !proxy.ip().is_loopback()
        || proxy.port() == 0
        || bridge.port() == 0
        || bridge.ip().is_unspecified()
        || bridge.ip().is_multicast()
    {
        return Err(invalid("Invalid transport or bridge endpoint"));
    }
    let arguments = encode_arguments(arguments)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(proxy).await?;
        // Offer only RFC1929: accepting no-auth would discard PT arguments.
        stream.write_all(&[5, 1, 2]).await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        if response != [5, 2] {
            return Err(invalid("Transport refused argument authentication"));
        }
        let mut auth = vec![1, arguments.len() as u8];
        auth.extend_from_slice(&arguments);
        auth.extend_from_slice(&[1, 0]);
        stream.write_all(&auth).await?;
        stream.read_exact(&mut response).await?;
        if response != [1, 0] {
            return Err(invalid("Transport rejected arguments"));
        }
        let mut request = vec![5, 1, 0];
        match bridge.ip() {
            std::net::IpAddr::V4(ip) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
        }
        request.extend_from_slice(&bridge.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        if header[..3] != [5, 0, 0] {
            return Err(invalid("Transport connection rejected"));
        }
        let length = match header[3] {
            1 => 4,
            4 => 16,
            3 => {
                let length = stream.read_u8().await? as usize;
                if length == 0 {
                    return Err(invalid("Empty transport bound address"));
                }
                length
            }
            _ => return Err(invalid("Invalid transport address type")),
        };
        let mut bound = vec![0; length + 2];
        stream.read_exact(&mut bound).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Transport handshake timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn args() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("cert".into(), "fixture".into()),
            ("iat-mode".into(), "0".into()),
        ])
    }

    #[test]
    fn arguments_are_escaped_and_bounded() {
        let values = BTreeMap::from([("a".into(), "b;c=d\\e".into())]);
        assert_eq!(encode_arguments(&values).unwrap(), b"a=b\\;c\\=d\\\\e");
        assert!(encode_arguments(&BTreeMap::new()).is_err());
        assert!(encode_arguments(&BTreeMap::from([("a".into(), "x".repeat(253))])).is_err());
        assert!(encode_arguments(&BTreeMap::from([("a".into(), "x\n".into())])).is_err());
    }

    #[test]
    fn transport_file_rejects_weak_pins_endpoint_aliases_and_oversized_input() {
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "anonguard-pt-config-{:032x}",
            rand::random::<u128>()
        )));
        let binding = BridgeTransport {
            identity: crate::crypto::identity::SigningKey::from_bytes(&[51; 32])
                .verifying_key()
                .to_bytes(),
            proxy: "127.0.0.1:1080".parse().unwrap(),
            bridge: "192.0.2.1:443".parse().unwrap(),
            arguments: args(),
        };
        std::fs::write(
            &fixture.0,
            serde_json::to_vec(&vec![binding.clone()]).unwrap(),
        )
        .unwrap();
        assert_eq!(load_bridges(&fixture.0).unwrap().len(), 1);
        let mut alias = binding.clone();
        alias.identity = crate::crypto::identity::SigningKey::from_bytes(&[52; 32])
            .verifying_key()
            .to_bytes();
        std::fs::write(
            &fixture.0,
            serde_json::to_vec(&vec![binding.clone(), alias]).unwrap(),
        )
        .unwrap();
        assert!(load_bridges(&fixture.0).is_err());
        let mut weak = binding.clone();
        weak.identity = [0; 32];
        std::fs::write(&fixture.0, serde_json::to_vec(&vec![weak]).unwrap()).unwrap();
        assert!(load_bridges(&fixture.0).is_err());
        let mut value = serde_json::to_value(&binding).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("fallback".into(), serde_json::json!("direct"));
        std::fs::write(&fixture.0, serde_json::to_vec(&vec![value]).unwrap()).unwrap();
        assert!(load_bridges(&fixture.0).is_err());
        std::fs::write(&fixture.0, vec![b' '; 65537]).unwrap();
        assert!(load_bridges(&fixture.0).is_err());
    }

    #[tokio::test]
    async fn authenticates_arguments_and_preserves_payload() {
        for bridge in ["192.0.2.1:443", "[2001:db8::1]:443"] {
            let bridge: SocketAddr = bridge.parse().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 2]);
                peer.write_all(&[5, 2]).await.unwrap();
                assert_eq!(peer.read_u8().await.unwrap(), 1);
                let len = peer.read_u8().await.unwrap() as usize;
                let mut user = vec![0; len];
                peer.read_exact(&mut user).await.unwrap();
                assert_eq!(user, b"cert=fixture;iat-mode=0");
                assert_eq!(peer.read_u8().await.unwrap(), 1);
                assert_eq!(peer.read_u8().await.unwrap(), 0);
                peer.write_all(&[1, 0]).await.unwrap();
                let mut request = vec![0; if bridge.is_ipv4() { 10 } else { 22 }];
                peer.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..3], &[5, 1, 0]);
                assert_eq!(&request[request.len() - 2..], &443u16.to_be_bytes());
                peer.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 42])
                    .await
                    .unwrap();
            });
            let mut stream = connect(address, bridge, &args()).await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), 42);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_no_auth_downgrade_without_contacting_bridge() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = proxy.accept().await.unwrap();
            let mut request = [0; 3];
            peer.read_exact(&mut request).await.unwrap();
            peer.write_all(&[5, 0]).await.unwrap();
        });
        assert!(connect(address, target.local_addr().unwrap(), &args())
            .await
            .is_err());
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), target.accept())
                .await
                .is_err()
        );
        assert!(connect(
            "192.0.2.1:1080".parse().unwrap(),
            target.local_addr().unwrap(),
            &args()
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn rejects_failed_malformed_and_truncated_connect_replies() {
        for reply in [
            vec![5, 1, 0, 1],
            vec![4, 0, 0, 1],
            vec![5, 0, 1, 1],
            vec![5, 0, 0, 9],
            vec![5, 0, 0, 3, 0],
            vec![5, 0, 0, 1, 0],
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                peer.write_all(&[5, 2]).await.unwrap();
                assert_eq!(peer.read_u8().await.unwrap(), 1);
                let length = peer.read_u8().await.unwrap() as usize;
                let mut rest = vec![0; length + 2];
                peer.read_exact(&mut rest).await.unwrap();
                peer.write_all(&[1, 0]).await.unwrap();
                let mut request = [0; 10];
                peer.read_exact(&mut request).await.unwrap();
                peer.write_all(&reply).await.unwrap();
            });
            assert!(connect(address, "192.0.2.1:443".parse().unwrap(), &args())
                .await
                .is_err());
            server.await.unwrap();
        }
    }
}
