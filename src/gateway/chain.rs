use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::kernel::dns::{build_socks5h_connect_frame, TargetAddress};

/// Handshakes with a single SOCKS5 proxy to establish a tunnel to a target (IP/Domain + Port).
/// Guarantees that remote DNS and IPv6 blocking policies from kernel/dns.rs are enforced.
pub async fn socks5_connect_through(
    mut stream: TcpStream,
    target_host: &str,
    target_port: u16,
    block_ipv6: bool,
) -> std::io::Result<TcpStream> {
    // 1. Initial auth negotiation (No Auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await?;
    if auth_resp[0] != 0x05 || auth_resp[1] == 0xFF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 proxy rejected no-auth",
        ));
    }

    // 2. Build SOCKS5h request frame through unified kernel DNS engine
    let target = if let Ok(ip) = target_host.parse::<Ipv4Addr>() {
        TargetAddress::IPv4(ip.octets())
    } else if let Ok(ip) = target_host.parse::<Ipv6Addr>() {
        TargetAddress::IPv6(ip.octets())
    } else {
        TargetAddress::Domain(target_host.to_string())
    };

    let req = build_socks5h_connect_frame(&target, target_port, block_ipv6)?;
    stream.write_all(&req).await?;

    // 3. Read response
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;

    if resp_header[0] != 0x05 || resp_header[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "SOCKS5 connection failed with reply code: {}",
                resp_header[1]
            ),
        ));
    }

    // Skip the bound address in the response
    let atyp = resp_header[3];
    match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4 + 2];
            stream.read_exact(&mut addr).await?;
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16 + 2];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            // Domain
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut addr = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut addr).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unknown ATYP in SOCKS5 response",
            ));
        }
    }

    Ok(stream)
}

/// Reads and parses an incoming SOCKS5 handshake from a client, returning the requested target host and port.
/// Does NOT send the CONNECT reply so the server can verify upstream circuit connectivity first.
pub async fn read_socks5_request<S>(stream: &mut S) -> std::io::Result<(String, u16)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
{
    // 1. Initial auth negotiation
    let mut auth_req = [0u8; 2];
    stream.read_exact(&mut auth_req).await?;
    if auth_req[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Not SOCKS5",
        ));
    }

    let num_methods = auth_req[1] as usize;
    let mut methods = vec![0u8; num_methods];
    stream.read_exact(&mut methods).await?;

    // Reply NO AUTH REQUIRED
    stream.write_all(&[0x05, 0x00]).await?;

    // 2. Connect request
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header).await?;

    if req_header[0] != 0x05 || req_header[1] != 0x01 {
        // Only support CONNECT
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Only CONNECT supported",
        ));
    }

    let host;
    let atyp = req_header[3];
    match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            host = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string();
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            host = Ipv6Addr::from(addr).to_string();
        }
        0x03 => {
            // Domain
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut domain = vec![0u8; len_buf[0] as usize];
            stream.read_exact(&mut domain).await?;
            host = String::from_utf8_lossy(&domain).to_string();
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unknown ATYP",
            ))
        }
    }

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = ((port_buf[0] as u16) << 8) | (port_buf[1] as u16);

    Ok((host, port))
}

/// Sends a SOCKS5 CONNECT reply to the client with the specified status code (RFC 1928).
/// Common codes:
/// - 0x00: Success
/// - 0x01: General SOCKS server failure
/// - 0x02: Connection not allowed by ruleset (e.g. exit policy block / SSRF)
/// - 0x03: Network unreachable
/// - 0x04: Host unreachable
/// - 0x05: Connection refused
pub async fn send_socks5_reply<S>(stream: &mut S, rep: u8) -> std::io::Result<()>
where
    S: AsyncWriteExt + Unpin + ?Sized,
{
    let resp = [
        0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // Bound addr: 0.0.0.0
        0x00, 0x00, // Bound port: 0
    ];
    stream.write_all(&resp).await
}

/// Parses an incoming SOCKS5 request from a client, returning the requested target host and port.
/// Responds with a generic success (0x00) immediately for convenience.
pub async fn intercept_socks5_request<S>(stream: &mut S) -> std::io::Result<(String, u16)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
{
    let target = read_socks5_request(stream).await?;
    send_socks5_reply(stream, 0x00).await?;
    Ok(target)
}
