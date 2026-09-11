use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Handshakes with a single SOCKS5 proxy to establish a tunnel to a target (IP/Domain + Port).
/// Returns the negotiated stream.
pub async fn socks5_connect_through(
    mut stream: TcpStream,
    target_host: &str,
    target_port: u16,
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

    // 2. Connect request
    let mut req = vec![0x05, 0x01, 0x00];

    // Parse target_host as IPv4, IPv6, or Domain Name
    if let Ok(ip) = target_host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = target_host.parse::<Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03);
        let bytes = target_host.as_bytes();
        if bytes.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Domain name too long",
            ));
        }
        req.push(bytes.len() as u8);
        req.extend_from_slice(bytes);
    }

    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xFF) as u8);

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

/// Parses an incoming SOCKS5 request from a client, returning the requested target host and port.
/// Responds with a generic success to the client so the client starts sending payload data.
pub async fn intercept_socks5_request(stream: &mut TcpStream) -> std::io::Result<(String, u16)> {
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

    // 3. Respond success to client immediately (we will build the chain async)
    // We bind to 0.0.0.0:0 in the response
    let success_resp = [
        0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 0.0.0.0
        0x00, 0x00, // port 0
    ];
    stream.write_all(&success_resp).await?;

    Ok((host, port))
}
