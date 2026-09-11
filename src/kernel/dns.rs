//! SOCKS5h remote domain name resolution (RFC 1928 Address Type 0x03).

use std::io::{Error, ErrorKind, Result};

pub const ADDR_TYPE_IPV4: u8 = 0x01;
pub const ADDR_TYPE_DOMAIN: u8 = 0x03;
pub const ADDR_TYPE_IPV6: u8 = 0x04;

pub const CMD_CONNECT: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddress {
    IPv4([u8; 4]),
    Domain(String),
    IPv6([u8; 16]),
}

/// Serializes target host and port into a strict SOCKS5h request frame.
/// Guarantees that domains are formatted as FQDNs (AddrType 0x03) so resolution happens on the proxy.
pub fn build_socks5h_connect_frame(target: &TargetAddress, port: u16, block_ipv6: bool) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(32);
    frame.push(0x05); // SOCKS version 5
    frame.push(CMD_CONNECT); // Command 0x01 (CONNECT)
    frame.push(0x00); // Reserved byte

    match target {
        TargetAddress::Domain(domain) => {
            if domain.len() > 255 {
                return Err(Error::new(ErrorKind::InvalidInput, "Domain name exceeds 255 bytes"));
            }
            frame.push(ADDR_TYPE_DOMAIN);
            frame.push(domain.len() as u8);
            frame.extend_from_slice(domain.as_bytes());
        }
        TargetAddress::IPv4(ip) => {
            frame.push(ADDR_TYPE_IPV4);
            frame.extend_from_slice(ip);
        }
        TargetAddress::IPv6(ip) => {
            if block_ipv6 {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "IPv6 target blocked by AnonGuard policy to prevent dual-stack leak",
                ));
            }
            frame.push(ADDR_TYPE_IPV6);
            frame.extend_from_slice(ip);
        }
    }

    // Append big-endian port
    frame.extend_from_slice(&port.to_be_bytes());
    Ok(frame)
}
