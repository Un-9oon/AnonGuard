//! Exit Relay Policy enforcement.
//!
//! Protects volunteer exit relay operators from Server-Side Request Forgery (SSRF),
//! internal network scanning, local service exploitation, and common abuse vectors (SMTP spam).

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ExitPolicy {
    pub allow_private_networks: bool,
    pub blocked_ports: Vec<u16>,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        Self {
            allow_private_networks: false,
            // Default blocked abuse ports: SMTP spam (25), Windows RPC/NetBIOS/SMB (135, 137-139, 445)
            blocked_ports: vec![25, 135, 137, 138, 139, 445],
        }
    }
}

impl ExitPolicy {
    pub fn new(allow_private_networks: bool) -> Self {
        Self {
            allow_private_networks,
            ..Default::default()
        }
    }

    /// Validates whether an outbound destination target is permitted.
    pub fn is_permitted(&self, host: &str, port: u16) -> bool {
        // Check blocked ports
        if self.blocked_ports.contains(&port) {
            return false;
        }

        if self.allow_private_networks {
            return true;
        }

        let lower = host.trim().to_lowercase();

        // Block localhost and internal metadata hostnames
        if lower == "localhost"
            || lower.ends_with(".localhost")
            || lower.ends_with(".local")
            || lower.ends_with(".internal")
            || lower == "metadata.google.internal"
            || lower == "instance-data"
        {
            return false;
        }

        // Validate IP literals
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.is_ip_permitted(ip);
        }

        true
    }

    /// Resolves DNS and securely connects to the destination target.
    /// Eliminates DNS rebinding SSRF attacks by verifying all resolved IP addresses
    /// against the ExitPolicy blocklist before connecting directly to the validated IP.
    pub async fn resolve_and_connect(
        &self,
        host: &str,
        port: u16,
    ) -> Result<tokio::net::TcpStream, std::io::Error> {
        if !self.is_permitted(host, port) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Exit relay policy blocked connection to restricted target {}:{} (anti-SSRF)",
                    host, port
                ),
            ));
        }

        let addrs = tokio::net::lookup_host((host, port)).await?;
        let mut target_addr = None;

        for addr in addrs {
            if !self.is_ip_permitted(addr.ip()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Exit relay policy blocked resolved IP {} for target {} (anti-SSRF / anti-DNS rebinding)",
                        addr.ip(),
                        host
                    ),
                ));
            }
            if target_addr.is_none() {
                target_addr = Some(addr);
            }
        }

        let addr = target_addr.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No IP address resolved for target {}:{}", host, port),
            )
        })?;

        tokio::net::TcpStream::connect(addr).await
    }

    /// Validates if an IP address belongs to allowed public internet space.
    pub fn is_ip_permitted(&self, ip: IpAddr) -> bool {
        if self.allow_private_networks {
            return true;
        }

        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();

                // Loopback (127.0.0.0/8)
                if ipv4.is_loopback() || octets[0] == 127 {
                    return false;
                }

                // Unspecified (0.0.0.0/8)
                if ipv4.is_unspecified() || octets[0] == 0 {
                    return false;
                }

                // Cloud Metadata (169.254.169.254) & Link-Local (169.254.0.0/16)
                if ipv4.is_link_local() || (octets[0] == 169 && octets[1] == 254) {
                    return false;
                }

                // RFC 1918 Private networks:
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return false;
                }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return false;
                }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return false;
                }

                // Multicast (224.0.0.0/4)
                if ipv4.is_multicast() || (octets[0] >= 224 && octets[0] <= 239) {
                    return false;
                }

                // Broadcast (255.255.255.255)
                if ipv4.is_broadcast()
                    || (octets[0] == 255
                        && octets[1] == 255
                        && octets[2] == 255
                        && octets[3] == 255)
                {
                    return false;
                }

                // Carrier-grade NAT (100.64.0.0/10)
                if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                    return false;
                }

                // Documentation / Testing networks (RFC 5737)
                if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                    return false;
                }
                if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                    return false;
                }
                if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                    return false;
                }

                true
            }
            IpAddr::V6(ipv6) => {
                // Loopback (::1)
                if ipv6.is_loopback() {
                    return false;
                }
                // Unspecified (::)
                if ipv6.is_unspecified() {
                    return false;
                }
                // Multicast (ff00::/8)
                if ipv6.is_multicast() {
                    return false;
                }
                // Link-local (fe80::/10)
                let segments = ipv6.segments();
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return false;
                }
                // Unique local / ULA (fc00::/7)
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return false;
                }
                // IPv4-mapped IPv6 (::ffff:x.x.x.x)
                if let Some(v4) = ipv6.to_ipv4_mapped() {
                    return self.is_ip_permitted(IpAddr::V4(v4));
                }

                true
            }
        }
    }
}

/// Global helper evaluating the default secure exit policy.
pub fn is_exit_target_permitted(host: &str, port: u16) -> bool {
    ExitPolicy::default().is_permitted(host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_policy_ssrf_rejection() {
        let policy = ExitPolicy::default();

        // Loopback & Localhost
        assert!(!policy.is_permitted("127.0.0.1", 80));
        assert!(!policy.is_permitted("127.0.0.2", 443));
        assert!(!policy.is_permitted("localhost", 8080));
        assert!(!policy.is_permitted("app.localhost", 80));
        assert!(!policy.is_permitted("service.local", 80));
        assert!(!policy.is_permitted("::1", 80));

        // Cloud Metadata
        assert!(!policy.is_permitted("169.254.169.254", 80));
        assert!(!policy.is_permitted("metadata.google.internal", 80));
        assert!(!policy.is_permitted("169.254.1.1", 80));

        // Private LAN (RFC 1918)
        assert!(!policy.is_permitted("10.0.0.1", 80));
        assert!(!policy.is_permitted("10.254.254.254", 80));
        assert!(!policy.is_permitted("172.16.0.1", 80));
        assert!(!policy.is_permitted("172.31.255.255", 80));
        assert!(!policy.is_permitted("192.168.1.1", 80));
        assert!(!policy.is_permitted("192.168.0.254", 80));

        // Blocked Ports (SMTP 25, SMB 445)
        assert!(!policy.is_permitted("8.8.8.8", 25));
        assert!(!policy.is_permitted("1.1.1.1", 445));

        // Permitted Public Targets
        assert!(policy.is_permitted("8.8.8.8", 53));
        assert!(policy.is_permitted("1.1.1.1", 443));
        assert!(policy.is_permitted("142.250.190.46", 443)); // google.com
        assert!(policy.is_permitted("example.com", 80));
        assert!(policy.is_permitted("wikipedia.org", 443));
    }

    #[tokio::test]
    async fn test_exit_policy_resolve_and_connect_rebinding() {
        let policy = ExitPolicy::default();

        // 1. Literal loopback connection attempt must fail with PermissionDenied
        let res = policy.resolve_and_connect("127.0.0.1", 80).await;
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );

        // 2. Localhost resolution attempt must fail with PermissionDenied
        let res2 = policy.resolve_and_connect("localhost", 80).await;
        assert!(res2.is_err());
        assert_eq!(
            res2.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );

        // 3. Permitted private network mode succeeds when enabled
        let private_policy = ExitPolicy::new(true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let conn = private_policy.resolve_and_connect("127.0.0.1", port).await;
        assert!(conn.is_ok());
    }
}
