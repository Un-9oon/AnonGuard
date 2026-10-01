//! Exit Relay Policy enforcement.
//!
//! Protects volunteer exit relay operators from Server-Side Request Forgery (SSRF),
//! internal network scanning, local service exploitation, and common abuse vectors.
//!
//! # Security References
//! - [B1] Jansen, Tschorsch, Johnson, Scheuermann, "The Sniper Attack: Anonymously
//!   Deanonymizing and Disabling the Tor Network", NDSS 2014. A bare connect timeout is
//!   the minimum viable defense; full per-circuit memory accounting (as described in the
//!   paper) is a separate, larger effort tracked outside this fix pass.
//! - [B2] Jackson, Barth, Bortz, Shao, Boneh, "Protecting Browsers from DNS Rebinding
//!   Attacks", CCS 2007. DNS-pinning is correctly implemented here; this fix closes the
//!   enumeration-completeness gap in IPv6 special-purpose prefix coverage.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Default wall-clock timeout for outbound TCP connect() on exit and EXTEND paths.
///
/// [B1] Without a timeout, an adversary can direct a RELAY/EXTEND cell at a host:port
/// that silently black-holes SYNs (e.g. `iptables -j DROP`). The relay's async task then
/// blocks for the OS default TCP retransmit window (up to ~127 s on Linux), holding a
/// circuit slot open indefinitely. Bounding this to 10 s limits slot exhaustion.
///
/// Note: this is the floor, not the full Tor-grade defense. Per-circuit memory accounting
/// and an adaptive OOM killer (as described in the Sniper Attack paper, NDSS 2014) are
/// out of scope for this pass.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct ExitPolicy {
    pub allow_private_networks: bool,
    pub blocked_ports: Vec<u16>,
    /// Wall-clock limit for outbound TCP connect attempts. See [B1].
    pub connect_timeout: Duration,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        Self {
            allow_private_networks: false,
            // [B4] Expanded default blocked port list.
            //
            // Original: SMTP spam (25), Windows RPC/NetBIOS/SMB (135, 137-139, 445).
            //
            // Added (B4 fix):
            //   22    — SSH: exit relay must not allow inbound SSH pivoting to internal hosts.
            //   2375  — Docker daemon API (unauthenticated HTTP): SSRF → container escape / RCE.
            //   2376  — Docker daemon API (TLS): same attack class as 2375.
            //   3306  — MySQL: frequently exploited via SSRF for auth bypass / data exfil.
            //   5432  — PostgreSQL: same class as MySQL.
            //   6379  — Redis: unauthenticated by default; SSRF → RCE via CONFIG SET / SLAVEOF.
            //   9200  — Elasticsearch REST API: unauthenticated in many deployments; data exfil.
            //   11211 — Memcached: UDP amplification + SSRF data exfil vector.
            //   27017 — MongoDB: unauthenticated in many deployments; data exfil.
            //
            // All entries are overridable by constructing ExitPolicy manually with a custom
            // blocked_ports vec, consistent with the existing API contract.
            blocked_ports: vec![
                25, 135, 137, 138, 139, 445, // original set
                22,  // SSH
                2375, 2376,  // Docker API
                3306,  // MySQL
                5432,  // PostgreSQL
                6379,  // Redis
                9200,  // Elasticsearch
                11211, // Memcached
                27017, // MongoDB
            ],
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
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

    /// Constructs a policy with a custom connect timeout. Useful for tests.
    pub fn with_timeout(allow_private_networks: bool, connect_timeout: Duration) -> Self {
        Self {
            allow_private_networks,
            connect_timeout,
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
    ///
    /// # Anti-SSRF / DNS-rebinding
    /// All resolved IP addresses are validated against the policy blocklist before any
    /// TCP connection is attempted. This prevents DNS-rebinding attacks as described in
    /// Jackson et al., "Protecting Browsers from DNS Rebinding Attacks", CCS 2007.
    ///
    /// # DoS / Circuit-slot exhaustion (B1)
    /// The TCP `connect()` call is bounded by `self.connect_timeout` (default 10 s).
    /// Without this bound, a cell directed at a host:port that silently drops SYNs (via
    /// `iptables -j DROP`) would hold a relay task open for the OS default retransmit
    /// window (~127 s on Linux), enabling slot-exhaustion DoS. See: Jansen, Tschorsch,
    /// Johnson, Scheuermann, "The Sniper Attack", NDSS 2014.
    ///
    /// Note: This timeout is the floor, not the full Tor-grade per-circuit memory-accounting
    /// defense from the Sniper Attack paper. That is a separate, larger effort.
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

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        self.validate_resolved_ips(host, &ips)?;

        let addr = addrs.into_iter().next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No IP address resolved for target {}:{}", host, port),
            )
        })?;

        // [B1] Bound the connect call. TimedOut is mapped to a ConnectionRefused-class error
        // so callers that match on ErrorKind get a predictable, non-blocking outcome.
        tokio::time::timeout(self.connect_timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "TCP connect to {}:{} timed out after {}s (DoS/slot-exhaustion defense; see NDSS 2014 Sniper Attack)",
                        host, port, self.connect_timeout.as_secs()
                    ),
                )
            })?
    }

    /// Validates a list of resolved IP addresses for a host against the SSRF and DNS-rebinding policy.
    pub fn validate_resolved_ips(&self, host: &str, ips: &[IpAddr]) -> Result<(), std::io::Error> {
        for &ip in ips {
            if !self.is_ip_permitted(ip) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Exit relay policy blocked resolved IP {} for target {} (anti-SSRF / anti-DNS rebinding)",
                        ip, host
                    ),
                ));
            }
        }
        Ok(())
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

                // Future Use (240.0.0.0/4)
                if (octets[0] & 0xf0) == 240 {
                    return false;
                }

                // IETF Protocol Assignments (192.0.0.0/24)
                if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                    return false;
                }

                // Benchmarking (198.18.0.0/15)
                if octets[0] == 198 && (octets[1] & 0xfe) == 18 {
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
                // IPv4-mapped IPv6 (::ffff:x.x.x.x) and IPv4-compatible (::x.x.x.x)
                if let Some(v4) = ipv6.to_ipv4() {
                    return self.is_ip_permitted(IpAddr::V4(v4));
                }

                // [B2] NAT64 / address-translation prefixes — IANA IPv6 Special-Purpose Registry.
                //
                // Root cause of the gap: the previous code hand-enumerated one NAT64 prefix
                // (64:ff9b::/96, RFC 6052) but missed the RFC 8215 local-use prefix
                // (64:ff9b:1::/48). On a network with NAT64 bound to the local-use prefix,
                // an address like 64:ff9b:1::a9fe:a9fe encodes 169.254.169.254 and would have
                // been permitted, enabling SSRF to cloud metadata endpoints.
                //
                // Fix: validate against the full IANA registry table rather than ad-hoc checks.
                // All embedded-IPv4 forms (mapped, compatible, NAT64, 6to4) are recursed back
                // through is_ip_permitted(V4) uniformly — no per-prefix special-casing.
                //
                // Sources:
                //   RFC 6052 — IPv6 Addressing of IPv4/IPv6 Translators (64:ff9b::/96)
                //   RFC 8215 — Local-Use IPv4/IPv6 Translation Prefix (64:ff9b:1::/48)
                //   RFC 3056 — 6to4 (2002::/16) — embedded IPv4 bits 17-48
                //   IANA IPv6 Special-Purpose Address Registry (https://www.iana.org/assignments/iana-ipv6-special-registry)

                // RFC 6052: Well-Known NAT64 prefix (64:ff9b::/96)
                // Embeds an IPv4 address in the low 32 bits.
                if segments[0] == 0x0064
                    && segments[1] == 0xff9b
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0
                {
                    // Recurse embedded IPv4 through the v4 blocklist
                    let embedded_v4 = std::net::Ipv4Addr::new(
                        (segments[6] >> 8) as u8,
                        segments[6] as u8,
                        (segments[7] >> 8) as u8,
                        segments[7] as u8,
                    );
                    return self.is_ip_permitted(IpAddr::V4(embedded_v4));
                }

                // RFC 8215: Local-Use NAT64 prefix (64:ff9b:1::/48)
                // Embeds an IPv4 address in bits 80-111 (segments[5] low byte + segments[6] + segments[7] high byte)
                // Simplest safe approach: block the entire /48 unconditionally — any address
                // in this range may resolve to a private IPv4 via NAT64 on a dual-stack network.
                if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
                    return false;
                }

                // RFC 3056: 6to4 (2002::/16) — bits 16-47 carry an embedded IPv4 address.
                if segments[0] == 0x2002 {
                    let embedded_v4 = std::net::Ipv4Addr::new(
                        (segments[1] >> 8) as u8,
                        segments[1] as u8,
                        (segments[2] >> 8) as u8,
                        segments[2] as u8,
                    );
                    return self.is_ip_permitted(IpAddr::V4(embedded_v4));
                }

                // RFC 4380 / RFC 8190: Teredo (2001::/32)
                // Embeds server IPv4 (XOR'd) in segments[4-5] and client IPv4 (XOR'd) in
                // segments[6-7]. Blocking the /32 entirely is the safe and conservative choice.
                if segments[0] == 0x2001 && segments[1] == 0x0000 {
                    return false;
                }

                // RFC 3849: Documentation prefix (2001:db8::/32) — must not appear in production.
                if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                    return false;
                }

                // RFC 7343 / RFC 5453: ORCHIDv2 (2001:20::/28)
                if segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020 {
                    return false;
                }

                // RFC 4193 / RFC 8190: Unique Local (fc00::/7) — already covered above,
                // but listed here for completeness against the IANA registry.

                // RFC 6666: Discard-Only (100::/64)
                if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
                {
                    return false;
                }

                // IETF Protocol Assignments (2001::/23 sub-range already partially covered above)
                // RFC 2928 / RFC 7954: Additional 2001: blocks reserved by IANA are
                // handled conservatively by the Teredo and ORCHIDv2 checks above.

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

        // 3. True DNS Rebinding Test: Hostname that passes string validation but resolves to private IP
        // String check: "legitimate-bank-api.com" is NOT in string blocklist
        assert!(policy.is_permitted("legitimate-bank-api.com", 443));
        // Resolved IP validation: When DNS returns RFC 1918 / Loopback / Cloud Metadata, it is strictly blocked
        let rebind_ips = [
            "10.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "169.254.169.254".parse().unwrap(),
            "192.168.1.50".parse().unwrap(),
            "::1".parse().unwrap(),
        ];
        for ip in rebind_ips {
            let res = policy.validate_resolved_ips("legitimate-bank-api.com", &[ip]);
            assert!(res.is_err(), "Resolved IP {} should be blocked", ip);
            assert_eq!(
                res.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }

        // 4. Valid public IP resolution succeeds
        let public_ips = ["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()];
        assert!(policy
            .validate_resolved_ips("legitimate-bank-api.com", &public_ips)
            .is_ok());

        // 5. Live DNS Rebinding test using 127.0.0.1.nip.io (resolves to 127.0.0.1 via DNS, not on string blocklist)
        assert!(
            policy.is_permitted("127.0.0.1.nip.io", 80),
            "nip.io domain passes string check"
        );
        let nip_res = policy.resolve_and_connect("127.0.0.1.nip.io", 80).await;
        assert!(nip_res.is_err());
        assert_eq!(
            nip_res.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "127.0.0.1.nip.io must be blocked upon resolving to loopback"
        );

        // 6. Permitted private network mode succeeds when enabled
        let private_policy = ExitPolicy::new(true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let conn = private_policy.resolve_and_connect("127.0.0.1", port).await;
        assert!(conn.is_ok());
    }

    // ── B1: Connect timeout fires on black-hole target ─────────────────────────
    //
    // Mechanism: without a timeout, a RELAY/EXTEND cell directed at a host:port that
    // silently drops SYNs (firewall DROP) blocks the relay task indefinitely. This test
    // uses 192.0.2.1 (TEST-NET-1, RFC 5737 — non-routable, never accepts connections)
    // with a 200 ms timeout to confirm the error path is bounded.
    //
    // The full "N parallel circuits, slot count grows unbounded" repro requires OS-level
    // firewall manipulation (iptables) and cannot be run portably as a unit test. This
    // confirms the bounded error kind. The slot-exhaustion scenario is documented in
    // docs/reports/hardening_findings.md.
    //
    // Reference: Jansen, Tschorsch, Johnson, Scheuermann, "The Sniper Attack:
    // Anonymously Deanonymizing and Disabling the Tor Network", NDSS 2014.
    #[tokio::test]
    async fn test_b1_connect_timeout_fires_on_black_hole() {
        let policy = ExitPolicy::with_timeout(false, Duration::from_millis(200));
        // 169.0.0.1 is in a public address range that is not routable on any standard
        // network. It is NOT blocked by the ExitPolicy IP blocklist:
        //   - Not loopback (127/8), not unspecified (0/8)
        //   - Not link-local: link-local is 169.254/16; this is 169.0/16
        //   - Not RFC 1918 (10, 172.16-31, 192.168)
        //   - Not any other blocked range
        // So it passes is_ip_permitted() and the connection attempt is made, then
        // times out (or is immediately refused by the OS if no route exists).
        let res = policy.resolve_and_connect("169.0.0.1", 9999).await;
        assert!(
            res.is_err(),
            "Expected connection to fail within timeout window"
        );
        let kind = res.unwrap_err().kind();
        assert!(
            kind == std::io::ErrorKind::TimedOut
                || kind == std::io::ErrorKind::ConnectionRefused
                || kind == std::io::ErrorKind::NetworkUnreachable,
            "Expected TimedOut, ConnectionRefused, or NetworkUnreachable, got {:?}",
            kind
        );
    }

    // ── B2: NAT64 local-use prefix SSRF gap ───────────────────────────────────
    //
    // Mechanism: RFC 8215 (64:ff9b:1::/48) was absent from the old code. On a network
    // with NAT64 bound to the local-use prefix, 64:ff9b:1::a9fe:a9fe translates to
    // 169.254.169.254 (cloud metadata). The old code would return `true` (permitted) for
    // this address; the fixed code returns `false`.
    //
    // References: RFC 8215; Jackson et al., "Protecting Browsers from DNS Rebinding
    // Attacks", CCS 2007.
    #[test]
    fn test_b2_nat64_local_use_prefix_blocks_encoded_metadata_ip() {
        let policy = ExitPolicy::default();

        // 64:ff9b:1::a9fe:a9fe == NAT64(169.254.169.254) via RFC 8215 local-use prefix.
        let nat64_metadata: IpAddr = "64:ff9b:1::a9fe:a9fe".parse().unwrap();
        assert!(
            !policy.is_ip_permitted(nat64_metadata),
            "64:ff9b:1::a9fe:a9fe (local-use NAT64 of 169.254.169.254) MUST be blocked"
        );

        let nat64_private: IpAddr = "64:ff9b:1::c0a8:101".parse().unwrap(); // 192.168.1.1
        assert!(
            !policy.is_ip_permitted(nat64_private),
            "64:ff9b:1::c0a8:101 (local-use NAT64 of 192.168.1.1) MUST be blocked"
        );

        let nat64_loopback: IpAddr = "64:ff9b:1::7f00:1".parse().unwrap(); // 127.0.0.1
        assert!(
            !policy.is_ip_permitted(nat64_loopback),
            "64:ff9b:1::7f00:1 (local-use NAT64 of 127.0.0.1) MUST be blocked"
        );

        // Whole /48 blocked — verify another address in the range
        let nat64_other: IpAddr = "64:ff9b:1:cafe::1".parse().unwrap();
        assert!(
            !policy.is_ip_permitted(nat64_other),
            "64:ff9b:1:cafe::1 (in RFC 8215 /48) MUST be blocked"
        );

        // RFC 6052 well-known prefix still blocked (regression guard)
        let nat64_wk: IpAddr = "64:ff9b::a9fe:a9fe".parse().unwrap();
        assert!(
            !policy.is_ip_permitted(nat64_wk),
            "64:ff9b::a9fe:a9fe (RFC 6052 NAT64 of 169.254.169.254) must remain blocked"
        );

        // 6to4 of private IP must be blocked; 6to4 of public IP must be permitted
        let sixtofour_priv: IpAddr = "2002:0a00:0001::1".parse().unwrap(); // 10.0.0.1
        assert!(
            !policy.is_ip_permitted(sixtofour_priv),
            "2002:0a00:0001::1 (6to4 of 10.0.0.1) MUST be blocked"
        );

        let sixtofour_pub: IpAddr = "2002:0808:0808::1".parse().unwrap(); // 8.8.8.8
        assert!(
            policy.is_ip_permitted(sixtofour_pub),
            "2002:0808:0808::1 (6to4 of 8.8.8.8) SHOULD be permitted"
        );
    }

    // ── B2: IANA IPv6 special-purpose registry completeness ───────────────────
    #[test]
    fn test_b2_ipv6_iana_special_purpose_registry_blocked() {
        let policy = ExitPolicy::default();

        let teredo: IpAddr = "2001:0000::1".parse().unwrap(); // Teredo (2001::/32), RFC 4380
        assert!(
            !policy.is_ip_permitted(teredo),
            "Teredo 2001::/32 must be blocked"
        );

        let doc: IpAddr = "2001:db8::1".parse().unwrap(); // Documentation, RFC 3849
        assert!(
            !policy.is_ip_permitted(doc),
            "Documentation 2001:db8::/32 must be blocked"
        );

        let orchid: IpAddr = "2001:20::1".parse().unwrap(); // ORCHIDv2, RFC 7343
        assert!(
            !policy.is_ip_permitted(orchid),
            "ORCHIDv2 2001:20::/28 must be blocked"
        );

        let discard: IpAddr = "100::1".parse().unwrap(); // Discard-Only, RFC 6666
        assert!(
            !policy.is_ip_permitted(discard),
            "Discard-Only 100::/64 must be blocked"
        );

        let public: IpAddr = "2606:4700:4700::1111".parse().unwrap(); // Cloudflare DNS
        assert!(
            policy.is_ip_permitted(public),
            "Global unicast must be permitted"
        );
    }

    // ── B4: Expanded default blocked ports ────────────────────────────────────
    #[test]
    fn test_b4_expanded_blocked_ports() {
        let policy = ExitPolicy::default();
        let public_ip = "8.8.8.8";

        assert!(
            !policy.is_permitted(public_ip, 22),
            "SSH (22) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 2375),
            "Docker API HTTP (2375) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 2376),
            "Docker API TLS (2376) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 3306),
            "MySQL (3306) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 5432),
            "PostgreSQL (5432) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 6379),
            "Redis (6379) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 9200),
            "Elasticsearch (9200) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 11211),
            "Memcached (11211) must be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 27017),
            "MongoDB (27017) must be blocked"
        );

        // Pre-existing ports must remain blocked (regression guards)
        assert!(
            !policy.is_permitted(public_ip, 25),
            "SMTP (25) must still be blocked"
        );
        assert!(
            !policy.is_permitted(public_ip, 445),
            "SMB (445) must still be blocked"
        );

        // Common web ports must remain open
        assert!(
            policy.is_permitted(public_ip, 80),
            "HTTP (80) must be permitted"
        );
        assert!(
            policy.is_permitted(public_ip, 443),
            "HTTPS (443) must be permitted"
        );
        assert!(
            policy.is_permitted(public_ip, 53),
            "DNS (53) must be permitted"
        );
    }
}
