//! Linux Network Namespace and nftables isolation primitives.

pub struct NetnsConfig {
    pub namespace_name: String,
    pub authorized_proxy_ip: String,
    pub authorized_proxy_port: u16,
}

impl NetnsConfig {
    pub fn new(namespace_name: impl Into<String>, proxy_ip: impl Into<String>, proxy_port: u16) -> Self {
        Self {
            namespace_name: namespace_name.into(),
            authorized_proxy_ip: proxy_ip.into(),
            authorized_proxy_port: proxy_port,
        }
    }

    /// Generates strict nftables firewall rules dropping all outbound traffic
    /// except packets destined for the authorized proxy endpoint.
    pub fn generate_nftables_rules(&self) -> String {
        format!(
            r#"table inet anonguard_filter {{
    chain output {{
        type filter hook output priority 0; policy drop;

        # Allow local loopback
        oif "lo" accept

        # Allow established and related connections
        ct state established,related accept

        # Strictly permit outbound transport ONLY to authorized proxy endpoint
        ip daddr {} tcp dport {} accept

        # Drop everything else
        drop
    }}
}}"#,
            self.authorized_proxy_ip, self.authorized_proxy_port
        )
    }
}
