//! Linux Network Namespace and nftables isolation primitives.

pub struct NetnsConfig {
    pub namespace_name: String,
    pub authorized_proxy_ip: String,
    pub authorized_proxy_port: u16,
}

impl NetnsConfig {
    pub fn new(
        namespace_name: impl Into<String>,
        proxy_ip: impl Into<String>,
        proxy_port: u16,
    ) -> Self {
        Self {
            namespace_name: namespace_name.into(),
            authorized_proxy_ip: proxy_ip.into(),
            authorized_proxy_port: proxy_port,
        }
    }

    /// Generates strict nftables firewall rules dropping all outbound traffic
    /// except packets destined for the authorized proxy endpoint.
    pub fn generate_nftables_rules(&self) -> Result<String, std::io::Error> {
        let ip: std::net::IpAddr = self.authorized_proxy_ip.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid authorized_proxy_ip for nftables: {}", e),
            )
        })?;

        Ok(format!(
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
            ip, self.authorized_proxy_port
        ))
    }

    /// Applies the strict nftables ruleset to the Linux kernel via `nft -f -`.
    /// Requires root or `CAP_NET_ADMIN` capability.
    pub fn apply_nftables_rules(&self) -> Result<(), std::io::Error> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let rules = self.generate_nftables_rules()?;
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(rules.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(std::io::Error::other(format!(
                "Failed to apply nftables rules: {}",
                err_msg.trim()
            )));
        }

        Ok(())
    }

    /// Flushes and removes the AnonGuard nftables filter table from the kernel.
    pub fn flush_nftables_rules() -> Result<(), std::io::Error> {
        use std::process::Command;

        let output = Command::new("nft")
            .args(["delete", "table", "inet", "anonguard_filter"])
            .output()?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(std::io::Error::other(format!(
                "Failed to flush nftables rules: {}",
                err_msg.trim()
            )));
        }

        Ok(())
    }
}
