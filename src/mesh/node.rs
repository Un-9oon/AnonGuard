//! Proxy node representation and protocol abstraction.

use std::fmt;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Http,
    Https,
    Socks4,
    Socks4a,
    Socks5,
    Socks5h,
    Reverse,
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Socks4 => write!(f, "socks4"),
            Self::Socks4a => write!(f, "socks4a"),
            Self::Socks5 => write!(f, "socks5"),
            Self::Socks5h => write!(f, "socks5h"),
            Self::Reverse => write!(f, "reverse"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyNode {
    pub raw_url: String,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub latency_ms: Option<f64>,
    pub is_alive: bool,
    pub failure_count: u32,
}

impl ProxyNode {
    /// Parses a proxy string (e.g. `socks5://user:pass@1.2.3.4:1080` or `1.2.3.4:8080`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let input = raw.trim();
        let formatted = if !input.contains("://") {
            format!("http://{}", input)
        } else {
            input.to_string()
        };

        let parsed = Url::parse(&formatted).map_err(|e| format!("Invalid URL '{}': {}", raw, e))?;
        let scheme = parsed.scheme().to_lowercase();
        let protocol = match scheme.as_str() {
            "http" => ProxyProtocol::Http,
            "https" => ProxyProtocol::Https,
            "socks4" => ProxyProtocol::Socks4,
            "socks4a" => ProxyProtocol::Socks4a,
            "socks5" => ProxyProtocol::Socks5,
            "socks5h" => ProxyProtocol::Socks5h,
            "reverse" => ProxyProtocol::Reverse,
            other => return Err(format!("Unsupported proxy protocol '{}'", other)),
        };

        let host = parsed
            .host_str()
            .ok_or("Missing host in proxy URL")?
            .to_string();
        let port = parsed.port().unwrap_or(match protocol {
            ProxyProtocol::Http => 8080,
            ProxyProtocol::Https => 443,
            ProxyProtocol::Socks4
            | ProxyProtocol::Socks4a
            | ProxyProtocol::Socks5
            | ProxyProtocol::Socks5h => 1080,
            ProxyProtocol::Reverse => 0,
        });

        let username = if !parsed.username().is_empty() {
            Some(parsed.username().to_string())
        } else {
            None
        };

        let password = parsed.password().map(|p| p.to_string());

        Ok(Self {
            raw_url: raw.to_string(),
            protocol,
            host,
            port,
            username,
            password,
            latency_ms: None,
            is_alive: true,
            failure_count: 0,
        })
    }

    /// Upgrades socks5/socks4 to remote DNS variant (socks5h/socks4a).
    pub fn enforce_remote_dns(&mut self) {
        if self.protocol == ProxyProtocol::Socks5 {
            self.protocol = ProxyProtocol::Socks5h;
        } else if self.protocol == ProxyProtocol::Socks4 {
            self.protocol = ProxyProtocol::Socks4a;
        }
    }
}
