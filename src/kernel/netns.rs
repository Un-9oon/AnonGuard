//! Linux application isolation: a loopback-only namespace and private Unix SOCKS bridge.
//! The transport remains outside the namespace. Host nftables is never modified.
use super::KillSwitchController;
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    sync::Semaphore,
};

pub struct NetnsConfig {
    pub namespace_name: String,
    pub authorized_proxy_ip: String,
    pub authorized_proxy_port: u16,
}
impl NetnsConfig {
    pub fn new(name: impl Into<String>, ip: impl Into<String>, port: u16) -> Self {
        Self {
            namespace_name: name.into(),
            authorized_proxy_ip: ip.into(),
            authorized_proxy_port: port,
        }
    }
    fn validate(&self) -> io::Result<std::net::IpAddr> {
        if self.namespace_name.is_empty()
            || self.namespace_name.len() > 40
            || !self
                .namespace_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid network namespace name",
            ));
        }
        let ip: std::net::IpAddr = self
            .authorized_proxy_ip
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid proxy IP"))?;
        if !ip.is_loopback() || self.authorized_proxy_port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Namespace proxy must be a loopback endpoint",
            ));
        }
        Ok(ip)
    }
    pub fn generate_nftables_rules(&self) -> io::Result<String> {
        let ip = self.validate()?;
        let family = if ip.is_ipv4() { "ip" } else { "ip6" };
        Ok(format!(
            r#"table inet anonguard_filter {{
 chain output {{
  type filter hook output priority 0; policy drop;
  oifname "lo" {family} daddr {ip} tcp dport {port} accept
  oifname "lo" {family} saddr {ip} tcp sport {port} ct state established accept
 }}
 chain input {{
  type filter hook input priority 0; policy drop;
  iifname "lo" {family} daddr {ip} tcp dport {port} accept
  iifname "lo" {family} saddr {ip} tcp sport {port} ct state established accept
 }}
}}
"#,
            port = self.authorized_proxy_port
        ))
    }
    fn command(args: &[&str]) -> io::Result<()> {
        let output = Command::new("ip").args(args).output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Network namespace operation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }
    /// Creates a fresh namespace. Existing namespaces are never silently reused.
    /// On failure, a partially created namespace has no external interfaces/routes.
    pub fn apply_nftables_rules(&self) -> io::Result<()> {
        use std::io::Write;
        let rules = self.generate_nftables_rules()?;
        Self::command(&["netns", "add", &self.namespace_name])?;
        let mut child = Command::new("ip")
            .args(["netns", "exec", &self.namespace_name, "nft", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Missing nft input"))?
            .write_all(rules.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "Namespace nftables installation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Self::command(&["-n", &self.namespace_name, "link", "set", "lo", "up"])
    }
    /// Explicit administrative cleanup, only after protected applications have stopped.
    pub fn remove_namespace(&self) -> io::Result<()> {
        self.validate()?;
        Self::command(&["netns", "delete", &self.namespace_name])
    }
    pub fn verify_current_namespace(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        self.validate()?;
        let current = std::fs::metadata("/proc/self/ns/net")?;
        let expected = std::fs::metadata(Path::new("/run/netns").join(&self.namespace_name))?;
        if current.ino() != expected.ino() || current.dev() != expected.dev() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Namespace proxy must run inside the configured namespace",
            ));
        }
        Ok(())
    }
}

pub struct IsolationHandle {
    bridge: tokio::task::JoinHandle<io::Result<()>>,
    child: tokio::process::Child,
    socket: PathBuf,
}
impl IsolationHandle {
    pub async fn wait_failure(&mut self) -> io::Result<()> {
        tokio::select! {
            result = &mut self.bridge => { result.map_err(|e| io::Error::other(e.to_string()))??; }
            result = self.child.wait() => { result?; }
        }
        Err(io::Error::other(
            "Namespace proxy stopped; protected applications remain isolated",
        ))
    }
}
impl Drop for IsolationHandle {
    fn drop(&mut self) {
        self.bridge.abort();
        let _ = self.child.start_kill();
        let _ = std::fs::remove_file(&self.socket);
        // The namespace and its DROP rules deliberately survive process exit.
    }
}

pub fn start_isolation(
    config: &NetnsConfig,
    socket: &Path,
    kill: KillSwitchController,
    helper_executable: &Path,
) -> io::Result<IsolationHandle> {
    use std::os::unix::fs::PermissionsExt;
    let ip = config.validate()?;
    let endpoint = std::net::SocketAddr::new(ip, config.authorized_proxy_port);
    let parent = socket
        .parent()
        .ok_or_else(|| io::Error::other("Socket requires a parent directory"))?;
    std::fs::create_dir_all(parent)?;
    // Refuse existing socket paths. Do not unlink another daemon's live socket.
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    config.apply_nftables_rules()?;
    let bridge = tokio::spawn(async move {
        let limit = Arc::new(Semaphore::new(64));
        loop {
            let permit = limit
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| io::Error::other("Bridge closed"))?;
            let (mut client, _) = listener.accept().await?;
            let mut cancellation = kill.subscribe();
            if kill.is_tripped() {
                return Err(io::Error::other("Isolation kill switch active"));
            }
            tokio::spawn(async move {
                let _permit = permit;
                tokio::select! {
                    _ = async {
                        if let Ok(Ok(mut proxy)) = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(endpoint)).await {
                            let _ = tokio::time::timeout(std::time::Duration::from_secs(3600), tokio::io::copy_bidirectional(&mut client, &mut proxy)).await;
                        }
                    } => {}
                    _ = cancellation.changed() => {}
                }
            });
        }
    });
    let mut command = tokio::process::Command::new("ip");
    command.args(["netns", "exec", &config.namespace_name]);
    command
        .arg(helper_executable)
        .arg("--namespace-proxy")
        .arg("--namespace-name")
        .arg(&config.namespace_name)
        .arg("--namespace-socket")
        .arg(socket)
        .arg("--listen")
        .arg(endpoint.to_string());
    command.kill_on_drop(true);
    match command.spawn() {
        Ok(child) => Ok(IsolationHandle {
            bridge,
            child,
            socket: socket.to_path_buf(),
        }),
        Err(e) => {
            bridge.abort();
            let _ = std::fs::remove_file(socket);
            Err(e)
        }
    }
}

pub async fn run_namespace_proxy(config: &NetnsConfig, socket: &Path) -> io::Result<()> {
    let ip = config.validate()?;
    config.verify_current_namespace()?;
    let listener =
        TcpListener::bind(std::net::SocketAddr::new(ip, config.authorized_proxy_port)).await?;
    let limit = Arc::new(Semaphore::new(64));
    loop {
        let permit = limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("Namespace proxy closed"))?;
        let (mut client, _) = listener.accept().await?;
        let path = socket.to_path_buf();
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(Ok(mut host)) =
                tokio::time::timeout(std::time::Duration::from_secs(5), UnixStream::connect(path))
                    .await
            {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(3600),
                    tokio::io::copy_bidirectional(&mut client, &mut host),
                )
                .await;
            }
        });
    }
}
