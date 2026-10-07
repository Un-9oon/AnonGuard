#![cfg(target_os = "linux")]
//! Run explicitly as root in an isolated CI runner with iproute2, nftables and python3.
use anonguard::kernel::{
    netns::{start_isolation, NetnsConfig},
    KillSwitchController,
};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UdpSocket},
    process::Command,
};
struct Cleanup(NetnsConfig, std::path::PathBuf, String);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.remove_namespace();
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &self.2])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}
async fn command(program: &str, args: &[&str]) -> String {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

async fn fault_routes(namespace: &str, host: &str, peer: &str) -> String {
    command(
        "ip",
        &["link", "add", host, "type", "veth", "peer", "name", peer],
    )
    .await;
    command("ip", &["link", "set", peer, "netns", namespace]).await;
    command(
        "sysctl",
        &["-w", &format!("net.ipv6.conf.{host}.disable_ipv6=0")],
    )
    .await;
    command(
        "ip",
        &[
            "netns",
            "exec",
            namespace,
            "sysctl",
            "-w",
            &format!("net.ipv6.conf.{peer}.disable_ipv6=0"),
        ],
    )
    .await;
    command("ip", &["addr", "add", "192.0.2.1/30", "dev", host]).await;
    command(
        "ip",
        &[
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            host,
            "nodad",
        ],
    )
    .await;
    command(
        "ip",
        &["-n", namespace, "addr", "add", "192.0.2.2/30", "dev", peer],
    )
    .await;
    command(
        "ip",
        &[
            "-n",
            namespace,
            "-6",
            "addr",
            "add",
            "2001:db8:1::2/64",
            "dev",
            peer,
            "nodad",
        ],
    )
    .await;
    command("ip", &["link", "set", host, "up"]).await;
    command("ip", &["-n", namespace, "link", "set", peer, "up"]).await;
    let host_info: serde_json::Value =
        serde_json::from_str(&command("ip", &["-j", "link", "show", "dev", host]).await).unwrap();
    let peer_info: serde_json::Value = serde_json::from_str(
        &command("ip", &["-n", namespace, "-j", "link", "show", "dev", peer]).await,
    )
    .unwrap();
    let host_mac = host_info[0]["address"].as_str().unwrap();
    let peer_mac = peer_info[0]["address"].as_str().unwrap();
    // Avoid attributing absent neighbor resolution to successful firewall isolation.
    for address in ["192.0.2.1", "2001:db8:1::1"] {
        command(
            "ip",
            &[
                "-n",
                namespace,
                "neigh",
                "replace",
                address,
                "lladdr",
                host_mac,
                "nud",
                "permanent",
                "dev",
                peer,
            ],
        )
        .await;
    }
    for address in ["192.0.2.2", "2001:db8:1::2"] {
        command(
            "ip",
            &[
                "neigh",
                "replace",
                address,
                "lladdr",
                peer_mac,
                "nud",
                "permanent",
                "dev",
                host,
            ],
        )
        .await;
    }
    peer_mac.to_string()
}

#[tokio::test]
#[ignore = "requires root and network namespace capabilities"]
async fn application_namespace_has_proxy_access_and_no_external_route_after_crash() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = [0; 64];
                while let Ok(n) = stream.read(&mut bytes).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let name = format!("ag-test-{:016x}", rand::random::<u64>());
    let dir = std::env::temp_dir().join(&name);
    std::fs::create_dir_all(&dir).unwrap();
    let config = NetnsConfig::new(&name, "127.0.0.1", port);
    let interface_id = rand::random::<u32>();
    let host_interface = format!("ag{interface_id:08x}h");
    let peer_interface = format!("ag{interface_id:08x}p");
    let _cleanup = Cleanup(
        NetnsConfig::new(&name, "127.0.0.1", port),
        dir.clone(),
        host_interface.clone(),
    );
    let handle = start_isolation(
        &config,
        &dir.join("proxy.sock"),
        KillSwitchController::new(),
        Path::new(env!("CARGO_BIN_EXE_anonguard-daemon")),
    )
    .unwrap();
    let positive=format!("import socket; s=socket.create_connection(('127.0.0.1',{port}),2); s.sendall(b'namespace-test'); assert s.makefile('rb').read(14)==b'namespace-test'");
    let mut ready = false;
    for _ in 0..30 {
        let result = Command::new("ip")
            .args(["netns", "exec", &name, "python3", "-c", &positive])
            .output()
            .await
            .unwrap();
        if result.status.success() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "Namespace proxy never became ready");
    // Fault injection: routes really exist, so the DROP policy must stop packets.
    // All addresses and observers belong to this isolated CI fixture.
    let peer_mac = fault_routes(&name, &host_interface, &peer_interface).await;
    let udp_v4 = UdpSocket::bind("192.0.2.1:0").await.unwrap();
    let udp_v6 = UdpSocket::bind("[2001:db8:1::1]:0").await.unwrap();
    let tcp_v4 = TcpListener::bind("192.0.2.1:0").await.unwrap();
    let tcp_v6 = TcpListener::bind("[2001:db8:1::1]:0").await.unwrap();
    // Ensure the controlled endpoints are reachable from their host namespace.
    for listener in [&tcp_v4, &tcp_v6] {
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop((client, server));
    }
    for socket in [&udp_v4, &udp_v6] {
        socket
            .send_to(b"control", socket.local_addr().unwrap())
            .await
            .unwrap();
        let mut control = [0; 7];
        tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut control))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&control, b"control");
    }
    let observer_code = r#"import socket, select, sys, time
s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((sys.argv[1],0)); s.setblocking(False)
peer=bytes.fromhex(sys.argv[2].replace(':',''))
print('READY',flush=True)
deadline=time.monotonic()+20
while time.monotonic()<deadline:
 ready,_,_=select.select([s,sys.stdin],[],[],0.1)
 if s in ready:
  while True:
   try: packet=s.recv(65536)
   except BlockingIOError: break
   if packet[6:12]==peer and packet[12:14] in (b'\x08\x00',b'\x86\xdd'):
    raise AssertionError('direct IP packet escaped the protected namespace')
 if sys.stdin in ready:
  assert sys.stdin.readline().strip()=='STOP'
  break
else: raise AssertionError('observer exceeded its bounded lifetime')
"#;
    let mut observer = Command::new("python3")
        .args(["-u", "-c", observer_code, &host_interface, &peer_mac])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut observer_stdout = BufReader::new(observer.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), observer_stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line, "READY\n");
    let negative = format!(
        r#"import socket, errno
for family,target in [(socket.AF_INET,('192.0.2.1',{})),(socket.AF_INET6,('2001:db8:1::1',{}))]:
 s=socket.socket(family,socket.SOCK_STREAM); s.settimeout(0.5)
 try: s.connect(target)
 except OSError as e:
  assert e.errno not in (errno.ENETUNREACH,errno.EAFNOSUPPORT,errno.EADDRNOTAVAIL), 'fixture route is missing'
 else: raise AssertionError('direct TCP connection escaped namespace')
 s.close()
query=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x07invalid\x00\x00\x01\x00\x01'
for family,target in [(socket.AF_INET,('192.0.2.1',{})),(socket.AF_INET6,('2001:db8:1::1',{}))]:
 s=socket.socket(family,socket.SOCK_DGRAM)
 try: s.sendto(query,target)
 except OSError as e:
  assert e.errno in (errno.EACCES,errno.EPERM), 'fixture route is missing'
 s.close()
"#,
        tcp_v4.local_addr().unwrap().port(),
        tcp_v6.local_addr().unwrap().port(),
        udp_v4.local_addr().unwrap().port(),
        udp_v6.local_addr().unwrap().port()
    );
    command("ip", &["netns", "exec", &name, "python3", "-c", &negative]).await;
    let held_code = format!(
        r#"import socket
s=socket.create_connection(('127.0.0.1',{port}),2)
s.sendall(b'held'); assert s.makefile('rb').read(4)==b'held'
print('READY',flush=True); s.settimeout(3)
try: assert s.recv(1)==b''
except ConnectionResetError: pass
"#
    );
    let mut held = Command::new("ip")
        .args(["netns", "exec", &name, "python3", "-u", "-c", &held_code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut held_stdout = BufReader::new(held.stdout.take().unwrap());
    line.clear();
    tokio::time::timeout(Duration::from_secs(3), held_stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line, "READY\n");
    drop(handle);
    let ended = tokio::time::timeout(Duration::from_secs(4), held.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        ended.status.success(),
        "Active namespace connection survived helper crash: {}",
        String::from_utf8_lossy(&ended.stderr)
    );
    command("ip", &["netns", "exec", &name, "python3", "-c", &negative]).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = observer.stdin.as_mut().unwrap().write_all(b"STOP\n").await;
    let observed = tokio::time::timeout(Duration::from_secs(3), observer.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        observed.status.success(),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    for socket in [&udp_v4, &udp_v6] {
        let mut payload = [0; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), socket.recv(&mut payload))
                .await
                .is_err(),
            "Direct DNS query escaped namespace"
        );
    }
    echo.abort();
}
