import re

with open('src/gateway/server.rs', 'r') as f:
    content = f.read()

# 1. Imports
import_str = "use crate::core::state_machine::{GuardedSocket, ActiveGuarded};\n"
if "GuardedSocket" not in content:
    content = content.replace("use tokio::net::{TcpListener, TcpStream};", "use tokio::net::{TcpListener, TcpStream};\n" + import_str)

# 2. In run(), wrap client
client_wrap = """                let mut client = GuardedSocket::new(client_stream, kill_switch.atomic_handle())
                    .begin_verification()
                    .mark_verified();"""
content = re.sub(r'let mut client = client_stream;', client_wrap, content, count=1)

# 3. In run(), wrap guard_stream/upstream_stream
guard_wrap = """                            let mut guard_stream = GuardedSocket::new(guard_stream, kill_switch.atomic_handle())
                                .begin_verification()
                                .mark_verified();
                            let _ = stream_onion_circuit("""
content = content.replace("let _ = stream_onion_circuit(", guard_wrap, 1)

upstream_wrap = """                        let mut upstream_stream = GuardedSocket::new(upstream_stream, kill_switch.atomic_handle())
                            .begin_verification()
                            .mark_verified();
                        let _ = crate::morphing::morph_bidirectional_guarded("""
content = content.replace("let _ = crate::morphing::morph_bidirectional_guarded(\n                            &mut client,\n                            &mut upstream_stream,", upstream_wrap, 1)

# Wait, `morph_bidirectional_guarded` in `crate::morphing` takes `&mut S1, &mut S2`. It should work fine.

# What about the Reverse Relay loop?
reverse_client_wrap = """                                    let mut stream = GuardedSocket::new(stream, kill_switch.atomic_handle())
                                        .begin_verification()
                                        .mark_verified();
                                    let (target_host, target_port) =
                                        match crate::gateway::chain::intercept_socks5_request("""
content = content.replace("let (target_host, target_port) =\n                                        match crate::gateway::chain::intercept_socks5_request(", reverse_client_wrap, 1)

reverse_target_wrap = """                                            let mut target_stream = GuardedSocket::new(target_stream, kill_switch.atomic_handle())
                                                .begin_verification()
                                                .mark_verified();
                                            info!("""
content = content.replace("info!(\n                                                \"Reverse Relay: Forwarding traffic", reverse_target_wrap, 1)

# Now, stream_onion_circuit
old_stream = """pub async fn stream_onion_circuit(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    circuit: OnionCircuit,
    jitter: Option<JitterEngine>,
    kill_switch: Option<KillSwitchController>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {"""
new_stream = """pub async fn stream_onion_circuit(
    client: &mut GuardedSocket<ActiveGuarded>,
    upstream: &mut GuardedSocket<ActiveGuarded>,
    circuit: OnionCircuit,
    jitter: Option<JitterEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {"""
content = content.replace(old_stream, new_stream, 1)

old_split = """    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();"""
new_split = """    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);"""
content = content.replace(old_split, new_split, 1)

old_fwd_bwd = """    let mut fwd_done = false;
    let mut rx_opt = kill_switch.map(|ks| ks.subscribe());

    loop {
        let kill_wait = async {
            if let Some(ref mut rx) = rx_opt {
                while rx.changed().await.is_ok() {
                    if *rx.borrow() {
                        return;
                    }
                }
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            _ = kill_wait => {
                tracing::error!("[AnonGuard KillSwitch] TRIPPED! Enforcing immediate fail-closed circuit termination.");
                break;
            }
            _ = &mut bwd => {
                // Upstream connection ended or remote sent Destroy cell
                break;
            }
            _ = &mut fwd, if !fwd_done => {
                // Client upload finished; keep bwd running until upstream closes
                fwd_done = true;
            }
        }
    }"""
new_fwd_bwd = """    let mut fwd_done = false;
    loop {
        tokio::select! {
            _ = &mut bwd => {
                // Upstream connection ended or remote sent Destroy cell
                break;
            }
            _ = &mut fwd, if !fwd_done => {
                // Client upload finished; keep bwd running until upstream closes
                fwd_done = true;
            }
        }
    }"""
content = content.replace(old_fwd_bwd, new_fwd_bwd, 1)

# Finally, handle_onion_relay_connection
with open('src/gateway/server.rs', 'w') as f:
    f.write(content)
