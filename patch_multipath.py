import re

with open("src/gateway/server.rs", "r") as f:
    content = f.read()

# We need to insert `stream_multipath_circuits` after `stream_onion_circuit`.
multipath_func = """
pub async fn stream_multipath_circuits(
    client: &mut GuardedSocket<ActiveGuarded>,
    mut upstreams: Vec<GuardedSocket<ActiveGuarded>>,
    circuits: Vec<OnionCircuit>,
    jitter: Option<JitterEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{Mutex, mpsc};
    use crate::onion::multipath::{MultiPathSlicer, MultiPathReassembler, MULTIPATH_HEADER_SIZE};

    let num_paths = upstreams.len();
    if num_paths == 0 || circuits.len() != num_paths {
        return Err("Mismatched or empty upstreams/circuits".into());
    }

    let (mut client_read, mut client_write) = tokio::io::split(client);
    
    // We must take ownership of upstreams to spawn concurrent readers.
    // However, GuardedSocket doesn't easily split into owned parts without into_split() on the underlying TCP.
    // Instead of spawning, we can use a select loop with futures.
    
    // But honestly, the easiest way to handle multi-path in async Rust is mpsc channels.
    // Let's implement the FWD path (Client -> Network) in a loop, and BWD path (Network -> Client) using a channel.

    let circuits = Arc::new(circuits.into_iter().map(|c| Mutex::new(c)).collect::<Vec<_>>());
    
    let (tx, mut rx) = mpsc::channel(100);
    
    // To handle lifetimes without spawn, we can use a massive select macro or FuturesUnordered.
    // Let's just use a simple channel for BWD and tokio::spawn since we can take ownership of upstreams if we change the signature!
    // Wait, the signature takes `mut upstreams: Vec<GuardedSocket<ActiveGuarded>>` which OWNS them!
    
    // We can't tokio::spawn with `circuits` unless it's Arc'd, which it is.
    // But `client_write` is a borrow. So we can't tokio::spawn the writer.
    
    // Let's just do it in one big future using `tokio::select!` for the FWD path and RX path.
    // For the upstreams, we can't easily select over a Vec of mutable references.
    panic!("Not implemented yet");
}
"""

if "pub async fn stream_multipath_circuits" not in content:
    content = content.replace(
        "pub async fn build_telescopic_circuit(",
        multipath_func + "\npub async fn build_telescopic_circuit("
    )

with open("src/gateway/server.rs", "w") as f:
    f.write(content)
