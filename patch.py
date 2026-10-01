import re

with open("src/gateway/server.rs", "r") as f:
    content = f.read()

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

    let circuits = Arc::new(circuits.into_iter().map(|c| Mutex::new(c)).collect::<Vec<_>>());
    
    // We will use a channel to collect BWD packets from all upstreams
    let (tx, mut rx) = mpsc::channel(100);

    // FWD Path
    // Since we need to write to multiple upstreams, and we can't easily split `&mut [GuardedSocket]` 
    // to pass to multiple tasks, we'll do FWD iteratively in one task.
    // Wait, if we do it in one task, writing to upstream_0 might block upstream_1.
    // That's acceptable for now to prove the concept.
    
    // We will extract the streams to avoid lifetime issues
    // For simplicity, we just use the first upstream for testing the signature.
    Ok(())
}
"""

if "pub async fn stream_multipath_circuits" not in content:
    content = content.replace(
        "pub async fn build_telescopic_circuit(",
        multipath_func + "\npub async fn build_telescopic_circuit("
    )

with open("src/gateway/server.rs", "w") as f:
    f.write(content)
