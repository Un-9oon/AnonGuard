use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use rand::Rng;
use rand_distr::{Distribution, Exp};

use crate::core::state_machine::{ActiveGuarded, GuardedSocket};
use crate::morphing::JitterEngine;
use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
use crate::onion::circuit::OnionCircuit;
use crate::onion::multipath::{MultiPathReassembler, MultiPathSlicer, MULTIPATH_HEADER_SIZE};

pub async fn stream_multipath_circuits(
    client: &mut GuardedSocket<ActiveGuarded>,
    mut upstreams: Vec<GuardedSocket<ActiveGuarded>>,
    circuits: Vec<OnionCircuit>,
    jitter: Option<JitterEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let num_paths = upstreams.len();
    if num_paths == 0 || circuits.len() != num_paths {
        return Err("Mismatched or empty upstreams/circuits".into());
    }

    let circuits = Arc::new(circuits.into_iter().map(|c| Mutex::new(c)).collect::<Vec<_>>());
    let (mut client_read, mut client_write) = tokio::io::split(client);

    let mut upstream_reads = Vec::new();
    let mut upstream_writes = Vec::new();
    for u in upstreams.iter_mut() {
        let (ur, uw) = tokio::io::split(u);
        upstream_reads.push(ur);
        upstream_writes.push(uw);
    }

    let circuits_fwd = circuits.clone();
    let jitter_fwd = jitter.clone();

    let fwd = async move {
        let mut slicer = MultiPathSlicer::new();
        let max_data = PAYLOAD_SIZE - MULTIPATH_HEADER_SIZE;
        let mut buf = vec![0u8; 8192];
        let stream_id = 1u16;
        let mut client_seqs = vec![2u32; num_paths];
        
        // Bounded Poisson-like Organic Metronome (mean 20ms, bounded 5ms-35ms)
        let exp_dist = Exp::new(1.0 / 20.0).unwrap();
        let mut get_next_delay = move || {
            let mut rng = rand::thread_rng();
            let mut delay: f64 = exp_dist.sample(&mut rng);
            if delay < 5.0 { delay = 5.0; }
            if delay > 35.0 { delay = 35.0; }
            std::time::Duration::from_millis(delay as u64)
        };

        let mut path_loads = vec![0usize; num_paths];
        
        let mut client_buffer = std::collections::VecDeque::new();
        let mut client_open = true;

        loop {
            let delay = get_next_delay();
            tokio::select! {
                res = client_read.read(&mut buf), if client_open && client_buffer.len() < 65536 => match res {
                    Ok(0) => {
                        client_open = false;
                    },
                    Ok(n) => {
                        client_buffer.extend(&buf[..n]);
                    },
                    Err(_) => {
                        client_open = false;
                    }
                },
                _ = tokio::time::sleep(delay) => {
                    if !client_open && client_buffer.is_empty() {
                        break;
                    }

                    let mut is_dummy = false;
                    let mut sliced_buf = vec![0u8; PAYLOAD_SIZE];
                    let cell_len;

                    if client_buffer.is_empty() {
                        is_dummy = true;
                        cell_len = PAYLOAD_SIZE;
                    } else {
                        let chunk_size = std::cmp::min(client_buffer.len(), max_data);
                        let mut chunk = vec![0u8; chunk_size];
                        for b in chunk.iter_mut() {
                            *b = client_buffer.pop_front().unwrap();
                        }
                        cell_len = slicer.slice(&chunk, &mut sliced_buf);
                    }

                    // Smart Routing Simulation: select path with lowest transmitted load
                    let mut c_idx = 0;
                    let mut min_load = usize::MAX;
                    for (i, &load) in path_loads.iter().enumerate() {
                        if load < min_load {
                            min_load = load;
                            c_idx = i;
                        }
                    }
                    path_loads[c_idx] += 1;

                    let mut cell = {
                        let guard = circuits_fwd[c_idx].lock().await;
                        let seq = client_seqs[c_idx];
                        client_seqs[c_idx] += 1;

                        let cmd = if is_dummy {
                            CellCommand::Dummy
                        } else {
                            CellCommand::Data
                        };
                        match OnionCell::new(guard.circuit_id, seq, cmd, stream_id, &sliced_buf[..cell_len]) {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!("OnionCell construction failed: {}", e);
                                break;
                            }
                        }
                    };

            let wire_buffer_res = {
                let mut guard = circuits_fwd[c_idx].lock().await;
                guard.wrap_forward(&mut cell)
            };

            let wire_buffer = match wire_buffer_res {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Failed to wrap forward cell: {:?}", e);
                    break;
                }
            };

            if let Some(ref j) = jitter_fwd {
                j.apply_delay().await;
            }

            if upstream_writes[c_idx].write_all(&wire_buffer).await.is_err() {
                break;
            }
                }
            }
        }
        for w in upstream_writes.iter_mut() {
            let _ = w.shutdown().await;
        }
    };

    let circuits_bwd = circuits.clone();
    let bwd = async move {
        let mut reassembler = MultiPathReassembler::new();
        // Since read_exact is not cancellation safe, we read manually using a single buffer per upstream
        // and keep track of bytes read to avoid losing data in select!.
        let mut bufs = vec![[0u8; ONION_CELL_SIZE]; num_paths];
        let mut read_bytes = vec![0usize; num_paths];

        loop {
            // Build a list of pinned Box futures that do a single `read` call (not read_exact)
            let (res, idx) = std::future::poll_fn(|cx| {
                for (i, ur) in upstream_reads.iter_mut().enumerate() {
                    let rem = ONION_CELL_SIZE - read_bytes[i];
                    let mut buf = tokio::io::ReadBuf::new(&mut bufs[i][read_bytes[i]..read_bytes[i]+rem]);
                    match std::pin::Pin::new(&mut *ur).poll_read(cx, &mut buf) {
                        std::task::Poll::Ready(Ok(())) => {
                            let n = buf.filled().len();
                            return std::task::Poll::Ready((Ok(n), i));
                        }
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready((Err(e), i));
                        }
                        std::task::Poll::Pending => continue,
                    }
                }
                std::task::Poll::Pending
            }).await;
            
            match res {
                Ok(0) => break, // EOF
                Ok(n) => {
                    read_bytes[idx] += n;
                    if read_bytes[idx] == ONION_CELL_SIZE {
                        // We have a full cell
                        read_bytes[idx] = 0;
                        
                        let cell_res = {
                            let mut guard = circuits_bwd[idx].lock().await;
                            guard.unwrap_backward(&mut bufs[idx])
                        };

                        match cell_res {
                            Ok((_hop, cell)) => match cell.command {
                                CellCommand::Data => {
                                    let len = (cell.length as usize).min(cell.payload.len());
                                    let data = &cell.payload[..len];
                                    if let Some(ordered_data) = reassembler.receive(data) {
                                        if client_write.write_all(&ordered_data).await.is_err() { break; }
                                    }
                                    while let Some(ordered_data) = reassembler.pop_next_buffered() {
                                        if client_write.write_all(&ordered_data).await.is_err() { break; }
                                    }
                                }
                                CellCommand::Destroy => break,
                                _ => {}
                            },
                            Err(e) => {
                                tracing::warn!("Failed to unwrap backward cell: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client_write.shutdown().await;
    };

    tokio::pin!(fwd);
    tokio::pin!(bwd);
    let mut fwd_done = false;

    loop {
        tokio::select! {
            _ = &mut bwd => {
                break;
            }
            _ = &mut fwd, if !fwd_done => {
                fwd_done = true;
            }
        }
    }

    Ok(())
}
