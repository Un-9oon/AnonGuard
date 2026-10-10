//! Bounded hop-local cover inside authenticated TLS. This is not an anonymity proof.
//! Each direction has a 64-cell application buffer; outbound adds a 64-cell
//! FIFO plus one producer cell. Congestion and connection lifetimes still leak.
//! Never use this framing outside authenticated, mandatory-version TLS links.
use rand::Rng;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{mpsc, watch},
    task::AbortHandle,
    time::Instant,
};

const CELL: usize = crate::onion::cell::ONION_CELL_SIZE;
const FRAME: usize = CELL + 4;
const QUEUE: usize = 64;
const DEADLINE: Duration = Duration::from_secs(30);

pub struct CoveredStream {
    application: DuplexStream,
    cancel: watch::Sender<bool>,
    workers: Vec<AbortHandle>,
    accepted: u64,
    shutdown_done: bool,
    progress: watch::Receiver<u64>,
    finished: watch::Receiver<bool>,
    flushing: Option<Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>>,
    shutting: Option<Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>>,
}
impl Drop for CoveredStream {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        for worker in &self.workers {
            worker.abort();
        }
    }
}
impl AsyncRead for CoveredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.application).poll_read(cx, buf)
    }
}
impl AsyncWrite for CoveredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutting.is_some() || self.shutdown_done || *self.cancel.borrow() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Covered link shutting down",
            )));
        }
        let result = Pin::new(&mut self.application).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = result {
            self.accepted += count as u64;
            self.flushing = None;
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.accepted.is_multiple_of(CELL as u64) {
            return Poll::Ready(Err(invalid("Cannot flush a partial onion cell")));
        }
        if self.flushing.is_none() {
            let target = self.accepted;
            let mut progress = self.progress.clone();
            self.flushing = Some(Box::pin(deadline(async move {
                loop {
                    if *progress.borrow() >= target {
                        return Ok(());
                    }
                    progress
                        .changed()
                        .await
                        .map_err(|_| invalid("Covered writer closed before flush"))?;
                }
            })));
        }
        let result = self.flushing.as_mut().unwrap().as_mut().poll(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            let _ = self.cancel.send(true);
        }
        if result.is_ready() {
            self.flushing = None;
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if self.shutting.is_none() {
            match Pin::new(&mut self.application).poll_shutdown(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            let mut finished = self.finished.clone();
            self.shutting = Some(Box::pin(deadline(async move {
                loop {
                    if *finished.borrow() {
                        return Ok(());
                    }
                    finished
                        .changed()
                        .await
                        .map_err(|_| invalid("Covered shutdown failed"))?;
                }
            })));
        }
        let result = self.shutting.as_mut().unwrap().as_mut().poll(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.shutdown_done = true;
        }
        if matches!(result, Poll::Ready(Err(_))) {
            let _ = self.cancel.send(true);
            self.shutting = None;
        }
        result
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
async fn deadline<F: std::future::Future<Output = io::Result<T>>, T>(future: F) -> io::Result<T> {
    tokio::time::timeout(DEADLINE, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Covered link deadline"))?
}
fn spawn<F>(future: F, cancel: watch::Sender<bool>, cancel_success: bool) -> AbortHandle
where
    F: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    let mut receiver = cancel.subscribe();
    tokio::spawn(async move {
        if *receiver.borrow() {
            return;
        }
        tokio::select! {
            _=receiver.changed()=>{},
            result=future=>{if cancel_success || result.is_err(){let _=cancel.send(true);}},
        }
    })
    .abort_handle()
}

/// Fixed envelope stream. Accepted intervals are 10–1000 ms. Shutdown closes both
/// directions after a bounded FIFO drain; flush waits for complete cells to be
/// written and flushed into TLS, not acknowledged by the remote application.
pub fn wrap<S>(stream: S, interval: Duration) -> io::Result<CoveredStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !(Duration::from_millis(10)..=Duration::from_secs(1)).contains(&interval) {
        return Err(invalid("Covered link interval out of bounds"));
    }
    let phase = Duration::from_nanos(rand::thread_rng().gen_range(1..=interval.as_nanos() as u64));
    let (application, bridge) = tokio::io::duplex(CELL * QUEUE);
    let (mut app_read, mut app_write) = tokio::io::split(bridge);
    let (mut wire_read, mut wire_write) = tokio::io::split(stream);
    let (sender, mut receiver) = mpsc::channel::<[u8; CELL]>(QUEUE);
    let (cancel, _) = watch::channel(false);
    let (progress_sender, progress) = watch::channel(0u64);
    let (finished_sender, finished) = watch::channel(false);
    let producer = spawn(
        async move {
            loop {
                let mut cell = [0u8; CELL];
                // Idle applications may wait indefinitely. Once the first byte is
                // accepted, a partial cell must complete within the deadline.
                if app_read.read(&mut cell[..1]).await? == 0 {
                    return Ok(());
                }
                deadline(app_read.read_exact(&mut cell[1..])).await?;
                sender
                    .send(cell)
                    .await
                    .map_err(|_| invalid("Covered writer closed"))?;
            }
        },
        cancel.clone(),
        false,
    );
    let writer = spawn(
        async move {
            let mut sent = 0u64;
            let clock = tokio::time::sleep(phase);
            tokio::pin!(clock);
            loop {
                clock.as_mut().await;
                let mut frame = [0u8; FRAME];
                frame[0] = 1;
                match receiver.try_recv() {
                    Ok(cell) => {
                        frame[1] = 1;
                        frame[4..].copy_from_slice(&cell);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        frame[1] = 2;
                        rand::thread_rng().fill(&mut frame[4..]);
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        deadline(wire_write.flush()).await?;
                        deadline(wire_write.shutdown()).await?;
                        let _ = finished_sender.send(true);
                        return Ok(());
                    }
                }
                deadline(wire_write.write_all(&frame)).await?;
                deadline(wire_write.flush()).await?;
                if frame[1] == 1 {
                    sent += CELL as u64;
                    let _ = progress_sender.send(sent);
                }
                // Reset after completion: never emit catch-up bursts after congestion.
                clock.as_mut().reset(Instant::now() + interval);
            }
        },
        cancel.clone(),
        true,
    );
    let reader = spawn(
        async move {
            let mut credit = 128f64;
            let mut updated = Instant::now();
            loop {
                let mut frame = [0u8; FRAME];
                // Silence is bounded too: a negotiated cover peer must keep sending.
                deadline(wire_read.read_exact(&mut frame)).await?;
                let now = Instant::now();
                credit = (credit + now.duration_since(updated).as_secs_f64() * 200.).min(128.);
                updated = now;
                if credit < 1. {
                    return Err(invalid("Covered link receive budget exhausted"));
                }
                credit -= 1.;
                if frame[0] != 1 || frame[2..4] != [0, 0] {
                    return Err(invalid("Invalid covered envelope"));
                }
                match frame[1] {
                    1 => deadline(app_write.write_all(&frame[4..])).await?,
                    2 => {}
                    _ => return Err(invalid("Unknown covered envelope kind")),
                }
            }
        },
        cancel.clone(),
        true,
    );
    Ok(CoveredStream {
        application,
        cancel,
        workers: vec![producer, writer, reader],
        accepted: 0,
        shutdown_done: false,
        progress,
        finished,
        flushing: None,
        shutting: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fragmented_roundtrip_and_shutdown() {
        let (a, b) = tokio::io::duplex(FRAME * 4);
        let mut a = wrap(a, Duration::from_millis(10)).unwrap();
        let mut b = wrap(b, Duration::from_millis(10)).unwrap();
        let data = [7u8; CELL];
        a.write_all(&data[..13]).await.unwrap();
        a.write_all(&data[13..]).await.unwrap();
        let mut actual = [0u8; CELL];
        tokio::time::timeout(Duration::from_secs(1), b.read_exact(&mut actual))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data, actual);
        a.shutdown().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), b.read(&mut actual))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn idle_padding_and_bad_envelope_close() {
        let (a, mut raw) = tokio::io::duplex(FRAME * 2);
        let mut a = wrap(a, Duration::from_millis(10)).unwrap();
        let mut frame = [0u8; FRAME];
        raw.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..4], &[1, 2, 0, 0]);
        frame[1] = 99;
        raw.write_all(&frame).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), a.read(&mut frame))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn blocked_transport_is_bounded_and_drop_cancels() {
        let (a, mut raw) = tokio::io::duplex(1);
        let mut a = wrap(a, Duration::from_millis(10)).unwrap();
        let data = vec![1u8; CELL * (QUEUE * 4)];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), a.write_all(&data))
                .await
                .is_err()
        );
        drop(a);
        let mut byte = [0u8; 1];
        while raw.read(&mut byte).await.unwrap() != 0 {}
    }
    #[test]
    fn invalid_interval_refuses() {
        let (a, _) = tokio::io::duplex(1);
        assert!(wrap(a, Duration::ZERO).is_err());
    }
    #[tokio::test]
    async fn shutdown_drains_final_cells_in_order() {
        let (a, b) = tokio::io::duplex(FRAME * 16);
        let mut a = wrap(a, Duration::from_millis(10)).unwrap();
        let mut b = wrap(b, Duration::from_millis(10)).unwrap();
        let mut data = vec![0u8; CELL * 8];
        for (index, cell) in data.chunks_mut(CELL).enumerate() {
            cell.fill(index as u8);
        }
        a.write_all(&data).await.unwrap();
        a.shutdown().await.unwrap();
        a.shutdown().await.unwrap();
        let mut received = vec![0u8; data.len()];
        b.read_exact(&mut received).await.unwrap();
        assert_eq!(data, received);
    }
    #[tokio::test]
    async fn flush_waits_for_wire_and_partial_cell_refuses() {
        let (a, mut raw) = tokio::io::duplex(FRAME * 4);
        let mut a = wrap(a, Duration::from_millis(10)).unwrap();
        a.write_all(&[9u8; CELL]).await.unwrap();
        a.flush().await.unwrap();
        let mut frame = [0u8; FRAME];
        loop {
            raw.read_exact(&mut frame).await.unwrap();
            if frame[1] == 1 {
                break;
            }
        }
        assert_eq!(&frame[4..], &[9u8; CELL]);
        a.write_all(&[0]).await.unwrap();
        assert!(a.flush().await.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn stalled_shutdown_has_deadline() {
        let (a, _raw) = tokio::io::duplex(1);
        let mut a = wrap(a, Duration::from_millis(10)).unwrap();
        a.write_all(&[0u8; CELL]).await.unwrap();
        assert!(a.shutdown().await.is_err());
    }
    #[tokio::test]
    async fn invalid_version_reserved_and_truncated_close() {
        for variant in 0..3 {
            let (a, mut raw) = tokio::io::duplex(FRAME * 2);
            let mut a = wrap(a, Duration::from_millis(10)).unwrap();
            let mut frame = [0u8; FRAME];
            frame[0] = 1;
            frame[1] = 2;
            match variant {
                0 => frame[0] = 2,
                1 => frame[2] = 1,
                _ => {}
            }
            let count = if variant == 2 { FRAME - 1 } else { FRAME };
            raw.write_all(&frame[..count]).await.unwrap();
            raw.shutdown().await.unwrap();
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), a.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }
}
