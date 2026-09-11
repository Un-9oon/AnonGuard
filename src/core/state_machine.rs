//! Compile-time type-state pattern enforcing zero-leak state transitions.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Marker trait representing a valid state in the AnonGuard lifecycle.
pub trait State: Send + Sync + 'static {
    fn name() -> &'static str;
}

pub struct Uninitialized;
impl State for Uninitialized {
    fn name() -> &'static str {
        "UNINITIALIZED"
    }
}

pub struct Verifying;
impl State for Verifying {
    fn name() -> &'static str {
        "VERIFYING"
    }
}

pub struct ActiveGuarded;
impl State for ActiveGuarded {
    fn name() -> &'static str {
        "ACTIVE_GUARDED"
    }
}

pub struct DroppedFailClosed;
impl State for DroppedFailClosed {
    fn name() -> &'static str {
        "DROPPED_FAIL_CLOSED"
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("Socket transition error: {0}")]
    Transition(String),
    #[error("Kill switch active: packet transmission strictly blocked")]
    KillSwitchTripped,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A guarded TCP socket whose send capabilities are statically gated by its type-state parameter `S`.
pub struct GuardedSocket<S: State> {
    stream: Option<TcpStream>,
    kill_switch: Arc<AtomicBool>,
    _state: PhantomData<S>,
}

impl GuardedSocket<Uninitialized> {
    pub fn new(stream: TcpStream, kill_switch: Arc<AtomicBool>) -> Self {
        Self {
            stream: Some(stream),
            kill_switch,
            _state: PhantomData,
        }
    }

    pub fn begin_verification(mut self) -> GuardedSocket<Verifying> {
        GuardedSocket {
            stream: self.stream.take(),
            kill_switch: self.kill_switch.clone(),
            _state: PhantomData,
        }
    }
}

impl GuardedSocket<Verifying> {
    pub fn mark_verified(mut self) -> GuardedSocket<ActiveGuarded> {
        GuardedSocket {
            stream: self.stream.take(),
            kill_switch: self.kill_switch.clone(),
            _state: PhantomData,
        }
    }

    pub fn fail_verification(mut self) -> GuardedSocket<DroppedFailClosed> {
        self.kill_switch.store(true, Ordering::SeqCst);
        GuardedSocket {
            stream: self.stream.take(),
            kill_switch: self.kill_switch.clone(),
            _state: PhantomData,
        }
    }
}

// ONLY GuardedSocket<ActiveGuarded> implements data transmission!
impl GuardedSocket<ActiveGuarded> {
    /// Transmits data across the verified guarded socket.
    /// Fails immediately if the atomic kill switch is flagged.
    pub async fn send_guarded(&mut self, buf: &[u8]) -> Result<usize, GuardError> {
        if self.kill_switch.load(Ordering::SeqCst) {
            return Err(GuardError::KillSwitchTripped);
        }

        if let Some(stream) = self.stream.as_mut() {
            let written = stream.write(buf).await?;
            Ok(written)
        } else {
            Err(GuardError::KillSwitchTripped)
        }
    }

    /// Reads data from the verified socket.
    pub async fn recv_guarded(&mut self, buf: &mut [u8]) -> Result<usize, GuardError> {
        if self.kill_switch.load(Ordering::SeqCst) {
            return Err(GuardError::KillSwitchTripped);
        }

        if let Some(stream) = self.stream.as_mut() {
            let read = stream.read(buf).await?;
            Ok(read)
        } else {
            Err(GuardError::KillSwitchTripped)
        }
    }

    /// Trips the kill switch and converts socket into DroppedFailClosed state.
    pub fn trip_kill_switch(mut self) -> GuardedSocket<DroppedFailClosed> {
        self.kill_switch.store(true, Ordering::SeqCst);
        GuardedSocket {
            stream: self.stream.take(),
            kill_switch: self.kill_switch.clone(),
            _state: PhantomData,
        }
    }
}

impl<S: State> Drop for GuardedSocket<S> {
    fn drop(&mut self) {
        // Ensure stream is cleanly shut down on drop if not already transitioned
        if let Some(mut stream) = self.stream.take() {
            tokio::spawn(async move {
                let _ = stream.shutdown().await;
            });
        }
    }
}
