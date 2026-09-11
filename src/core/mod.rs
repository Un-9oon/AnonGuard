//! Core state machine, type invariants, and configuration.

pub mod config;
pub mod state_machine;

pub use config::GuardConfig;
pub use state_machine::{
    ActiveGuarded, DroppedFailClosed, GuardError, GuardedSocket, State, Uninitialized, Verifying,
};
