#![deny(dead_code, unused_variables)]

//! # AnonGuard Core Engine
//!
//! A cross-layer anonymity and anti-attribution framework with zero-leak guarantees.

pub mod core;
pub mod crypto;
pub mod gateway;
pub mod kernel;
pub mod mesh;
pub mod morphing;
pub mod onion;

pub use crate::core::{
    ActiveGuarded, DroppedFailClosed, GuardConfig, GuardError, GuardedSocket, State,
};
pub use crate::crypto::{HeaderNormalizer, TlsProfile};
pub use crate::gateway::GatewayServer;
pub use crate::kernel::{build_socks5h_connect_frame, KillSwitchController, TargetAddress};
pub use crate::mesh::{ProxyNode, ProxyPool, ProxyProtocol};
pub use crate::morphing::{PacketPadder, PoissonJitter};

/// High-level orchestrator coordinating the AnonGuard system.
pub struct AnonGuardEngine {
    pub config: GuardConfig,
    pub pool: ProxyPool,
    pub kill_switch: KillSwitchController,
}

impl AnonGuardEngine {
    pub fn new(config: GuardConfig) -> Self {
        Self {
            config,
            pool: ProxyPool::new(),
            kill_switch: KillSwitchController::new(),
        }
    }

    pub async fn add_proxy(&self, raw_url: &str) -> Result<(), String> {
        self.pool.add_proxy(raw_url).await
    }

    pub fn get_kill_switch(&self) -> KillSwitchController {
        self.kill_switch.clone()
    }

    pub fn is_tripped(&self) -> bool {
        self.kill_switch.is_tripped()
    }
}

impl Default for AnonGuardEngine {
    fn default() -> Self {
        Self::new(GuardConfig::default())
    }
}
