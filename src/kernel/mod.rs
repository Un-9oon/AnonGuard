//! Kernel and L3/L4 zero-leak isolation layer.

pub mod dns;
pub mod killswitch;
pub mod netns;

pub use dns::{build_socks5h_connect_frame, TargetAddress};
pub use killswitch::KillSwitchController;
pub use netns::NetnsConfig;
