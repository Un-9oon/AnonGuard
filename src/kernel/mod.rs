//! Kernel and L3/L4 zero-leak isolation layer.

pub mod dns;
pub mod exit_policy;
pub mod killswitch;
#[cfg(target_os = "linux")]
pub mod netns;

pub use dns::{build_socks5h_connect_frame, TargetAddress};
pub use exit_policy::{is_exit_target_permitted, ExitPolicy};
pub use killswitch::{check_fail_closed_guarantee, FailClosedGuarantee, KillSwitchController};
#[cfg(target_os = "linux")]
pub use netns::NetnsConfig;
