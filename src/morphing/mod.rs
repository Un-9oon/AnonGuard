//! Traffic morphing and statistical correlation resistance.

pub mod jitter;
pub mod padding;

pub use jitter::PoissonJitter;
pub use padding::PacketPadder;
