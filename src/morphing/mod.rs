//! Traffic morphing and statistical correlation resistance.

pub mod chaos;
pub mod jitter;
pub mod obfuscator;
pub mod padding;

pub use chaos::LorenzAttractor;
pub use jitter::PoissonJitter;
pub use obfuscator::{morph_bidirectional, JitterEngine};
pub use padding::PacketPadder;
