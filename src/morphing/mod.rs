//! Traffic morphing and statistical correlation resistance.

pub mod chaos;
pub mod jitter;
pub mod obfuscator;
pub mod padding;
pub mod rmt;

pub use chaos::LorenzAttractor;
pub use jitter::PoissonJitter;
pub use obfuscator::{morph_bidirectional, morph_bidirectional_guarded, JitterEngine};
pub use padding::PacketPadder;
pub use rmt::{RmtEnsemble, RmtTimingEngine};
