//! Traffic morphing and statistical correlation resistance.

pub mod chaos;
pub mod jitter;
pub mod obfuscator;
pub mod padding;
pub mod quantum;

pub use chaos::LorenzAttractor;
pub use jitter::PoissonJitter;
pub use quantum::{QuantumRmtEngine, QuantumEnsemble};
pub use obfuscator::{morph_bidirectional, morph_bidirectional_guarded, JitterEngine};
pub use padding::PacketPadder;
