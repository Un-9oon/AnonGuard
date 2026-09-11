//! Dynamic proxy routing mesh and node abstraction.

pub mod node;
pub mod pool;

pub use node::{ProxyNode, ProxyProtocol};
pub use pool::ProxyPool;
