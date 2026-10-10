//! Persistent entry guards pinned by cryptographic identity, not only by address.
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardState {
    pub protocol_version: u32,
    pub guards: Vec<String>,
    #[serde(default)]
    pub identities: HashMap<String, [u8; 32]>,
}
impl Default for GuardState {
    fn default() -> Self {
        Self {
            protocol_version: 6,
            guards: Vec::new(),
            identities: HashMap::new(),
        }
    }
}
impl GuardState {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn load_checked(path: &Path) -> Result<Self, String> {
        match crate::core::storage::read_bounded_file(path, 65536) {
            Ok(bytes) => {
                let state: Self = serde_json::from_slice(&bytes).map_err(|e| {
                    format!("Invalid persistent guard state; explicit v6 migration required: {e}")
                })?;
                if state.protocol_version != 6 {
                    return Err(
                        "Unsupported guard identity format; explicit migration required".into(),
                    );
                }
                Ok(state)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(format!("Cannot read persistent guard state: {e}")),
        }
    }
    /// Compatibility helper. Runtime callers use load_checked and reject corrupt state.
    pub fn load(path: &Path) -> Self {
        Self::load_checked(path).unwrap_or_default()
    }
    pub fn save_checked(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        crate::core::storage::atomic_write(path, &bytes).map_err(|e| e.to_string())
    }
    pub fn save(&self, path: &Path) {
        if let Err(error) = self.save_checked(path) {
            tracing::error!(%error,"Guard state persistence failed");
        }
    }
}
