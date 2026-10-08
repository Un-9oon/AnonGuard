//! Persistent entry guards pinned by cryptographic identity, not only by address.
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuardState {
    pub guards: Vec<String>,
    #[serde(default)]
    pub identities: HashMap<String, [u8; 32]>,
}
impl GuardState {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn load_checked(path: &Path) -> Result<Self, String> {
        match crate::core::storage::read_bounded_file(path, 65536) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("Invalid persistent guard state: {e}")),
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
