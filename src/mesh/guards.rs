use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardState {
    /// The host:port strings of the pinned Entry Guards.
    pub guards: Vec<String>,
}

impl GuardState {
    pub fn new() -> Self {
        Self { guards: Vec::new() }
    }

    /// Loads the guard state from disk. Returns a new empty state if the file doesn't exist.
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::new();
        }

        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<GuardState>(&content) {
                Ok(state) => {
                    info!("Loaded {} persistent entry guards from {:?}", state.guards.len(), path);
                    state
                }
                Err(e) => {
                    error!("Failed to parse guard state file {:?}: {}", path, e);
                    Self::new()
                }
            },
            Err(e) => {
                error!("Failed to read guard state file {:?}: {}", path, e);
                Self::new()
            }
        }
    }

    /// Saves the guard state to disk securely (atomic write, mode 0o600 on Unix).
    pub fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                if let Err(e) = fs::create_dir_all(parent) {
                    error!("Failed to create directory for guard state {:?}: {}", parent, e);
                    return;
                }
            }
        }

        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                let temp_path = path.with_extension("tmp");
                if let Err(e) = fs::write(&temp_path, json) {
                    error!("Failed to write temporary guard state to {:?}: {}", temp_path, e);
                    return;
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(mut perms) = fs::metadata(&temp_path).map(|m| m.permissions()) {
                        perms.set_mode(0o600);
                        let _ = fs::set_permissions(&temp_path, perms);
                    }
                }

                if let Err(e) = fs::rename(&temp_path, path) {
                    error!("Failed to atomically replace guard state file {:?}: {}", path, e);
                } else {
                    info!("Saved persistent entry guards to {:?}", path);
                }
            }
            Err(e) => {
                error!("Failed to serialize guard state: {}", e);
            }
        }
    }
}
