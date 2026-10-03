use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardState {
    /// The host:port strings of the pinned Entry Guards.
    pub guards: Vec<String>,
}

impl Default for GuardState {
    fn default() -> Self {
        Self::new()
    }
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
                    info!(
                        "Loaded {} persistent entry guards from {:?}",
                        state.guards.len(),
                        path
                    );
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
                    error!(
                        "Failed to create directory for guard state {:?}: {}",
                        parent, e
                    );
                    return;
                }
            }
        }

        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                let temp_path = path.with_extension("tmp");
                #[cfg(unix)]
                let write_result = {
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&temp_path)
                        .and_then(|mut f| {
                            use std::io::Write;
                            f.write_all(json.as_bytes())?;
                            f.sync_all()
                        })
                };

                #[cfg(not(unix))]
                let write_result = fs::write(&temp_path, &json);

                if let Err(e) = write_result {
                    error!(
                        "Failed to write temporary guard state securely to {:?}: {}",
                        temp_path, e
                    );
                    return;
                }

                if let Err(e) = fs::rename(&temp_path, path) {
                    error!(
                        "Failed to atomically replace guard state file {:?}: {}",
                        path, e
                    );
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
