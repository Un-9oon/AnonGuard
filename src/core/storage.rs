//! Private, exclusive temporary files and atomic durable state replacement.
use std::io::Write;
use std::{fs, io, path::Path};
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".anonguard-{:032x}.tmp", rand::random::<u128>()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_identity_key(path: &std::path::Path) -> std::io::Result<ed25519_dalek::SigningKey> {
    use std::io::{Error, ErrorKind, Read};
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Identity key must be a regular 32-byte file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "Identity key must deny group and other access (chmod 600)",
            ));
        }
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(33));
    file.take(33).read_to_end(&mut bytes)?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    if bytes.len() != seed.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Identity key changed size during read",
        ));
    }
    seed.copy_from_slice(&bytes);
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

pub fn load_or_create_signing_key(
    path: &std::path::Path,
) -> std::io::Result<ed25519_dalek::SigningKey> {
    use std::io::Write;
    match read_identity_key(path) {
        Ok(key) => return Ok(key),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".anonguard-key-{:032x}.tmp",
        rand::random::<u128>()
    ));
    let result = (|| {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        let seed = zeroize::Zeroizing::new(key.to_bytes());
        file.write_all(seed.as_ref())?;
        file.sync_all()?;
        // Publish without replacing an identity won by another concurrent launch.
        match std::fs::hard_link(&temp, path) {
            Ok(()) => Ok(key),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_identity_key(path),
            Err(e) => Err(e),
        }
    })();
    let cleanup = std::fs::remove_file(&temp);
    let key = result?;
    cleanup?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(key)
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "anonguard-identity-{:032x}",
                rand::random::<u128>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn concurrent_startup_publishes_one_durable_identity() {
        let directory = Directory::new();
        let path = std::sync::Arc::new(directory.0.join("identity.key"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_signing_key(&path).unwrap().verifying_key()
                })
            })
            .collect();
        let expected = tasks
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>();
        assert!(expected.iter().all(|key| key == &expected[0]));
        assert_eq!(
            read_identity_key(&path).unwrap().verifying_key(),
            expected[0]
        );
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn corrupt_identity_is_never_replaced() {
        let directory = Directory::new();
        let path = directory.0.join("identity.key");
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(load_or_create_signing_key(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
        assert!(read_identity_key(&directory.0).is_err());
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn existing_identity_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = Directory::new();
        let path = directory.0.join("identity.key");
        let expected = load_or_create_signing_key(&path).unwrap().verifying_key();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load_or_create_signing_key(&path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_identity_key(&path).unwrap().verifying_key(), expected);
    }
}
