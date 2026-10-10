//! Private, exclusive temporary files and atomic durable state replacement.
use std::io::Write;
use std::{fs, io, path::Path};

/// Open a bounded regular input without blocking on a FIFO. Parent directories
/// must remain administrator-controlled; this is not a hostile-filesystem jail.
pub fn open_regular_file(path: &Path, maximum: u64) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Security input must be a bounded regular file",
        ));
    }
    Ok(file)
}

/// Bound both the initial size and bytes read if a regular file grows concurrently.
pub fn read_bounded_file(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let read_limit = maximum
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid input size limit"))?;
    let file = open_regular_file(path, maximum)?;
    let mut bytes = Vec::new();
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Security input exceeds size limit",
        ));
    }
    Ok(bytes)
}
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

pub fn read_identity_key(path: &Path) -> io::Result<crate::crypto::identity::SigningKey> {
    crate::crypto::hybrid_identity::HybridSigningKey::read_private_file(path)
        .map(crate::crypto::identity::SigningKey::from_hybrid)
}

pub fn load_or_create_signing_key(path: &Path) -> io::Result<crate::crypto::identity::SigningKey> {
    crate::crypto::hybrid_identity::HybridSigningKey::load_or_create(path)
        .map(crate::crypto::identity::SigningKey::from_hybrid)
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

    #[test]
    fn bounded_input_rejects_oversized_and_nonregular_files() {
        let directory = Directory::new();
        let path = directory.0.join("state.json");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(read_bounded_file(&path, 4).unwrap(), b"1234");
        assert!(read_bounded_file(&path, 3).is_err());
        assert!(read_bounded_file(&directory.0, 4096).is_err());
        assert!(read_bounded_file(&path, u64::MAX).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_and_symlink_keys_fail_without_creating_or_replacing_identity() {
        use std::os::unix::fs::{symlink, FileTypeExt};
        let directory = Directory::new();
        let target = directory.0.join("real.key");
        load_or_create_signing_key(&target).unwrap();
        let original = std::fs::read(&target).unwrap();
        let alias = directory.0.join("alias.key");
        symlink(&target, &alias).unwrap();
        assert!(load_or_create_signing_key(&alias).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), original);
        let fifo = directory.0.join("fifo.key");
        // The test owns this path and creates no writer, exercising the nonblocking open.
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(load_or_create_signing_key(&fifo).is_err());
        assert!(read_bounded_file(&fifo, 4096).is_err());
        assert!(std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo());
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 3);
    }
}
