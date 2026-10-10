//! Offline creation and signing of quorum-authorized retirement policies.
use anonguard::core::{
    revocation::{RevocationPolicy, MAX_POLICY_BYTES},
    storage,
};
use anonguard::crypto::identity::VerifyingKey;
use clap::{Parser, Subcommand};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(about = "Offline identity retirement ceremony; never prints private keys")]
struct Args {
    #[command(subcommand)]
    command: Operation,
}
#[derive(Subcommand)]
enum Operation {
    Create {
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        authority_keys: String,
        /// Cumulative comma-separated Ed25519 public pins; empty permits initial enrollment
        #[arg(long, default_value = "")]
        retire: String,
        #[arg(long)]
        output: PathBuf,
    },
    Sign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        authority_id: String,
        #[arg(long)]
        authority_keys: String,
        #[arg(long)]
        identity_key_path: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        authority_keys: String,
        #[arg(long)]
        quorum: usize,
    },
}

fn pin(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| "Invalid public pin")?;
    let pin: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public pin requires 32 bytes")?;
    let key = VerifyingKey::from_bytes(&pin).map_err(|_| "Invalid public identity")?;
    if key.is_weak() {
        return Err("Weak public identity".into());
    }
    Ok(pin)
}
fn keys(value: &str) -> Result<HashMap<String, VerifyingKey>, String> {
    let mut result = HashMap::new();
    let mut distinct = HashSet::new();
    for entry in value.split(',') {
        let (id, hex) = entry.split_once(':').ok_or("Expected id:public_pin")?;
        let pin = pin(hex)?;
        if id.is_empty()
            || id.len() > 128
            || result.len() >= 16
            || !distinct.insert(pin)
            || result
                .insert(
                    id.into(),
                    VerifyingKey::from_bytes(&pin).map_err(|_| "Invalid identity")?,
                )
                .is_some()
        {
            return Err("Authority identities and pins must be distinct and bounded".into());
        }
    }
    Ok(result)
}
fn read(path: &Path) -> Result<RevocationPolicy, Box<dyn std::error::Error>> {
    let bytes = storage::read_bounded_file(path, MAX_POLICY_BYTES)?;
    let policy: RevocationPolicy = serde_json::from_slice(&bytes)?;
    policy.validate_shape()?;
    Ok(policy)
}
fn publish(path: &Path, policy: &RevocationPolicy) -> Result<(), Box<dyn std::error::Error>> {
    // No replacement: each signer produces a distinct reviewable ceremony artifact.
    let bytes = serde_json::to_vec_pretty(policy)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Operation::Create {
            generation,
            authority_keys,
            retire,
            output,
        } => {
            let keys = keys(&authority_keys)?;
            let revoked = if retire.is_empty() {
                Vec::new()
            } else {
                retire.split(',').map(pin).collect::<Result<Vec<_>, _>>()?
            };
            let policy = RevocationPolicy::new(generation, &keys, revoked);
            policy.validate_shape()?;
            publish(&output, &policy)?;
        }
        Operation::Sign {
            input,
            authority_id,
            authority_keys,
            identity_key_path,
            output,
        } => {
            let mut policy = read(&input)?;
            // Never generate a new signing identity merely because a path is missing.
            let key = storage::read_identity_key(&identity_key_path)?;
            let trusted = keys(&authority_keys)?;
            if policy.authority_set != anonguard::core::revocation::authority_set_digest(&trusted)
                || trusted.get(&authority_id) != Some(&key.verifying_key())
            {
                return Err(
                    "Signer and policy must match the independently authenticated authority set"
                        .into(),
                );
            }
            policy.sign(&authority_id, &key)?;
            publish(&output, &policy)?;
        }
        Operation::Verify {
            input,
            authority_keys,
            quorum,
        } => {
            let policy = read(&input)?;
            policy.verify(&keys(&authority_keys)?, quorum)?;
            println!(
                "{}",
                serde_json::json!({ "generation": policy.generation, "digest": hex::encode(policy.digest()), "retired_identities": policy.revoked.len(), "policy_verified": true })
            );
        }
    }
    Ok(())
}
