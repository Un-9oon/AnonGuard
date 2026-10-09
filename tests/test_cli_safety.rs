use std::process::Command;

fn refuses(args: &[&str], message: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_anonguard-daemon"))
        .args(args)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(message), "unexpected error: {error}");
}

#[test]
fn invalid_startup_options_are_rejected_before_network_or_key_changes() {
    refuses(&["--onion"], "Onion mode requires");
    refuses(&["--jitter-lambda", "NaN"], "finite and positive");
    refuses(&["--rmt-ensemble", "unknown"], "must be goe or gue");
    refuses(&["--authorities", "127.0.0.1:9000"], "require pinned keys");
}

#[cfg(target_os = "linux")]
#[test]
fn strict_firewall_requires_explicit_installation() {
    refuses(
        &["--strict-fail-closed"],
        "requires --enable-firewall-killswitch",
    );
}

#[test]
fn authority_endpoints_require_matching_independent_pins() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let unrelated = format!("other:{public}");
    refuses(
        &[
            "--authorities",
            "auth@127.0.0.1:9000",
            "--authority-keys",
            &unrelated,
        ],
        "matching pinned key",
    );
    let aliases = format!("a:{public},b:{public}");
    refuses(
        &[
            "--authorities",
            "a@127.0.0.1:9000,b@127.0.0.1:9001",
            "--authority-keys",
            &aliases,
            "--quorum-threshold",
            "2",
        ],
        "distinct signing keys",
    );
}

#[test]
fn padded_profiles_refuse_legacy_customization_and_missing_onion() {
    refuses(&["--padded-sessions"], "--onion");
    for legacy in ["--jitter", "--chaos", "--rmt-morphing", "--chaffing"] {
        refuses(&["--onion", "--padded-sessions", legacy], "cannot be used");
    }
    refuses(
        &[
            "--onion",
            "--padded-sessions",
            "--privacy-profile",
            "custom",
        ],
        "invalid value",
    );
}
