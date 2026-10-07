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
