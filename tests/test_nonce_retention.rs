//! Replay defenses must retain accepted proofs through their complete validity window.
use anonguard::mesh::sybil::{solve_pow_bounded, verify_pow, NonceRegistry};

#[test]
fn future_dated_proof_cannot_replay_at_its_last_valid_second() {
    let registry = NonceRegistry::new();
    let nonce = solve_pow_bounded("future-proof", 1300, 8).unwrap();
    assert!(verify_pow("future-proof", 1300, nonce, 8, 1000));
    assert!(!registry.check_and_record("future-proof", nonce, 1000));
    assert!(verify_pow("future-proof", 1300, nonce, 8, 1600));
    assert!(
        registry.check_and_record("future-proof", nonce, 1600),
        "An accepted proof remained valid after its replay record was discarded"
    );
}

#[test]
fn registry_exhaustion_rejects_admission_without_forgetting_live_proofs() {
    let registry = NonceRegistry::new();
    assert!(!registry.check_and_record("budget", 0, 900));
    for nonce in 1..100_000 {
        assert!(!registry.check_and_record("budget", nonce, 1000));
    }
    assert!(
        registry.check_and_record("budget", 0, 1000),
        "Capacity pressure discarded the oldest still-valid replay record"
    );
    assert!(registry.check_and_record("budget", 100_000, 1000));
    assert!(registry.check_and_record("budget", 0, 1000));
    assert!(
        !registry.check_and_record("budget", 100_000, 1601),
        "Expired state must release capacity for new proofs"
    );
}

#[test]
fn invalid_identity_sizes_cannot_consume_replay_storage() {
    let registry = NonceRegistry::new();
    assert!(registry.check_and_record("", 1, 1000));
    assert!(registry.check_and_record(&"n".repeat(129), 1, 1000));
    assert!(!registry.check_and_record("valid", 1, 1000));
    assert!(registry.check_and_record("valid", 1, 1000));
}

#[test]
fn clock_rollback_cannot_resurrect_a_purged_proof() {
    let registry = NonceRegistry::new();
    let nonce = solve_pow_bounded("rollback", 1000, 8).unwrap();
    assert!(verify_pow("rollback", 1000, nonce, 8, 700));
    assert!(!registry.check_and_record("rollback", nonce, 700));
    assert!(!verify_pow("rollback", 1000, nonce, 8, 1301));
    assert!(!registry.check_and_record("new-proof", 1, 1301));
    assert!(verify_pow("rollback", 1000, nonce, 8, 1300));
    assert!(registry.check_and_record("rollback", nonce, 1300));
    assert!(!registry.check_and_record("new-proof", 2, 1301));
}
