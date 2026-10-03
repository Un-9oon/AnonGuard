use anonguard::mesh::authority::DirectoryAuthority;
use anonguard::mesh::consensus::RelayDescriptor;
use anonguard::mesh::sybil::{current_timestamp_secs, solve_pow_bounded};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[tokio::test]
async fn test_direct_registration_rejects_pow_replay() {
    let test_difficulty = 8;
    let mut auth = DirectoryAuthority::with_difficulty(
        "auth-replay".to_string(),
        "127.0.0.1:19202".to_string(),
        test_difficulty,
    );
    auth.allow_unauthenticated_registration = true;

    let now = current_timestamp_secs();
    let nonce = solve_pow_bounded("relay-replay-test", now, test_difficulty).unwrap();

    let mut desc1 = RelayDescriptor::new(
        "relay-replay-test".to_string(),
        "1.1.1.1".to_string(),
        9001,
        [1u8; 32],
        [0u8; 32],
        false,
        nonce,
        now,
    );
    let relay_key1 = SigningKey::generate(&mut OsRng);
    desc1.sign_with_key(&relay_key1);

    // First registration should succeed
    let res1 = auth.register_relay(desc1.clone()).await;
    assert!(res1.is_ok(), "First registration must succeed");

    // Second registration with the SAME nonce but different key/time/etc must fail
    let mut desc2 = RelayDescriptor::new(
        "relay-replay-test".to_string(),
        "1.1.1.2".to_string(),
        9002,
        [2u8; 32],
        [0u8; 32],
        false,
        nonce, // Reusing the same nonce!
        now,
    );
    let relay_key2 = SigningKey::generate(&mut OsRng);
    desc2.sign_with_key(&relay_key2);

    let res2 = auth.register_relay(desc2).await;
    assert!(
        res2.is_err(),
        "Second registration with replayed PoW nonce must fail"
    );
}
