#![no_main]
use anonguard::core::revocation::{RevocationPolicy, MAX_POLICY_BYTES};
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() as u64 > MAX_POLICY_BYTES {
        return;
    }
    if let Ok(policy) = serde_json::from_slice::<RevocationPolicy>(data) {
        if policy.validate_shape().is_ok() {
            let _ = policy.digest();
            let keys = (1..=4)
                .map(|seed| {
                    (
                        format!("a{}", seed - 1),
                        SigningKey::from_bytes(&[seed; 32]).verifying_key(),
                    )
                })
                .collect();
            let _ = policy.verify(&keys, 3);
        }
    }
});
