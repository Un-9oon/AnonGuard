#![no_main]
use anonguard::core::revocation::{RevocationPolicy, MAX_POLICY_BYTES};
use anonguard::crypto::identity::SigningKey;
use anonguard::crypto::identity::VerifyingKey;
use libfuzzer_sys::fuzz_target;
use std::{collections::HashMap, sync::OnceLock};

fuzz_target!(|data: &[u8]| {
    if data.len() as u64 > MAX_POLICY_BYTES {
        return;
    }
    if let Ok(policy) = serde_json::from_slice::<RevocationPolicy>(data) {
        if policy.validate_shape().is_ok() {
            let _ = policy.digest();
            static KEYS: OnceLock<HashMap<String, VerifyingKey>> = OnceLock::new();
            let keys = KEYS.get_or_init(|| {
                (1..=4)
                    .map(|seed| {
                        (
                            format!("a{}", seed - 1),
                            SigningKey::from_bytes(&[seed; 32]).verifying_key(),
                        )
                    })
                    .collect()
            });
            let _ = policy.verify(keys, 3);
        }
    }
});
