#![no_main]
use anonguard::crypto::hybrid_identity::{mlkem768_public_is_canonical, HybridPublicKey};
use anonguard::crypto::identity::{Signature, SigningKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    // Raw decoders, including both bounded and wrong-length inputs.
    let _ = HybridPublicKey::decode(data);
    let _ = Signature::from_slice(data);
    let _ = mlkem768_public_is_canonical(data);
    // Generate a valid proof once so mutations reach cryptographic verification
    // rather than requiring libFuzzer to invent a valid identity header/signature.
    static FIXTURE: OnceLock<(SigningKey, Vec<u8>)> = OnceLock::new();
    let (key, proof) = FIXTURE.get_or_init(|| {
        let key = SigningKey::from_bytes(&[91; 32]);
        let proof = key.sign(b"owned-fuzz-transcript").to_bytes();
        (key, proof)
    });
    let mut mutated = proof.clone();
    for pair in data.as_chunks::<3>().0.iter().take(32) {
        let index = u16::from_be_bytes([pair[0], pair[1]]) as usize % mutated.len();
        mutated[index] ^= pair[2];
    }
    if let Ok(signature) = Signature::from_slice(&mutated) {
        let _ = key
            .verifying_key()
            .verify_strict(b"owned-fuzz-transcript", &signature);
        // Wrong transcript must never authenticate even an untouched valid proof.
        assert!(key
            .verifying_key()
            .verify_strict(b"wrong-transcript", &signature)
            .is_err());
    }
    let mut kem = [0u8; 1184];
    let count = data.len().min(kem.len());
    kem[..count].copy_from_slice(&data[..count]);
    let _ = mlkem768_public_is_canonical(&kem);
});
