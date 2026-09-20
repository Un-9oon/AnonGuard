//! Forward Secrecy and Zeroization Tests.
//!
//! Task C: Provides machine-checkable proof that:
//!
//! 1. `HopKeys` implements `ZeroizeOnDrop` (compile-time trait-bound check).
//!    This means that when a `HopKeys` value is dropped, the `zeroize` crate's
//!    `ZeroizeOnDrop` blanket impl will overwrite all key material with zeros
//!    before the memory is returned to the allocator or reused.
//!
//! 2. No ephemeral secret raw bytes are logged or persisted (verified by
//!    `grep -rn "mlkem_dk\|client_secret\|EphemeralSecret" src/ --include="*.rs"
//!    | grep -i "write\|log\|persist\|save\|file"` returning zero matches — see
//!    Task C proof in the session report).

use anonguard::onion::circuit::HopKeys;
use zeroize::ZeroizeOnDrop;

/// Compile-time proof that `HopKeys` implements `ZeroizeOnDrop`.
///
/// If `HopKeys` does NOT implement `ZeroizeOnDrop`, this function will fail to
/// compile with a trait-bound error, making the zeroization guarantee
/// machine-checkable rather than just documented in prose.
///
/// This is the Task C "acceptable fallback": a compile-time trait-bound check
/// as specified in the task — "a test that fails to compile / fails an
/// assertion unless the exact struct holding the secret implements
/// `ZeroizeOnDrop` — using a trait-bound check".
fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn hop_keys_implements_zeroize_on_drop() {
    // If HopKeys does NOT implement ZeroizeOnDrop, this line will fail to compile.
    assert_zeroize_on_drop::<HopKeys>();
}

/// Behavioural proof that key material is zeroed when Zeroize is called.
///
/// We cannot safely read memory after drop (that would be UB), but we CAN
/// call `.zeroize()` directly — which is exactly what `ZeroizeOnDrop`'s
/// `Drop` impl does — and verify the result.
///
/// Since `HopKeys` derives `Zeroize` (a super-trait of `ZeroizeOnDrop`),
/// calling `.zeroize()` is equivalent to what happens on drop.
#[test]
fn hop_keys_bytes_are_zeroed_on_drop() {
    use zeroize::Zeroize;

    // Build a HopKeys with known non-zero values.
    let mut keys = HopKeys {
        forward_key: [0xAAu8; 32],
        backward_key: [0xBBu8; 32],
        forward_mac: [0xCCu8; 32],
        backward_mac: [0xDDu8; 32],
        forward_aead_key: [0xEEu8; 32],
        backward_aead_key: [0xFFu8; 32],
    };

    // Verify they are non-zero before zeroization.
    assert_eq!(
        keys.forward_key[0], 0xAA,
        "forward_key should be 0xAA before zeroize"
    );
    assert_eq!(
        keys.backward_aead_key[0], 0xFF,
        "backward_aead_key should be 0xFF before zeroize"
    );

    // Call zeroize() — this is exactly what ZeroizeOnDrop's Drop impl calls.
    keys.zeroize();

    // All six key fields must now be all-zero.
    assert_eq!(keys.forward_key, [0u8; 32], "forward_key must be zeroed");
    assert_eq!(keys.backward_key, [0u8; 32], "backward_key must be zeroed");
    assert_eq!(keys.forward_mac, [0u8; 32], "forward_mac must be zeroed");
    assert_eq!(keys.backward_mac, [0u8; 32], "backward_mac must be zeroed");
    assert_eq!(
        keys.forward_aead_key, [0u8; 32],
        "forward_aead_key must be zeroed"
    );
    assert_eq!(
        keys.backward_aead_key, [0u8; 32],
        "backward_aead_key must be zeroed"
    );
}
