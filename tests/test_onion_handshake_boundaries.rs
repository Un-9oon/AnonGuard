//! Malformed framing and malicious pinned relays must fail hybrid circuit setup.
use anonguard::crypto::identity::{SigningKey, VerifyingKey};
use anonguard::onion::{
    cell::{CellCommand, OnionCell, PAYLOAD_SIZE},
    circuit::{
        build_create_cell, decode_extend_payload, encode_extend_payload, handle_create_cell,
        process_created_cell, CircuitError, MAX_HOPS,
    },
};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[test]
fn malformed_create_cells_never_establish_a_relay_hop() {
    let identity = SigningKey::from_bytes(&[81; 32]);
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let (_, kem_public) = MlKem768::generate(&mut OsRng);
    let create = build_create_cell(77, &public, &kem_public, 0).unwrap();
    for case in 0..5 {
        let mut malformed = create.clone();
        match case {
            0 => malformed.command = CellCommand::Dummy,
            1 => malformed.length -= 1,
            2 => malformed.payload[1221] = 2,
            3 => malformed.payload[0] = MAX_HOPS as u8,
            _ => malformed.payload[1..33].fill(0),
        }
        assert!(handle_create_cell(&malformed, &identity).is_err());
    }
    assert!(handle_create_cell(&create, &identity).is_ok());
}

#[test]
fn malformed_responses_and_invalid_pins_do_not_produce_client_keys() {
    let identity = SigningKey::from_bytes(&[82; 32]);
    for case in 0..4 {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let (kem_secret, kem_public) = MlKem768::generate(&mut OsRng);
        let encoded: [u8; 1184] = kem_public.as_bytes().as_slice().try_into().unwrap();
        let create = build_create_cell(78, &public, &kem_public, 0).unwrap();
        let (_, mut response) = handle_create_cell(&create, &identity).unwrap();
        let mut pin = identity.verifying_key().to_bytes();
        match case {
            0 => response.command = CellCommand::Dummy,
            1 => response.length = 1215,
            2 => {
                pin = (0..=255)
                    .map(|byte| [byte; 32])
                    .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
                    .unwrap();
                response.payload[32..64].copy_from_slice(&pin);
            }
            _ => pin.fill(0),
        }
        let error = process_created_cell(
            &response,
            secret,
            public.as_bytes(),
            &kem_secret,
            &encoded,
            &pin,
            78,
            0,
        )
        .err()
        .expect("Malformed response produced traffic keys");
        assert!(matches!(
            error,
            CircuitError::ParseError(_)
                | CircuitError::PayloadTooShort
                | CircuitError::UnpinnedRelay
        ));
    }
}

#[test]
fn even_a_valid_relay_signature_cannot_authorize_zero_dh() {
    let identity = SigningKey::from_bytes(&[83; 32]);
    let pin = identity.verifying_key().to_bytes();
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let (kem_secret, kem_public) = MlKem768::generate(&mut OsRng);
    let encoded: [u8; 1184] = kem_public.as_bytes().as_slice().try_into().unwrap();
    let create = build_create_cell(79, &public, &kem_public, 0).unwrap();
    let (_, mut response) = handle_create_cell(&create, &identity).unwrap();
    response.payload[..32].fill(0);
    // The malicious pinned relay owns this identity and can sign its zero point.
    let mut transcript = b"AnonGuard-handshake-v6".to_vec();
    transcript.extend_from_slice(&79u32.to_be_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&pin);
    transcript.extend_from_slice(&[0; 32]);
    transcript.extend_from_slice(public.as_bytes());
    transcript.extend_from_slice(&encoded);
    transcript.extend_from_slice(
        &response.payload[64 + anonguard::crypto::identity::PROOF_SIZE
            ..64 + anonguard::crypto::identity::PROOF_SIZE + 1088],
    );
    response.payload[64..64 + anonguard::crypto::identity::PROOF_SIZE]
        .copy_from_slice(&identity.sign(&transcript).to_bytes());
    let error = process_created_cell(
        &response,
        secret,
        public.as_bytes(),
        &kem_secret,
        &encoded,
        &pin,
        79,
        0,
    )
    .err()
    .expect("Zero DH point produced traffic keys");
    assert!(
        error.to_string().contains("Non-contributory DH"),
        "The valid signature must pass before DH rejection: {error}"
    );
}

#[test]
fn truncated_extend_hosts_and_invalid_wire_lengths_are_rejected() {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let (_, kem_public) = MlKem768::generate(&mut OsRng);
    assert!(encode_extend_payload(&"a".repeat(256), 9001, &public, &kem_public, 1).is_err());
    let mut encoded =
        encode_extend_payload("relay.example", 9001, &public, &kem_public, 1).unwrap();
    encoded[2] = 0xff;
    assert!(matches!(
        decode_extend_payload(&encoded),
        Err(CircuitError::ParseError(_))
    ));
    encoded[1] = 255;
    assert!(matches!(
        decode_extend_payload(&encoded),
        Err(CircuitError::PayloadTooShort)
    ));
    let mut wire = OnionCell::new(80, 0, CellCommand::Create, 0, &[])
        .unwrap()
        .serialize();
    wire[8] = 255;
    assert!(OnionCell::parse(&wire).is_err());
    wire[8] = CellCommand::Create as u8;
    wire[11..13].copy_from_slice(&((PAYLOAD_SIZE + 1) as u16).to_be_bytes());
    assert!(OnionCell::parse(&wire).is_err());
}

#[test]
fn extend_framing_and_hop_indices_are_exact_without_u8_wraparound() {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let (_, kem_public) = MlKem768::generate(&mut OsRng);
    let valid =
        encode_extend_payload("relay.example", 9001, &public, &kem_public, MAX_HOPS - 1).unwrap();
    assert_eq!(decode_extend_payload(&valid).unwrap().4, MAX_HOPS - 1);
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(matches!(
        decode_extend_payload(&trailing),
        Err(CircuitError::ParseError(_))
    ));
    for hop in [MAX_HOPS, 255, 256, usize::MAX] {
        assert!(matches!(
            encode_extend_payload("relay.example", 9001, &public, &kem_public, hop),
            Err(CircuitError::HopIndexOutOfRange(_))
        ));
        assert!(matches!(
            build_create_cell(90, &public, &kem_public, hop),
            Err(CircuitError::HopIndexOutOfRange(_))
        ));
    }
    let identity = SigningKey::from_bytes(&[85; 32]);
    let (kem_secret, kem_public) = MlKem768::generate(&mut OsRng);
    let encoded: [u8; 1184] = kem_public.as_bytes().as_slice().try_into().unwrap();
    let create = build_create_cell(92, &public, &kem_public, 0).unwrap();
    let (_, response) = handle_create_cell(&create, &identity).unwrap();
    for hop in [MAX_HOPS, 256, usize::MAX] {
        assert!(matches!(
            process_created_cell(
                &response,
                EphemeralSecret::random_from_rng(OsRng),
                public.as_bytes(),
                &kem_secret,
                &encoded,
                &identity.verifying_key().to_bytes(),
                92,
                hop
            ),
            Err(CircuitError::HopIndexOutOfRange(_))
        ));
    }
    for hop in [MAX_HOPS as u8, 255] {
        let mut invalid = valid.clone();
        invalid[0] = hop;
        assert!(matches!(
            decode_extend_payload(&invalid),
            Err(CircuitError::HopIndexOutOfRange(_))
        ));
    }
}

#[test]
fn created_dual_signature_components_are_individually_mandatory() {
    use anonguard::crypto::{hybrid_identity::PUBLIC_KEY_SIZE, identity::PROOF_SIZE};
    let identity = SigningKey::from_bytes(&[84; 32]);
    for case in 0..6 {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let (kem_secret, kem_public) = MlKem768::generate(&mut OsRng);
        let encoded: [u8; 1184] = kem_public.as_bytes().as_slice().try_into().unwrap();
        let create = build_create_cell(91, &public, &kem_public, 0).unwrap();
        let (_, mut response) = handle_create_cell(&create, &identity).unwrap();
        let signature = 64 + PUBLIC_KEY_SIZE;
        match case {
            0 => response.payload[signature + 8..signature + 72].fill(0),
            1 => response.payload[signature + 72..64 + PROOF_SIZE].fill(0),
            2 => response.payload[signature + 8] ^= 1,
            3 => response.payload[signature + 72] ^= 1,
            4 => response.payload[64 + 8] ^= 1, // Classical public-key substitution.
            _ => response.payload[64 + 40] ^= 1, // PQ public-key substitution.
        }
        assert!(
            process_created_cell(
                &response,
                secret,
                public.as_bytes(),
                &kem_secret,
                &encoded,
                &identity.verifying_key().to_bytes(),
                91,
                0
            )
            .is_err(),
            "Component tampering case {case} yielded hop keys"
        );
    }
}

#[test]
fn proofs_cannot_mix_public_key_components_or_drop_a_signature_half() {
    use anonguard::crypto::{
        hybrid_identity::{HybridSigningKey, PUBLIC_KEY_SIZE},
        identity::{Signature, PROOF_SIZE},
    };
    let first = SigningKey::from_hybrid(HybridSigningKey::from_seeds(&[17; 64]));
    let mut seeds = [17; 64];
    seeds[32] ^= 1; // Preserve Ed identity but change its independent PQ component.
    let second = SigningKey::from_hybrid(HybridSigningKey::from_seeds(&seeds));
    seeds = [17; 64];
    seeds[0] ^= 1; // Preserve PQ identity while changing its classical component.
    let third = SigningKey::from_hybrid(HybridSigningKey::from_seeds(&seeds));
    let message = b"v6 boundary regression";
    let proof = first.sign(message).to_bytes();

    assert_ne!(first.verifying_key(), second.verifying_key());
    first
        .verifying_key()
        .verify_strict(message, &Signature::from_slice(&proof).unwrap())
        .unwrap();
    for truncated in [
        &proof[..PUBLIC_KEY_SIZE + 72],
        &proof[..PROOF_SIZE - 1],
        &proof[PUBLIC_KEY_SIZE..],
    ] {
        assert!(Signature::from_slice(truncated).is_err());
    }
    for substituted in [&second, &third] {
        let other = substituted.sign(message).to_bytes();
        let mut mixed = proof.clone();
        mixed[..PUBLIC_KEY_SIZE].copy_from_slice(&other[..PUBLIC_KEY_SIZE]);
        let mixed = Signature::from_slice(&mixed).unwrap();
        assert!(first
            .verifying_key()
            .verify_strict(message, &mixed)
            .is_err());
        // Re-pinning the substituted key cannot authorize old signatures: the
        // complete composite-key fingerprint is in both signed transcripts.
        assert!(substituted
            .verifying_key()
            .verify_strict(message, &mixed)
            .is_err());
    }
}
