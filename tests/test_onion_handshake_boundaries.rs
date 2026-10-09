//! Malformed framing and malicious pinned relays must fail hybrid circuit setup.
use anonguard::onion::{
    cell::{CellCommand, OnionCell, PAYLOAD_SIZE},
    circuit::{
        build_create_cell, decode_extend_payload, encode_extend_payload, handle_create_cell,
        process_created_cell, CircuitError, MAX_HOPS,
    },
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
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
    let mut transcript = b"AnonGuard-handshake-v4".to_vec();
    transcript.extend_from_slice(&79u32.to_be_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&pin);
    transcript.extend_from_slice(&[0; 32]);
    transcript.extend_from_slice(public.as_bytes());
    transcript.extend_from_slice(&encoded);
    transcript.extend_from_slice(&response.payload[128..1216]);
    response.payload[64..128].copy_from_slice(&identity.sign(&transcript).to_bytes());
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
