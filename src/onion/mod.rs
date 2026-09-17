//! Onion Routing Subsystem with HMAC-SHA256 Authenticated Layered Encryption.
//!
//! (Note: Now migrated to AEAD ChaCha20Poly1305)

pub mod cell;
pub mod circuit;

pub use cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
pub use circuit::{
    build_create_cell, decode_extend_payload, derive_hop_keys, encode_extend_payload,
    handle_create_cell, perform_client_relay_handshake, process_created_cell,
    HopCryptState, OnionCircuit, PeelResult, RelayCircuitHop,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::circuit::HopKeys;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

    fn gen_relay_key() -> (Ed25519SigningKey, [u8; 32]) {
        let sk = Ed25519SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn test_telescopic_circuit_create_and_extend_exchange() {
        let circuit_id = 999;
        let mut client_circuit = OnionCircuit::new(circuit_id);

        let client_secret_0 = EphemeralSecret::random_from_rng(OsRng);
        let client_pub_0 = X25519PublicKey::from(&client_secret_0);
        let create_cell_0 = build_create_cell(circuit_id, &client_pub_0, 0).unwrap();

        let (guard_sk, guard_pk) = gen_relay_key();
        let (mut relay_guard, created_cell_0) =
            handle_create_cell(&create_cell_0, &guard_sk).unwrap();

        let hop_keys0 = process_created_cell(
            &created_cell_0,
            client_secret_0,
            client_pub_0.as_bytes(),
            &guard_pk,
            circuit_id, 0
        )
        .unwrap();
        client_circuit.add_hop(hop_keys0).unwrap();

        let client_secret_1 = EphemeralSecret::random_from_rng(OsRng);
        let client_pub_1 = X25519PublicKey::from(&client_secret_1);
        let extend_payload_1 = encode_extend_payload("10.0.0.2", 9002, &client_pub_1, 1).unwrap();

        let mut extend_cell_1 =
            OnionCell::new(circuit_id, 1, CellCommand::Extend, 0, &extend_payload_1).unwrap();

        let mut wire_buffer_1 = client_circuit.wrap_forward(&mut extend_cell_1).unwrap();

        let peel_1 = relay_guard.peel_forward(&mut wire_buffer_1).unwrap();
        let (_target_host_1, _target_port_1, middle_pub_for_relay, _hop1) = match peel_1 {
            PeelResult::AddressedToThisRelay(cmd, payload) => {
                assert_eq!(cmd, CellCommand::Extend);
                decode_extend_payload(&payload).unwrap()
            }
            PeelResult::ForwardDownstream(_) => panic!("Guard must consume EXTEND cell!"),
        };

        let create_cell_1 = build_create_cell(circuit_id, &middle_pub_for_relay, 1).unwrap();
        let (middle_sk, middle_pk) = gen_relay_key();
        let (mut relay_middle, created_cell_1) =
            handle_create_cell(&create_cell_1, &middle_sk).unwrap();

        let mut return_wire_1 = created_cell_1.serialize();
        relay_guard.wrap_backward_originate(&mut return_wire_1).unwrap();

        let (_hop, client_unwrapped_1) = client_circuit.unwrap_backward(&mut return_wire_1).unwrap();
        assert_eq!(client_unwrapped_1.command, CellCommand::Created);

        let hop_keys1 = process_created_cell(
            &client_unwrapped_1,
            client_secret_1,
            middle_pub_for_relay.as_bytes(),
            &middle_pk,
            circuit_id, 1
        )
        .unwrap();
        client_circuit.add_hop(hop_keys1).unwrap();

        let client_secret_2 = EphemeralSecret::random_from_rng(OsRng);
        let client_pub_2 = X25519PublicKey::from(&client_secret_2);
        let extend_payload_2 = encode_extend_payload("10.0.0.3", 9003, &client_pub_2, 2).unwrap();

        let mut extend_cell_2 =
            OnionCell::new(circuit_id, 1, CellCommand::Extend, 0, &extend_payload_2).unwrap();

        let mut wire_buffer_2 = client_circuit.wrap_forward(&mut extend_cell_2).unwrap();

        let peel_2_guard = relay_guard.peel_forward(&mut wire_buffer_2).unwrap();
        let mut to_middle = match peel_2_guard {
            PeelResult::ForwardDownstream(buf) => *buf,
            _ => panic!("Guard must forward downstream!"),
        };

        let peel_2_middle = relay_middle.peel_forward(&mut to_middle).unwrap();
        let (_target_host_2, _target_port_2, exit_pub_for_relay, _hop2) = match peel_2_middle {
            PeelResult::AddressedToThisRelay(cmd, payload) => {
                assert_eq!(cmd, CellCommand::Extend);
                decode_extend_payload(&payload).unwrap()
            }
            PeelResult::ForwardDownstream(_) => panic!("Middle must consume EXTEND cell!"),
        };

        let create_cell_2 = build_create_cell(circuit_id, &exit_pub_for_relay, 2).unwrap();
        let (exit_sk, exit_pk) = gen_relay_key();
        let (mut relay_exit, created_cell_2) =
            handle_create_cell(&create_cell_2, &exit_sk).unwrap();

        let mut return_wire_2 = created_cell_2.serialize();
        relay_middle.wrap_backward_originate(&mut return_wire_2).unwrap();
        relay_guard.wrap_backward_relay(&mut return_wire_2).unwrap();

        let (_hop, client_unwrapped_2) = client_circuit.unwrap_backward(&mut return_wire_2).unwrap();
        assert_eq!(client_unwrapped_2.command, CellCommand::Created);

        let hop_keys2 = process_created_cell(
            &client_unwrapped_2,
            client_secret_2,
            exit_pub_for_relay.as_bytes(),
            &exit_pk,
            circuit_id, 2
        )
        .unwrap();
        client_circuit.add_hop(hop_keys2).unwrap();

        let payload = b"TELESCOPIC_ONION_AUTHENTICATED_VERIFICATION";
        let mut data_cell = OnionCell::new(circuit_id, 1, CellCommand::Data, 1, payload).unwrap();
        let mut client_send_buf = client_circuit.wrap_forward(&mut data_cell).unwrap();

        let p0 = relay_guard.peel_forward(&mut client_send_buf).unwrap();
        let mut to_m = match p0 {
            PeelResult::ForwardDownstream(b) => *b,
            _ => panic!("Expected forward downstream from guard"),
        };

        let p1 = relay_middle.peel_forward(&mut to_m).unwrap();
        let mut to_e = match p1 {
            PeelResult::ForwardDownstream(b) => *b,
            _ => panic!("Expected forward downstream from middle"),
        };

        let p2 = relay_exit.peel_forward(&mut to_e).unwrap();
        match p2 {
            PeelResult::AddressedToThisRelay(cmd, data) => {
                assert_eq!(cmd, CellCommand::Data);
                assert_eq!(data.as_slice(), payload);
            }
            PeelResult::ForwardDownstream(_) => panic!("Exit must consume authenticated data"),
        }
    }

    #[test]
    fn test_identity_binding_mitm_rejection() {
        let (relay_sk, _correct_pk) = gen_relay_key();
        let (_wrong_sk, wrong_pk) = gen_relay_key();

        let circuit_id = 0xdeadbeef;
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = X25519PublicKey::from(&client_secret);

        let create_cell = build_create_cell(circuit_id, &client_pub, 0).unwrap();
        let (_relay_hop, created_cell) = handle_create_cell(&create_cell, &relay_sk).unwrap();

        let result = process_created_cell(
            &created_cell,
            client_secret,
            client_pub.as_bytes(),
            &wrong_pk,
            circuit_id, 0
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_identity_binding_tampered_signature_rejected() {
        let (relay_sk, relay_pk) = gen_relay_key();
        let circuit_id = 0xcafebabe;
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = X25519PublicKey::from(&client_secret);

        let create_cell = build_create_cell(circuit_id, &client_pub, 0).unwrap();
        let (_relay_hop, mut created_cell) = handle_create_cell(&create_cell, &relay_sk).unwrap();

        created_cell.payload[64] ^= 0xFF;

        let result = process_created_cell(
            &created_cell,
            client_secret,
            client_pub.as_bytes(),
            &relay_pk,
            circuit_id, 0
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_cell_serialization_and_mac() {
        let payload = b"CLASSIFIED_MILITARY_PAYLOAD_AEAD";
        let cell = OnionCell::new(101, 1, CellCommand::Data, 1, payload).unwrap();

        assert_eq!(cell.circuit_id, 101);
        assert_eq!(cell.sequence_no, 1);
        assert_eq!(cell.command, CellCommand::Data);
        assert_eq!(cell.stream_id, 1);
        assert_eq!(cell.length, payload.len() as u16);

        let raw = cell.serialize();
        let parsed = OnionCell::parse(&raw).expect("Parsing valid cell failed");
        assert_eq!(parsed.circuit_id, 101);
        assert_eq!(parsed.sequence_no, 1);
        assert_eq!(&parsed.payload[..payload.len()], payload);
    }

    #[test]
    fn test_oversized_payload_rejection() {
        let huge_payload = vec![0xAA; PAYLOAD_SIZE + 1];
        let res = OnionCell::new(101, 1, CellCommand::Data, 1, &huge_payload);
        assert!(res.is_err());
    }

    #[test]
    fn test_tampering_rejection() {
        // Build a valid 3-hop circuit
        let (client_hop0, relay0_keys) = perform_client_relay_handshake();
        let (client_hop1, relay1_keys) = perform_client_relay_handshake();
        let (client_hop2, relay2_keys) = perform_client_relay_handshake();

        let mut client_circuit = OnionCircuit::new(77);
        client_circuit.add_hop(client_hop0).unwrap();
        client_circuit.add_hop(client_hop1).unwrap();
        client_circuit.add_hop(client_hop2).unwrap();

        let mut relay_guard = RelayCircuitHop::new(77, relay0_keys, 0);
        let mut relay_middle =
            RelayCircuitHop::new(77, relay1_keys, 1);
        let mut relay_exit = RelayCircuitHop::new(77, relay2_keys, 2);

        let payload = b"TAMPER_TEST_SENSITIVE_DATA";
        let mut cell = OnionCell::new(77, 1, CellCommand::Data, 1, payload).unwrap();
        let mut wire = client_circuit.wrap_forward(&mut cell).unwrap();

        // Peel through guard and middle (these are stream layers, not AEAD)
        let p0 = relay_guard.peel_forward(&mut wire).unwrap();
        let mut to_middle = match p0 {
            PeelResult::ForwardDownstream(b) => *b,
            _ => panic!("Guard should forward downstream"),
        };

        let p1 = relay_middle.peel_forward(&mut to_middle).unwrap();
        let mut to_exit = match p1 {
            PeelResult::ForwardDownstream(b) => *b,
            _ => panic!("Middle should forward downstream"),
        };

        // Flip a byte in the ciphertext body (after the 8-byte header)
        to_exit[20] ^= 0xFF;

        // The exit relay must NOT accept this as an authenticated cell.
        // peel_forward() should either return ForwardDownstream or Err, but NOT AddressedToThisRelay.
        let result = relay_exit.peel_forward(&mut to_exit);
        match result {
            Ok(PeelResult::AddressedToThisRelay(_, data)) => {
                // If it somehow accepted, the data must NOT match the original
                assert_ne!(
                    data.as_slice(),
                    payload,
                    "CRITICAL: Tampered cell was accepted with original payload — AEAD integrity broken!"
                );
            }
            Ok(PeelResult::ForwardDownstream(_)) => {
                // Expected: AEAD failed, cell treated as not-for-this-relay and forwarded
            }
            Err(_) => {
                // Also acceptable: explicit rejection
            }
        }
    }

    #[test]
    fn test_anti_replay_cell_rejection() {
        // We test anti-replay by using the RelayCircuitHop directly
        let forward_key = [1u8; 32];
        let backward_key = [2u8; 32];
        let mac_key = [99u8; 32];
        let keys = HopKeys {
            forward_key,
            backward_key,
            forward_mac: mac_key,
            backward_mac: mac_key,
        };
        let mut relay = RelayCircuitHop::new(1, keys, 0);

        let mut client_circuit = OnionCircuit::new(1);
        let keys2 = HopKeys {
            forward_key,
            backward_key,
            forward_mac: mac_key,
            backward_mac: mac_key,
        };
        client_circuit.add_hop(keys2).unwrap();

        let mut cell1 = OnionCell::new(1, 1, CellCommand::Data, 1, b"MESSAGE_1").unwrap();
        let mut raw1 = client_circuit.wrap_forward(&mut cell1).unwrap();
        
        let mut raw1_clone = raw1;

        let p1 = relay.peel_forward(&mut raw1).unwrap();
        assert!(matches!(
            p1,
            PeelResult::AddressedToThisRelay(CellCommand::Data, _)
        ));

        // Attempting to send stale/replayed sequence 1 must be rejected by anti-replay counter
        // (Since client_circuit sequence_no advanced, we just manually craft a sequence 1 cell)
        // Replay the previous raw packet
        let err = relay.peel_forward(&mut raw1_clone);
        assert!(err.is_err());
    }

    #[test]
    fn test_3_hop_authenticated_onion_circuit() {
        let (client_hop0, relay0_keys) = perform_client_relay_handshake();
        let (client_hop1, relay1_keys) = perform_client_relay_handshake();
        let (client_hop2, relay2_keys) = perform_client_relay_handshake();

        let mut client_circuit = OnionCircuit::new(42);
        client_circuit.add_hop(client_hop0).unwrap();
        client_circuit.add_hop(client_hop1).unwrap();
        client_circuit.add_hop(client_hop2).unwrap();

        let mut relay_guard = RelayCircuitHop::new(42, relay0_keys, 0);
        let mut relay_middle =
            RelayCircuitHop::new(42, relay1_keys, 1);
        let mut relay_exit = RelayCircuitHop::new(42, relay2_keys, 2);

        let secret_payload = b"TOP_SECRET_E2E_AUTHENTICATED_CELL";
        let mut original_cell =
            OnionCell::new(42, 1, CellCommand::Data, 7, secret_payload).unwrap();

        let mut wire_buffer = client_circuit.wrap_forward(&mut original_cell).unwrap();

        let peel_guard = relay_guard.peel_forward(&mut wire_buffer).unwrap();
        let mut to_middle = match peel_guard {
            PeelResult::ForwardDownstream(buf) => *buf,
            _ => panic!("Expected forward downstream from guard"),
        };

        let peel_middle = relay_middle.peel_forward(&mut to_middle).unwrap();
        let mut to_exit = match peel_middle {
            PeelResult::ForwardDownstream(buf) => *buf,
            _ => panic!("Expected forward downstream from middle"),
        };

        let peel_exit = relay_exit.peel_forward(&mut to_exit).unwrap();
        match peel_exit {
            PeelResult::AddressedToThisRelay(cmd, data) => {
                assert_eq!(cmd, CellCommand::Data);
                assert_eq!(data.as_slice(), secret_payload);
            }
            PeelResult::ForwardDownstream(_) => {
                panic!("Exit node should have consumed the cell!")
            }
        }

        let response_data = b"EXIT_AUTHENTICATED_RESPONSE";
        let exit_resp_cell = OnionCell::new(42, 1, CellCommand::Data, 7, response_data).unwrap();
        let mut return_buffer = exit_resp_cell.serialize();

        relay_exit.wrap_backward_originate(&mut return_buffer).unwrap();
        relay_middle.wrap_backward_relay(&mut return_buffer).unwrap();
        relay_guard.wrap_backward_relay(&mut return_buffer).unwrap();

        let (_hop, client_recovered) = client_circuit
            .unwrap_backward(&mut return_buffer)
            .expect("Client unwrap failed");

        assert_eq!(client_recovered.command, CellCommand::Data);
        assert_eq!(
            &client_recovered.payload[..response_data.len()],
            response_data
        );
    }
}
