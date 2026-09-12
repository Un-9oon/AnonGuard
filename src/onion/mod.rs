//! Onion Routing Subsystem with Poly1305 Authenticated Layered Encryption.

pub mod cell;
pub mod circuit;

pub use cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
pub use circuit::{
    build_create_cell, decode_extend_payload, derive_hop_keys, encode_extend_payload,
    handle_create_cell, perform_client_relay_handshake, process_created_cell, HandshakeKeys,
    HopCryptState, OnionCircuit, PeelResult, RelayCircuitHop,
};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

    #[test]
    fn test_telescopic_circuit_create_and_extend_exchange() {
        let circuit_id = 999;
        let mut client_circuit = OnionCircuit::new(circuit_id);

        // --- STEP 1: Telescopic Hop 0 (Guard) Handshake ---
        let client_secret_0 = EphemeralSecret::random_from_rng(OsRng);
        let client_pub_0 = X25519PublicKey::from(&client_secret_0);
        let create_cell_0 = build_create_cell(circuit_id, &client_pub_0).unwrap();

        // Relay Guard handles CREATE cell
        let (mut relay_guard, created_cell_0) = handle_create_cell(&create_cell_0).unwrap();

        // Client processes CREATED cell
        let (fwd0, bwd0, mac0) = process_created_cell(&created_cell_0, client_secret_0).unwrap();
        client_circuit.add_hop(fwd0, bwd0, mac0);
        assert_eq!(client_circuit.hop_count(), 1);

        // --- STEP 2: Telescopic Hop 1 (Middle) Extension ---
        let client_secret_1 = EphemeralSecret::random_from_rng(OsRng);
        let client_pub_1 = X25519PublicKey::from(&client_secret_1);
        let extend_payload_1 = encode_extend_payload("10.0.0.2", 9002, &client_pub_1).unwrap();

        // Client creates EXTEND cell addressed to Hop 0 (mac0)
        let extend_cell_1 =
            OnionCell::new(circuit_id, CellCommand::Extend, 0, &extend_payload_1, &mac0).unwrap();

        // Client wraps forward through current hops (Hop 0)
        let mut wire_buffer_1 = client_circuit.wrap_forward(&extend_cell_1);

        // Guard peels forward -> addressed to Guard!
        let peel_1 = relay_guard.peel_forward(&mut wire_buffer_1).unwrap();
        let (_target_host_1, _target_port_1, middle_pub_for_relay) = match peel_1 {
            PeelResult::AddressedToThisRelay(cmd, payload) => {
                assert_eq!(cmd, CellCommand::Extend);
                decode_extend_payload(&payload).unwrap()
            }
            PeelResult::ForwardDownstream(_) => panic!("Guard must consume EXTEND cell!"),
        };

        // Guard forwards CREATE to Relay Middle
        let create_cell_1 = build_create_cell(circuit_id, &middle_pub_for_relay).unwrap();
        let (mut relay_middle, created_cell_1) = handle_create_cell(&create_cell_1).unwrap();

        // Guard wraps Relay Middle's CREATED cell backward towards client
        let mut return_wire_1 = created_cell_1.serialize();
        relay_guard.wrap_backward(&mut return_wire_1);

        // Client unwraps backward through circuit (Hop 0)
        let client_unwrapped_1 = client_circuit.unwrap_backward(&mut return_wire_1).unwrap();
        assert_eq!(client_unwrapped_1.command, CellCommand::Created);

        // Client processes CREATED cell to complete Hop 1
        let (fwd1, bwd1, mac1) =
            process_created_cell(&client_unwrapped_1, client_secret_1).unwrap();
        client_circuit.add_hop(fwd1, bwd1, mac1);
        assert_eq!(client_circuit.hop_count(), 2);

        // --- STEP 3: Telescopic Hop 2 (Exit) Extension ---
        let client_secret_2 = EphemeralSecret::random_from_rng(OsRng);
        let client_pub_2 = X25519PublicKey::from(&client_secret_2);
        let extend_payload_2 = encode_extend_payload("10.0.0.3", 9003, &client_pub_2).unwrap();

        // Client creates EXTEND cell addressed to Hop 1 (mac1)
        let extend_cell_2 =
            OnionCell::new(circuit_id, CellCommand::Extend, 0, &extend_payload_2, &mac1).unwrap();

        // Client wraps forward across Hop 1 then Hop 0
        let mut wire_buffer_2 = client_circuit.wrap_forward(&extend_cell_2);

        // Guard peels Hop 0 -> forwards downstream
        let peel_2_guard = relay_guard.peel_forward(&mut wire_buffer_2).unwrap();
        let mut to_middle = match peel_2_guard {
            PeelResult::ForwardDownstream(buf) => *buf,
            _ => panic!("Guard must forward downstream!"),
        };

        // Middle peels Hop 1 -> addressed to Middle!
        let peel_2_middle = relay_middle.peel_forward(&mut to_middle).unwrap();
        let (_target_host_2, _target_port_2, exit_pub_for_relay) = match peel_2_middle {
            PeelResult::AddressedToThisRelay(cmd, payload) => {
                assert_eq!(cmd, CellCommand::Extend);
                decode_extend_payload(&payload).unwrap()
            }
            PeelResult::ForwardDownstream(_) => panic!("Middle must consume EXTEND cell!"),
        };

        // Middle forwards CREATE to Relay Exit
        let create_cell_2 = build_create_cell(circuit_id, &exit_pub_for_relay).unwrap();
        let (mut relay_exit, created_cell_2) = handle_create_cell(&create_cell_2).unwrap();

        // Middle wraps backward towards Guard
        let mut return_wire_2 = created_cell_2.serialize();
        relay_middle.wrap_backward(&mut return_wire_2);
        // Guard wraps backward towards client
        relay_guard.wrap_backward(&mut return_wire_2);

        // Client unwraps backward across Hop 0 and Hop 1
        let client_unwrapped_2 = client_circuit.unwrap_backward(&mut return_wire_2).unwrap();
        assert_eq!(client_unwrapped_2.command, CellCommand::Created);

        let (fwd2, bwd2, mac2) =
            process_created_cell(&client_unwrapped_2, client_secret_2).unwrap();
        client_circuit.add_hop(fwd2, bwd2, mac2);
        assert_eq!(client_circuit.hop_count(), 3);

        // --- STEP 4: Authenticated Data Flow across Telescopically Negotiated 3-Hop Circuit ---
        let payload = b"TELESCOPIC_ONION_AUTHENTICATED_VERIFICATION";
        let data_cell = OnionCell::new(circuit_id, CellCommand::Data, 1, payload, &mac2).unwrap();
        let mut client_send_buf = client_circuit.wrap_forward(&data_cell);

        // Relay 0 (Guard) peels Layer 0 -> forwards downstream
        let p0 = relay_guard.peel_forward(&mut client_send_buf).unwrap();
        let mut to_m = match p0 {
            PeelResult::ForwardDownstream(b) => *b,
            _ => panic!("Expected forward downstream from guard"),
        };

        // Relay 1 (Middle) peels Layer 1 -> forwards downstream
        let p1 = relay_middle.peel_forward(&mut to_m).unwrap();
        let mut to_e = match p1 {
            PeelResult::ForwardDownstream(b) => *b,
            _ => panic!("Expected forward downstream from middle"),
        };

        // Relay 2 (Exit) peels Layer 2 -> authenticates HMAC-SHA256 and consumes data!
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
    fn test_cell_serialization_and_mac() {
        let mac_key = [7u8; 32];
        let payload = b"CLASSIFIED_MILITARY_PAYLOAD_HMAC_SHA256";
        let cell = OnionCell::new(101, CellCommand::Data, 1, payload, &mac_key).unwrap();

        assert_eq!(cell.circuit_id, 101);
        assert_eq!(cell.command, CellCommand::Data);
        assert_eq!(cell.stream_id, 1);
        assert_eq!(cell.length, payload.len() as u16);
        assert!(cell.is_mac_valid(&mac_key));

        // Wrong MAC key must fail
        let wrong_key = [8u8; 32];
        assert!(!cell.is_mac_valid(&wrong_key));

        // Test wire serialization and deserialization
        let raw = cell.serialize();
        let parsed = OnionCell::parse(&raw).expect("Parsing valid cell failed");
        assert_eq!(parsed.circuit_id, 101);
        assert!(parsed.is_mac_valid(&mac_key));
        assert_eq!(&parsed.payload[..payload.len()], payload);
    }

    #[test]
    fn test_oversized_payload_rejection() {
        let mac_key = [7u8; 32];
        let huge_payload = vec![0xAA; PAYLOAD_SIZE + 1];
        let res = OnionCell::new(101, CellCommand::Data, 1, &huge_payload, &mac_key);
        assert!(
            res.is_err(),
            "Oversized payload must not be silently truncated"
        );
    }

    #[test]
    fn test_tampering_rejection() {
        let mac_key = [42u8; 32];
        let payload = b"UNTOUCHABLE_DATA";
        let cell = OnionCell::new(55, CellCommand::Data, 1, payload, &mac_key).unwrap();
        let mut raw = cell.serialize();

        // Adversary flips a single bit in the payload
        raw[25] ^= 0x01;

        let tampered = OnionCell::parse(&raw).unwrap();
        // HMAC-SHA256 MAC MUST reject tampered cell
        assert!(!tampered.is_mac_valid(&mac_key));
    }

    #[test]
    fn test_3_hop_authenticated_onion_circuit() {
        // 1. Establish 3 hops: Guard (hop 0), Middle (hop 1), Exit (hop 2)
        let (client_hop0, relay0_keys) = perform_client_relay_handshake();
        let (client_hop1, relay1_keys) = perform_client_relay_handshake();
        let (client_hop2, relay2_keys) = perform_client_relay_handshake();

        // 2. Initialize Client Circuit with 3 hops (forward, backward, mac)
        let mut client_circuit = OnionCircuit::new(42);
        client_circuit.add_hop(client_hop0.0, client_hop0.1, client_hop0.2);
        client_circuit.add_hop(client_hop1.0, client_hop1.1, client_hop1.2);
        client_circuit.add_hop(client_hop2.0, client_hop2.1, client_hop2.2);
        assert_eq!(client_circuit.hop_count(), 3);

        // 3. Initialize Relay states
        let mut relay_guard = RelayCircuitHop::new(42, relay0_keys.0, relay0_keys.1, relay0_keys.2);
        let mut relay_middle =
            RelayCircuitHop::new(42, relay1_keys.0, relay1_keys.1, relay1_keys.2);
        let mut relay_exit = RelayCircuitHop::new(42, relay2_keys.0, relay2_keys.1, relay2_keys.2);

        // 4. Client creates an authenticated Data Cell intended for Exit (Hop 2)
        let exit_mac_key = client_circuit.get_hop_mac_key(2).unwrap();
        let secret_payload = b"TOP_SECRET_E2E_AUTHENTICATED_CELL";
        let original_cell =
            OnionCell::new(42, CellCommand::Data, 7, secret_payload, &exit_mac_key).unwrap();

        // 5. Client wraps the cell in 3 layers of encryption
        let mut wire_buffer = client_circuit.wrap_forward(&original_cell);

        // 6. Node 1 (Guard) receives wire buffer and peels Layer 1
        let peel_guard = relay_guard
            .peel_forward(&mut wire_buffer)
            .expect("Guard peel error");
        match peel_guard {
            PeelResult::ForwardDownstream(mut next_buffer) => {
                // Guard forwards downstream
                // 7. Node 2 (Middle) receives peeled buffer and peels Layer 2
                let peel_middle = relay_middle
                    .peel_forward(&mut next_buffer)
                    .expect("Middle peel error");
                match peel_middle {
                    PeelResult::ForwardDownstream(mut exit_buffer) => {
                        // Middle forwards to Exit
                        // 8. Node 3 (Exit) receives peeled buffer and peels Layer 3
                        let peel_exit = relay_exit
                            .peel_forward(&mut exit_buffer)
                            .expect("Exit peel error");
                        match peel_exit {
                            PeelResult::AddressedToThisRelay(cmd, data) => {
                                // Exit verifies Poly1305 MAC and extracts payload!
                                assert_eq!(cmd, CellCommand::Data);
                                assert_eq!(data.as_slice(), secret_payload);
                            }
                            PeelResult::ForwardDownstream(_) => {
                                panic!("Exit node should have consumed the cell!")
                            }
                        }
                    }
                    PeelResult::AddressedToThisRelay(_, _) => {
                        panic!("Middle should not have matched MAC!")
                    }
                }
            }
            PeelResult::AddressedToThisRelay(_, _) => panic!("Guard should not have matched MAC!"),
        }

        // 9. Return Path (Backward Direction):
        let response_data = b"EXIT_AUTHENTICATED_RESPONSE";
        let exit_resp_cell =
            OnionCell::new(42, CellCommand::Data, 7, response_data, &exit_mac_key).unwrap();
        let mut return_buffer = exit_resp_cell.serialize();

        // Exit wraps in Layer 3
        relay_exit.wrap_backward(&mut return_buffer);
        // Middle wraps in Layer 2
        relay_middle.wrap_backward(&mut return_buffer);
        // Guard wraps in Layer 1
        relay_guard.wrap_backward(&mut return_buffer);

        // Client unwraps all 3 layers
        let client_recovered = client_circuit
            .unwrap_backward(&mut return_buffer)
            .expect("Client unwrap failed");

        assert_eq!(client_recovered.command, CellCommand::Data);
        assert!(client_recovered.is_mac_valid(&exit_mac_key));
        assert_eq!(
            &client_recovered.payload[..response_data.len()],
            response_data
        );
    }
}
