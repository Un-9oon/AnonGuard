//! Onion Routing Subsystem with Poly1305 Authenticated Layered Encryption.

pub mod cell;
pub mod circuit;

pub use cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
pub use circuit::{
    derive_hop_keys, perform_client_relay_handshake, HandshakeKeys, HopCryptState, OnionCircuit,
    PeelResult, RelayCircuitHop,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_serialization_and_mac() {
        let mac_key = [7u8; 32];
        let payload = b"CLASSIFIED_MILITARY_PAYLOAD_POLY1305";
        let cell = OnionCell::new(101, CellCommand::Data, 1, payload, &mac_key);

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
    fn test_tampering_rejection() {
        let mac_key = [42u8; 32];
        let payload = b"UNTOUCHABLE_DATA";
        let cell = OnionCell::new(55, CellCommand::Data, 1, payload, &mac_key);
        let mut raw = cell.serialize();

        // Adversary flips a single bit in the payload
        raw[25] ^= 0x01;

        let tampered = OnionCell::parse(&raw).unwrap();
        // Poly1305 MAC MUST reject tampered cell
        assert!(!tampered.is_mac_valid(&mac_key));
    }

    #[test]
    fn test_3_hop_authenticated_onion_circuit() {
        // 1. Establish 3 hops: Guard (hop 0), Middle (hop 1), Exit (hop 2)
        let (client_hop0, relay0_keys) = perform_client_relay_handshake(0);
        let (client_hop1, relay1_keys) = perform_client_relay_handshake(1);
        let (client_hop2, relay2_keys) = perform_client_relay_handshake(2);

        // 2. Initialize Client Circuit with 3 hops (forward, backward, mac)
        let mut client_circuit = OnionCircuit::new(42);
        client_circuit.add_hop(client_hop0.0, client_hop0.1, client_hop0.2);
        client_circuit.add_hop(client_hop1.0, client_hop1.1, client_hop1.2);
        client_circuit.add_hop(client_hop2.0, client_hop2.1, client_hop2.2);
        assert_eq!(client_circuit.hop_count(), 3);

        // 3. Initialize Relay states
        let mut relay_guard = RelayCircuitHop::new(42, relay0_keys.0, relay0_keys.1, relay0_keys.2);
        let mut relay_middle = RelayCircuitHop::new(42, relay1_keys.0, relay1_keys.1, relay1_keys.2);
        let mut relay_exit = RelayCircuitHop::new(42, relay2_keys.0, relay2_keys.1, relay2_keys.2);

        // 4. Client creates an authenticated Data Cell intended for Exit (Hop 2)
        let exit_mac_key = client_circuit.get_hop_mac_key(2).unwrap();
        let secret_payload = b"TOP_SECRET_E2E_AUTHENTICATED_CELL";
        let original_cell = OnionCell::new(42, CellCommand::Data, 7, secret_payload, &exit_mac_key);

        // 5. Client wraps the cell in 3 layers of encryption
        let mut wire_buffer = client_circuit.wrap_forward(&original_cell);

        // 6. Node 1 (Guard) receives wire buffer and peels Layer 1
        let peel_guard = relay_guard.peel_forward(&mut wire_buffer).expect("Guard peel error");
        match peel_guard {
            PeelResult::ForwardDownstream(mut next_buffer) => {
                // Guard forwards downstream
                // 7. Node 2 (Middle) receives peeled buffer and peels Layer 2
                let peel_middle = relay_middle.peel_forward(&mut next_buffer).expect("Middle peel error");
                match peel_middle {
                    PeelResult::ForwardDownstream(mut exit_buffer) => {
                        // Middle forwards to Exit
                        // 8. Node 3 (Exit) receives peeled buffer and peels Layer 3
                        let peel_exit = relay_exit.peel_forward(&mut exit_buffer).expect("Exit peel error");
                        match peel_exit {
                            PeelResult::AddressedToThisRelay(cmd, data) => {
                                // Exit verifies Poly1305 MAC and extracts payload!
                                assert_eq!(cmd, CellCommand::Data);
                                assert_eq!(data.as_slice(), secret_payload);
                            }
                            PeelResult::ForwardDownstream(_) => panic!("Exit node should have consumed the cell!"),
                        }
                    }
                    PeelResult::AddressedToThisRelay(_, _) => panic!("Middle should not have matched MAC!"),
                }
            }
            PeelResult::AddressedToThisRelay(_, _) => panic!("Guard should not have matched MAC!"),
        }

        // 9. Return Path (Backward Direction):
        let response_data = b"EXIT_AUTHENTICATED_RESPONSE";
        let exit_resp_cell = OnionCell::new(42, CellCommand::Data, 7, response_data, &exit_mac_key);
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
        assert_eq!(&client_recovered.payload[..response_data.len()], response_data);
    }
}
