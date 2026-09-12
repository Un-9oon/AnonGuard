//! Onion Routing Subsystem for Military-Grade Layered Encryption.

pub mod cell;
pub mod circuit;

pub use cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
pub use circuit::{
    derive_hop_keys, perform_client_relay_handshake, HopCryptState, OnionCircuit, PeelResult,
    RelayCircuitHop,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_serialization_and_digest() {
        let payload = b"CLASSIFIED_MILITARY_PAYLOAD_12345";
        let cell = OnionCell::new(101, CellCommand::Data, 1, payload);

        assert_eq!(cell.circuit_id, 101);
        assert_eq!(cell.command, CellCommand::Data);
        assert_eq!(cell.stream_id, 1);
        assert_eq!(cell.length, payload.len() as u16);
        assert!(cell.is_digest_valid());

        let raw = cell.serialize();
        let parsed = OnionCell::parse(&raw).expect("Parsing valid cell failed");
        assert_eq!(parsed.circuit_id, 101);
        assert_eq!(parsed.command, CellCommand::Data);
        assert!(parsed.is_digest_valid());
        assert_eq!(&parsed.payload[..payload.len()], payload);
    }

    #[test]
    fn test_3_hop_onion_circuit_peeling() {
        // 1. Establish 3 hops: Guard (hop 0), Middle (hop 1), Exit (hop 2)
        let (client_hop0, relay0_keys) = perform_client_relay_handshake(0);
        let (client_hop1, relay1_keys) = perform_client_relay_handshake(1);
        let (client_hop2, relay2_keys) = perform_client_relay_handshake(2);

        // 2. Initialize Client Circuit with 3 hops
        let mut client_circuit = OnionCircuit::new(42);
        client_circuit.add_hop(client_hop0.0, client_hop0.1);
        client_circuit.add_hop(client_hop1.0, client_hop1.1);
        client_circuit.add_hop(client_hop2.0, client_hop2.1);
        assert_eq!(client_circuit.hop_count(), 3);

        // 3. Initialize Relay states
        let mut relay_guard = RelayCircuitHop::new(42, relay0_keys.0, relay0_keys.1);
        let mut relay_middle = RelayCircuitHop::new(42, relay1_keys.0, relay1_keys.1);
        let mut relay_exit = RelayCircuitHop::new(42, relay2_keys.0, relay2_keys.1);

        // 4. Client creates a Data Cell intended for Exit
        let secret_payload = b"TOP_SECRET_MILITARY_PAYLOAD_E2E";
        let original_cell = OnionCell::new(42, CellCommand::Data, 7, secret_payload);

        // 5. Client wraps the cell in 3 layers of encryption
        let mut wire_buffer = client_circuit.wrap_forward(&original_cell);

        // 6. Node 1 (Guard) receives wire buffer and peels Layer 1
        let peel_guard = relay_guard.peel_forward(&mut wire_buffer).expect("Guard peel error");
        match peel_guard {
            PeelResult::ForwardDownstream(mut next_buffer) => {
                // Guard cannot read the payload! It must forward downstream.
                // 7. Node 2 (Middle) receives peeled buffer and peels Layer 2
                let peel_middle = relay_middle.peel_forward(&mut next_buffer).expect("Middle peel error");
                match peel_middle {
                    PeelResult::ForwardDownstream(mut exit_buffer) => {
                        // Middle cannot read the payload either! Forwards to Exit.
                        // 8. Node 3 (Exit) receives peeled buffer and peels Layer 3
                        let peel_exit = relay_exit.peel_forward(&mut exit_buffer).expect("Exit peel error");
                        match peel_exit {
                            PeelResult::AddressedToThisRelay(cmd, data) => {
                                // Exit successfully recovers the plaintext payload!
                                assert_eq!(cmd, CellCommand::Data);
                                assert_eq!(data.as_slice(), secret_payload);
                            }
                            PeelResult::ForwardDownstream(_) => panic!("Exit node should have consumed the cell!"),
                        }
                    }
                    PeelResult::AddressedToThisRelay(_, _) => panic!("Middle should not have matched digest!"),
                }
            }
            PeelResult::AddressedToThisRelay(_, _) => panic!("Guard should not have matched digest!"),
        }

        // 9. Now test Return Path (Backward Direction):
        // Exit generates a response cell
        let response_data = b"EXIT_NODE_AUTHORIZED_RESPONSE";
        let exit_resp_cell = OnionCell::new(42, CellCommand::Data, 7, response_data);
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
        assert!(client_recovered.is_digest_valid());
        assert_eq!(&client_recovered.payload[..response_data.len()], response_data);
    }
}
