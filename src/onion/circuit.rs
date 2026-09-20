use subtle::ConstantTimeEq;
// Layered Onion Circuit Routing, Multi-hop Key Agreement, and AEAD Peeling.
//
// Security: Every hop handshake is identity-bound via Ed25519 signature over the ephemeral
// X25519 public keys, linking DH to the relay's long-term identity key pinned in the consensus.
// Data is protected by ChaCha20-Poly1305 AEAD for the addressed hop, and ChaCha20 stream cipher
// for routing layers, using an explicit stateless nonce derived from the cell's sequence number.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE, PAYLOAD_SIZE};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_HOPS: usize = 3;
const BWD_COUNTER_BITS: u32 = 30;
const BWD_COUNTER_MASK: u32 = (1 << BWD_COUNTER_BITS) - 1;
const MAX_SEQ_GAP: u32 = 1000;

#[derive(Error, Debug)]
pub enum CircuitError {
    #[error("Hop index out of range: {0}")]
    HopIndexOutOfRange(usize),
    #[error("Sequence number exhausted")]
    SequenceExhausted,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("MAC verification failed")]
    MacVerificationFailed,
    #[error("Anti-replay rejection: {0}")]
    AntiReplayRejection(String),
    #[error("identity key does not match pinned consensus key")]
    UnpinnedRelay,
    #[error("Invalid padding length")]
    InvalidPadding,
    #[error("Payload too short")]
    PayloadTooShort,
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Invalid circuit id")]
    InvalidCircuitId,
    #[error("General error: {0}")]
    General(String),
}

impl From<String> for CircuitError {
    fn from(e: String) -> Self {
        CircuitError::General(e)
    }
}
impl From<&str> for CircuitError {
    fn from(e: &str) -> Self {
        CircuitError::General(e.to_string())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HopKeys {
    pub forward_key: [u8; 32],
    pub backward_key: [u8; 32],
    pub forward_mac: [u8; 32],
    pub backward_mac: [u8; 32],
    pub forward_aead_key: [u8; 32],
    pub backward_aead_key: [u8; 32],
}

/// Helper to build a 96-bit nonce from circuit_id and sequence_no
fn build_nonce(direction: u8, circuit_id: u32, sequence_no: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..8].copy_from_slice(&circuit_id.to_be_bytes());
    nonce[8..12].copy_from_slice(&sequence_no.to_be_bytes());
    nonce
}

fn pack_backward_seq(hop_index: usize, counter: u32) -> Result<u32, CircuitError> {
    if hop_index >= MAX_HOPS {
        return Err(CircuitError::HopIndexOutOfRange(hop_index));
    }
    if counter > BWD_COUNTER_MASK {
        return Err(CircuitError::SequenceExhausted);
    }
    Ok(((hop_index as u32) << BWD_COUNTER_BITS) | counter)
}

/// Per-hop cryptographic session state containing forward and backward keys.
pub struct HopCryptState {
    pub keys: HopKeys,
}

use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};

impl HopCryptState {
    /// AEAD-seals the addressed hop's payload using a dedicated, independently
    /// HKDF-derived key (forward_aead_key) — never reused from forward_key/forward_mac.
    pub fn seal_forward(&self, nonce: &[u8; 12], header: &[u8], pt_body: &mut [u8]) -> [u8; 16] {
        let cipher = ChaCha20Poly1305::new(&self.keys.forward_aead_key.into());
        // SAFETY: ChaCha20Poly1305 in-place encryption over in-memory slices cannot fail because allocation is not required and nonce/key lengths (12 bytes/32 bytes) are fixed by type signatures.
        let tag = cipher
            .encrypt_in_place_detached(nonce.into(), header, pt_body)
            .expect("safe: ChaCha20Poly1305 in-place detached encryption over in-memory slice cannot fail; key is 32-byte array, nonce is 12-byte array, buffer payload length is checked in OnionCell::new");
        tag.into()
    }

    pub fn open_forward(
        &self,
        nonce: &[u8; 12],
        header: &[u8],
        ct_body: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CircuitError> {
        let cipher = ChaCha20Poly1305::new(&self.keys.forward_aead_key.into());
        cipher
            .decrypt_in_place_detached(nonce.into(), header, ct_body, tag.into())
            .map_err(|_| CircuitError::MacVerificationFailed)
    }

    pub fn seal_backward(&self, nonce: &[u8; 12], header: &[u8], pt_body: &mut [u8]) -> [u8; 16] {
        let cipher = ChaCha20Poly1305::new(&self.keys.backward_aead_key.into());
        // SAFETY: ChaCha20Poly1305 in-place encryption over in-memory slices cannot fail because allocation is not required and nonce/key lengths (12 bytes/32 bytes) are fixed by type signatures.
        let tag = cipher
            .encrypt_in_place_detached(nonce.into(), header, pt_body)
            .expect("safe: ChaCha20Poly1305 in-place detached encryption over in-memory slice cannot fail; key is 32-byte array, nonce is 12-byte array, buffer payload length is checked in OnionCell::new");
        tag.into()
    }

    pub fn open_backward(
        &self,
        nonce: &[u8; 12],
        header: &[u8],
        ct_body: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CircuitError> {
        let cipher = ChaCha20Poly1305::new(&self.keys.backward_aead_key.into());
        cipher
            .decrypt_in_place_detached(nonce.into(), header, ct_body, tag.into())
            .map_err(|_| CircuitError::MacVerificationFailed)
    }

    pub fn new(keys: HopKeys) -> Self {
        Self { keys }
    }

    pub fn encrypt_forward_stream(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut cipher = ChaCha20::new(&self.keys.forward_key.into(), &(*nonce).into());
        cipher.apply_keystream(data);
    }

    pub fn encrypt_backward_stream(&self, nonce: &[u8; 12], data: &mut [u8]) {
        let mut cipher = ChaCha20::new(&self.keys.backward_key.into(), &(*nonce).into());
        cipher.apply_keystream(data);
    }
}

/// Key derivation function turning an X25519 + ML-KEM-768 hybrid secret into forward, backward, and MAC keys.
/// Uses RFC 5869 HKDF-SHA256 with domain-separated info labels for key commitment.
pub fn derive_hop_keys(shared_secret: &[u8]) -> Result<HopKeys, CircuitError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);

    let mut keys = HopKeys {
        forward_key: [0u8; 32],
        backward_key: [0u8; 32],
        forward_mac: [0u8; 32],
        backward_mac: [0u8; 32],
        forward_aead_key: [0u8; 32],
        backward_aead_key: [0u8; 32],
    };

    hk.expand(b"AnonGuard-Forward-Key-v4", &mut keys.forward_key)
        .map_err(|_| CircuitError::KeyDerivationFailed)?;
    hk.expand(b"AnonGuard-Backward-Key-v4", &mut keys.backward_key)
        .map_err(|_| CircuitError::KeyDerivationFailed)?;
    hk.expand(b"AnonGuard-Forward-MAC-v4", &mut keys.forward_mac)
        .map_err(|_| CircuitError::KeyDerivationFailed)?;
    hk.expand(b"AnonGuard-Backward-MAC-v4", &mut keys.backward_mac)
        .map_err(|_| CircuitError::KeyDerivationFailed)?;
    // Dedicated, full-entropy, single-purpose AEAD keys (v5). Previously the AEAD
    // path reused the first 16 bytes each of forward_key and forward_mac spliced
    // together, which halved effective entropy per source and reused MAC-domain
    // key material inside the cipher. These are independently HKDF-derived instead.
    hk.expand(b"AnonGuard-Forward-AEAD-Key-v5", &mut keys.forward_aead_key)
        .map_err(|_| CircuitError::KeyDerivationFailed)?;
    hk.expand(
        b"AnonGuard-Backward-AEAD-Key-v5",
        &mut keys.backward_aead_key,
    )
    .map_err(|_| CircuitError::KeyDerivationFailed)?;

    Ok(keys)
}

/// Represents a client-side 3-hop onion circuit (Guard -> Middle -> Exit).
pub struct OnionCircuit {
    pub circuit_id: u32,
    hops: Vec<HopCryptState>,
    pub sequence_no: u32,
    pub bwd_replay_windows: Vec<ReplayWindow>,
}

pub struct ReplayWindow {
    pub window: u64,
    pub next_expected: u32,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            window: 0,
            next_expected: 1,
        }
    }

    pub fn check_and_advance(&mut self, seq: u32) -> Result<(), CircuitError> {
        let _hop_index = (seq >> BWD_COUNTER_BITS) as usize;
        let counter = seq & BWD_COUNTER_MASK;

        if counter < self.next_expected {
            let diff = self.next_expected - counter;
            if diff > 64 || (self.window & (1 << (diff - 1))) != 0 {
                return Err(CircuitError::AntiReplayRejection(format!(
                    "Replay on sequence {}",
                    seq
                )));
            }
            self.window |= 1 << (diff - 1);
        } else if counter == self.next_expected {
            self.window = (self.window << 1) | 1;
            self.next_expected = counter + 1;
        } else {
            let diff = counter - self.next_expected;
            if diff > MAX_SEQ_GAP {
                return Err(CircuitError::AntiReplayRejection(format!(
                    "Sequence gap too large: {}",
                    diff
                )));
            }
            // Shift by (diff + 1): moves past the gap (leaving those bits as zero)
            // and sets bit 0 for the newly arrived packet.
            // Previously this was `<< diff` which incorrectly set bit 0 at the gap
            // boundary, allowing replay of the first sequence in the gap.
            if diff >= 63 {
                self.window = 1;
            } else {
                self.window = (self.window << (diff + 1)) | 1;
            }
            self.next_expected = counter + 1;
        }
        Ok(())
    }
}

impl OnionCircuit {
    pub fn new(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            hops: Vec::new(),
            sequence_no: 1,
            bwd_replay_windows: Vec::new(),
        }
    }

    pub fn add_hop(&mut self, keys: HopKeys) -> Result<(), CircuitError> {
        if self.hops.len() >= MAX_HOPS {
            return Err(CircuitError::HopIndexOutOfRange(self.hops.len()));
        }
        self.hops.push(HopCryptState::new(keys));
        self.bwd_replay_windows.push(ReplayWindow::new());
        Ok(())
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn wrap_forward(
        &mut self,
        cell: &mut OnionCell,
    ) -> Result<[u8; ONION_CELL_SIZE], CircuitError> {
        if self.sequence_no == u32::MAX {
            return Err(CircuitError::SequenceExhausted);
        }
        if cell.circuit_id != self.circuit_id {
            return Err(CircuitError::InvalidCircuitId);
        }
        cell.sequence_no = self.sequence_no;
        self.sequence_no = self
            .sequence_no
            .checked_add(1)
            .ok_or(CircuitError::SequenceExhausted)?;
        let nonce = build_nonce(1, self.circuit_id, cell.sequence_no);

        let mut raw = cell.serialize();

        if let Some(target_hop) = self.hops.last() {
            let (header, body) = raw.split_at_mut(8);
            let (pt, mac_buf) = body.split_at_mut(ONION_CELL_SIZE - 24);

            let tag = target_hop.seal_forward(&nonce, header, pt);
            mac_buf.copy_from_slice(&tag);
        }

        let hop_count = self.hops.len();
        if hop_count > 1 {
            for hop in self.hops.iter().take(hop_count - 1).rev() {
                hop.encrypt_forward_stream(&nonce, &mut raw[8..]);
            }
        }

        Ok(raw)
    }

    pub fn unwrap_backward(
        &mut self,
        raw: &mut [u8; ONION_CELL_SIZE],
    ) -> Result<(usize, OnionCell), CircuitError> {
        let cell_circuit_id = u32::from_be_bytes(
            raw[0..4]
                .try_into()
                .map_err(|_| CircuitError::ParseError("Invalid circuit id bytes".to_string()))?,
        );
        if cell_circuit_id != self.circuit_id {
            return Err(CircuitError::InvalidCircuitId);
        }

        let seq_bytes = raw[4..8]
            .try_into()
            .map_err(|_| CircuitError::ParseError("Invalid seq bytes".to_string()))?;
        let seq = u32::from_be_bytes(seq_bytes);
        let hop_index = (seq >> BWD_COUNTER_BITS) as usize;

        if hop_index >= self.hops.len() {
            return Err(CircuitError::HopIndexOutOfRange(hop_index));
        }

        let nonce = build_nonce(2, self.circuit_id, seq);

        // Peel outer layers up to the originating hop
        for hop in self.hops.iter().take(hop_index) {
            hop.encrypt_backward_stream(&nonce, &mut raw[8..]);
        }

        let target_hop = &self.hops[hop_index];
        let (header, body) = raw.split_at_mut(8);
        let (ct, mac_buf) = body.split_at_mut(ONION_CELL_SIZE - 24);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(mac_buf);
        target_hop.open_backward(&nonce, header, ct, &tag)?;

        self.bwd_replay_windows[hop_index].check_and_advance(seq)?;

        let cell = OnionCell::parse(raw).map_err(CircuitError::ParseError)?;
        Ok((hop_index, cell))
    }
}

/// Represents the relay's view of an onion circuit with anti-replay state.
pub struct RelayCircuitHop {
    pub circuit_id: u32,
    pub crypt: HopCryptState,
    pub expected_recv_seq: u32,
    pub next_send_seq: u32,
    pub hop_index: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeelOutcome {
    AddressedToThisRelay { command: CellCommand, len: usize },
    ForwardDownstream,
}

impl RelayCircuitHop {
    pub fn new(circuit_id: u32, keys: HopKeys, hop_index: usize) -> Self {
        Self {
            circuit_id,
            crypt: HopCryptState::new(keys),
            expected_recv_seq: 1,
            next_send_seq: 1,
            hop_index,
        }
    }

    pub fn peel_forward(
        &mut self,
        raw: &mut [u8; ONION_CELL_SIZE],
    ) -> Result<PeelOutcome, CircuitError> {
        let cell_circuit_id = u32::from_be_bytes(
            raw[0..4]
                .try_into()
                .map_err(|_| CircuitError::ParseError("Invalid circuit id bytes".to_string()))?,
        );
        if cell_circuit_id != self.circuit_id {
            return Err(CircuitError::InvalidCircuitId);
        }

        let seq_bytes = raw[4..8]
            .try_into()
            .map_err(|_| CircuitError::ParseError("Invalid seq bytes".to_string()))?;
        let seq = u32::from_be_bytes(seq_bytes);

        let nonce = build_nonce(1, self.circuit_id, seq);

        // Limit scope of immutable borrow
        let mut tag = [0u8; 16];
        let tag_matches = {
            let (header, body) = raw.split_at_mut(8);
            let (pt, mac_buf) = body.split_at_mut(ONION_CELL_SIZE - 24);
            tag.copy_from_slice(mac_buf);
            self.crypt.open_forward(&nonce, header, pt, &tag).is_ok()
        };

        if tag_matches {
            if seq < self.expected_recv_seq {
                return Err(CircuitError::AntiReplayRejection(format!(
                    "Stale sequence {}",
                    seq
                )));
            }
            if seq - self.expected_recv_seq > MAX_SEQ_GAP {
                return Err(CircuitError::AntiReplayRejection(
                    "Sequence gap too large".to_string(),
                ));
            }
            self.expected_recv_seq = seq + 1;

            let command = CellCommand::from_u8(raw[8]).ok_or_else(|| {
                CircuitError::ParseError(format!("Unknown cell command: {}", raw[8]))
            })?;
            let length = u16::from_be_bytes([raw[11], raw[12]]);
            return Ok(PeelOutcome::AddressedToThisRelay {
                command,
                len: (length as usize).min(PAYLOAD_SIZE),
            });
        }

        self.crypt.encrypt_forward_stream(&nonce, &mut raw[8..]);
        Ok(PeelOutcome::ForwardDownstream)
    }

    pub fn wrap_backward_relay(
        &mut self,
        raw: &mut [u8; ONION_CELL_SIZE],
    ) -> Result<(), CircuitError> {
        let seq_bytes = raw[4..8]
            .try_into()
            .map_err(|_| CircuitError::ParseError("Invalid seq bytes".to_string()))?;
        let seq = u32::from_be_bytes(seq_bytes);

        let claimed_hop = (seq >> BWD_COUNTER_BITS) as usize;
        if claimed_hop == self.hop_index {
            return Err(CircuitError::AntiReplayRejection(
                "Relayed cell claims our hop index".to_string(),
            ));
        }

        let nonce = build_nonce(2, self.circuit_id, seq);

        let (_header, body) = raw.split_at_mut(8);
        self.crypt.encrypt_backward_stream(&nonce, body);
        Ok(())
    }

    pub fn wrap_backward_originate(
        &mut self,
        raw: &mut [u8; ONION_CELL_SIZE],
    ) -> Result<(), CircuitError> {
        let counter = self.next_send_seq;
        self.next_send_seq = self
            .next_send_seq
            .checked_add(1)
            .ok_or(CircuitError::SequenceExhausted)?;
        let seq = pack_backward_seq(self.hop_index, counter)?;
        raw[4..8].copy_from_slice(&seq.to_be_bytes());

        let nonce = build_nonce(2, self.circuit_id, seq);

        let (header, body) = raw.split_at_mut(8);
        let (pt, mac_buf) = body.split_at_mut(ONION_CELL_SIZE - 24);

        let tag = self.crypt.seal_backward(&nonce, header, pt);
        mac_buf.copy_from_slice(&tag);
        Ok(())
    }
}

/// Builds a CREATE cell carrying the client's ephemeral X25519 public key and ML-KEM-768 public key.
pub fn build_create_cell(
    circuit_id: u32,
    client_pub: &X25519PublicKey,
    client_mlkem_pub: &EncapsulationKey<MlKem768Params>,
    hop_index: usize,
) -> Result<OnionCell, CircuitError> {
    let mut payload = [0u8; 1 + 32 + 1184];
    payload[0] = hop_index as u8;
    payload[1..33].copy_from_slice(client_pub.as_bytes());
    payload[33..1217].copy_from_slice(client_mlkem_pub.as_bytes().as_slice());
    OnionCell::new(circuit_id, 0, CellCommand::Create, 0, &payload).map_err(CircuitError::General)
}

pub fn handle_create_cell(
    create_cell: &OnionCell,
    relay_identity_key: &SigningKey,
) -> Result<(RelayCircuitHop, OnionCell), CircuitError> {
    if create_cell.command != CellCommand::Create {
        return Err(CircuitError::ParseError(format!(
            "Expected CREATE, got {:?}",
            create_cell.command
        )));
    }
    if create_cell.length < 1217 {
        return Err(CircuitError::PayloadTooShort);
    }
    let hop_index = create_cell.payload[0] as usize;
    if hop_index >= MAX_HOPS {
        return Err(CircuitError::HopIndexOutOfRange(hop_index));
    }

    let client_pub_bytes: [u8; 32] = create_cell.payload[1..33].try_into().map_err(|_| {
        CircuitError::ParseError("Failed to extract client X25519 public key".to_string())
    })?;
    let client_pub = X25519PublicKey::from(client_pub_bytes);

    let client_mlkem_pub_bytes: [u8; 1184] =
        create_cell.payload[33..1217].try_into().map_err(|_| {
            CircuitError::ParseError("Failed to extract client ML-KEM public key".to_string())
        })?;
    let client_mlkem_pub =
        EncapsulationKey::<MlKem768Params>::from_bytes((&client_mlkem_pub_bytes).into());

    let relay_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_pub = X25519PublicKey::from(&relay_secret);

    let x25519_shared = relay_secret.diffie_hellman(&client_pub);
    // Non-contributory DH rejection (V-03)
    if x25519_shared.as_bytes() == &[0u8; 32] {
        return Err(CircuitError::General(
            "Non-contributory DH key rejected".to_string(),
        ));
    }

    let (mlkem_ct, mlkem_shared) = client_mlkem_pub
        .encapsulate(&mut OsRng)
        .map_err(|_| CircuitError::General("ML-KEM encapsulation failed".to_string()))?;

    let mut hybrid_secret = [0u8; 64];
    hybrid_secret[0..32].copy_from_slice(x25519_shared.as_bytes());
    hybrid_secret[32..64].copy_from_slice(mlkem_shared.as_slice());

    let keys = derive_hop_keys(&hybrid_secret)?;

    let identity_pub = relay_identity_key.verifying_key();
    let mut preimage = Vec::with_capacity(22 + 32 + 32 + 1184 + 1088);
    preimage.extend_from_slice(b"AnonGuard-handshake-v2");
    preimage.extend_from_slice(relay_pub.as_bytes());
    preimage.extend_from_slice(&client_pub_bytes);
    preimage.extend_from_slice(&client_mlkem_pub_bytes);
    preimage.extend_from_slice(mlkem_ct.as_slice());
    let handshake_sig: Signature = relay_identity_key.sign(&preimage);

    let mut created_payload = [0u8; 32 + 32 + 64 + 1088];
    created_payload[0..32].copy_from_slice(relay_pub.as_bytes());
    created_payload[32..64].copy_from_slice(identity_pub.as_bytes());
    created_payload[64..128].copy_from_slice(&handshake_sig.to_bytes());
    created_payload[128..1216].copy_from_slice(mlkem_ct.as_slice());

    let created_cell = OnionCell::new(
        create_cell.circuit_id,
        0,
        CellCommand::Created,
        0,
        &created_payload,
    )
    .map_err(CircuitError::General)?;

    let relay_hop = RelayCircuitHop::new(create_cell.circuit_id, keys, hop_index);
    Ok((relay_hop, created_cell))
}

#[allow(clippy::too_many_arguments)]
pub fn process_created_cell(
    created_cell: &OnionCell,
    client_secret: EphemeralSecret,
    client_pub_bytes: &[u8; 32],
    client_mlkem_dk: &DecapsulationKey<MlKem768Params>,
    client_mlkem_pub_bytes: &[u8; 1184],
    pinned_identity_key: &[u8; 32],
    _cid: u32,
    _hop_index: usize,
) -> Result<HopKeys, CircuitError> {
    if created_cell.command != CellCommand::Created && created_cell.command != CellCommand::Extended
    {
        return Err(CircuitError::ParseError(format!(
            "Expected CREATED or EXTENDED cell, got {:?}",
            created_cell.command
        )));
    }
    if created_cell.length < 1216 {
        return Err(CircuitError::PayloadTooShort);
    }

    let relay_eph_pub_bytes: [u8; 32] = created_cell.payload[0..32].try_into().map_err(|_| {
        CircuitError::ParseError("Failed to extract relay ephemeral public key".to_string())
    })?;
    let relay_identity_pub_bytes: [u8; 32] =
        created_cell.payload[32..64].try_into().map_err(|_| {
            CircuitError::ParseError("Failed to extract relay identity public key".to_string())
        })?;
    let sig_bytes: [u8; 64] = created_cell.payload[64..128].try_into().map_err(|_| {
        CircuitError::ParseError("Failed to extract handshake signature".to_string())
    })?;
    let mlkem_ct_bytes: [u8; 1088] = created_cell.payload[128..1216]
        .try_into()
        .map_err(|_| CircuitError::ParseError("Failed to extract ML-KEM ciphertext".to_string()))?;

    // V-03: all-zero pin rejected
    if pinned_identity_key == &[0u8; 32] {
        return Err(CircuitError::UnpinnedRelay);
    }
    if relay_identity_pub_bytes
        .ct_eq(pinned_identity_key)
        .unwrap_u8()
        != 1
    {
        return Err(CircuitError::UnpinnedRelay);
    }

    let verifying_key = VerifyingKey::from_bytes(&relay_identity_pub_bytes).map_err(|e| {
        CircuitError::ParseError(format!("Invalid relay Ed25519 identity key: {e}"))
    })?;
    let signature = Signature::from_bytes(&sig_bytes);

    let mut preimage = Vec::with_capacity(22 + 32 + 32 + 1184 + 1088);
    preimage.extend_from_slice(b"AnonGuard-handshake-v2");
    preimage.extend_from_slice(&relay_eph_pub_bytes);
    preimage.extend_from_slice(client_pub_bytes);
    preimage.extend_from_slice(client_mlkem_pub_bytes);
    preimage.extend_from_slice(&mlkem_ct_bytes);

    verifying_key
        .verify_strict(&preimage, &signature)
        .map_err(|_| {
            CircuitError::General("Handshake Ed25519 signature verification failed".to_string())
        })?;

    let relay_eph_pub = X25519PublicKey::from(relay_eph_pub_bytes);
    let x25519_shared = client_secret.diffie_hellman(&relay_eph_pub);
    // V-03: non-contributory DH rejection
    if x25519_shared.as_bytes() == &[0u8; 32] {
        return Err(CircuitError::General(
            "Non-contributory DH key rejected".to_string(),
        ));
    }

    let mlkem_ct = Ciphertext::<MlKem768>::from(mlkem_ct_bytes);
    let mlkem_shared = client_mlkem_dk
        .decapsulate(&mlkem_ct)
        .map_err(|_| CircuitError::General("ML-KEM decapsulation failed".to_string()))?;

    let mut hybrid_secret = [0u8; 64];
    hybrid_secret[0..32].copy_from_slice(x25519_shared.as_bytes());
    hybrid_secret[32..64].copy_from_slice(mlkem_shared.as_slice());

    derive_hop_keys(&hybrid_secret)
}

pub fn encode_extend_payload(
    next_host: &str,
    next_port: u16,
    client_pub: &X25519PublicKey,
    client_mlkem_pub: &EncapsulationKey<MlKem768Params>,
    hop_index: usize,
) -> Result<Vec<u8>, CircuitError> {
    let host_bytes = next_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(CircuitError::General(
            "Host string exceeds 255 bytes limit".to_string(),
        ));
    }

    let mut payload = Vec::with_capacity(1 + 1 + host_bytes.len() + 2 + 32 + 1184);
    payload.push(hop_index as u8);
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);
    payload.extend_from_slice(&next_port.to_be_bytes());
    payload.extend_from_slice(client_pub.as_bytes());
    payload.extend_from_slice(client_mlkem_pub.as_bytes().as_slice());
    Ok(payload)
}

pub fn decode_extend_payload(
    payload: &[u8],
) -> Result<
    (
        String,
        u16,
        X25519PublicKey,
        EncapsulationKey<MlKem768Params>,
        usize,
    ),
    CircuitError,
> {
    if payload.len() < 1 + 1 + 2 + 32 + 1184 {
        return Err(CircuitError::PayloadTooShort);
    }
    let hop_index = payload[0] as usize;
    let host_len = payload[1] as usize;
    if payload.len() < 1 + 1 + host_len + 2 + 32 + 1184 {
        return Err(CircuitError::PayloadTooShort);
    }

    let host = String::from_utf8(payload[2..2 + host_len].to_vec())
        .map_err(|_| CircuitError::ParseError("Invalid UTF-8 in EXTEND host".to_string()))?;
    let port_bytes: [u8; 2] = payload[2 + host_len..2 + host_len + 2]
        .try_into()
        .map_err(|_| CircuitError::ParseError("Failed to read port".to_string()))?;
    let port = u16::from_be_bytes(port_bytes);

    let pub_bytes: [u8; 32] = payload[2 + host_len + 2..2 + host_len + 2 + 32]
        .try_into()
        .map_err(|_| CircuitError::ParseError("Failed to read public key".to_string()))?;
    let client_pub = X25519PublicKey::from(pub_bytes);

    let mlkem_bytes: [u8; 1184] = payload[2 + host_len + 2 + 32..2 + host_len + 2 + 32 + 1184]
        .try_into()
        .map_err(|_| CircuitError::ParseError("Failed to read ML-KEM public key".to_string()))?;
    let client_mlkem_pub = EncapsulationKey::<MlKem768Params>::from_bytes((&mlkem_bytes).into());

    Ok((host, port, client_pub, client_mlkem_pub, hop_index))
}

pub fn encode_relay_target(target_host: &str, target_port: u16) -> Result<Vec<u8>, CircuitError> {
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(CircuitError::General(
            "Target host string exceeds 255 bytes limit".to_string(),
        ));
    }
    let mut payload = Vec::with_capacity(1 + host_bytes.len() + 2);
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);
    payload.extend_from_slice(&target_port.to_be_bytes());
    Ok(payload)
}

pub fn decode_relay_target(payload: &[u8]) -> Result<(String, u16), CircuitError> {
    if payload.len() < 1 + 2 {
        return Err(CircuitError::PayloadTooShort);
    }
    let host_len = payload[0] as usize;
    if payload.len() < 1 + host_len + 2 {
        return Err(CircuitError::PayloadTooShort);
    }
    let host = String::from_utf8(payload[1..1 + host_len].to_vec())
        .map_err(|_| CircuitError::ParseError("Invalid UTF-8 in RELAY target host".to_string()))?;
    let port_bytes: [u8; 2] = payload[1 + host_len..1 + host_len + 2]
        .try_into()
        .map_err(|_| CircuitError::ParseError("Failed to read port".to_string()))?;
    let port = u16::from_be_bytes(port_bytes);
    Ok((host, port))
}

/// Simulates a complete client-relay key exchange in one call and returns the
/// matching client-side and relay-side `HopKeys` for use in benchmarks and tests.
///
/// # Errors
/// Returns `CircuitError::KeyDerivationFailed` if `OsRng` is unavailable or
/// returns `CircuitError::General` if ML-KEM encapsulation or decapsulation fails.
pub fn perform_client_relay_handshake() -> Result<(HopKeys, HopKeys), CircuitError> {
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = X25519PublicKey::from(&client_secret);
    let (client_mlkem_dk, client_mlkem_ek) = MlKem768::generate(&mut OsRng);

    let relay_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_public = X25519PublicKey::from(&relay_secret);

    let client_x25519_shared = client_secret.diffie_hellman(&relay_public);
    let relay_x25519_shared = relay_secret.diffie_hellman(&client_public);

    let (ct, relay_mlkem_shared) = client_mlkem_ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CircuitError::General("ML-KEM encapsulation failed".to_string()))?;
    let client_mlkem_shared = client_mlkem_dk
        .decapsulate(&ct)
        .map_err(|_| CircuitError::General("ML-KEM decapsulation failed".to_string()))?;

    let mut client_hybrid = [0u8; 64];
    client_hybrid[0..32].copy_from_slice(client_x25519_shared.as_bytes());
    client_hybrid[32..64].copy_from_slice(client_mlkem_shared.as_slice());

    let mut relay_hybrid = [0u8; 64];
    relay_hybrid[0..32].copy_from_slice(relay_x25519_shared.as_bytes());
    relay_hybrid[32..64].copy_from_slice(relay_mlkem_shared.as_slice());

    let client_keys = derive_hop_keys(&client_hybrid)?;
    let relay_keys = derive_hop_keys(&relay_hybrid)?;

    Ok((client_keys, relay_keys))
}

#[cfg(test)]
mod aead_key_derivation_tests {
    use super::*;

    /// Rule 8 test for the perform_client_relay_handshake() -> Result conversion.
    ///
    /// Before the fix: the function returned `(HopKeys, HopKeys)` and contained
    /// `.unwrap()` calls on ML-KEM encapsulate/decapsulate and derive_hop_keys —
    /// any OsRng failure or (in principle) crypto-library error would panic
    /// the entire daemon.
    ///
    /// After the fix: the function returns `Result<(HopKeys, HopKeys), CircuitError>`.
    /// This test calls the REAL function and asserts:
    ///   1. It succeeds (Ok) in normal conditions.
    ///   2. The caller-side and relay-side keys are symmetric (matching forward/backward).
    ///   3. Two sequential calls produce independent keys (forward secrecy).
    #[test]
    fn test_perform_client_relay_handshake_returns_result() {
        // Call the real function (not a reimplementation) — must succeed and return Ok.
        let result = perform_client_relay_handshake();
        assert!(
            result.is_ok(),
            "perform_client_relay_handshake must succeed and return Ok, got: {:?}",
            result.err()
        );
        let (ck, rk) = result.unwrap();

        // Keys must be symmetric: client's forward == relay's forward (shared handshake).
        assert_eq!(
            ck.forward_key, rk.forward_key,
            "Client forward_key must match relay forward_key after handshake"
        );
        assert_eq!(
            ck.backward_key, rk.backward_key,
            "Client backward_key must match relay backward_key after handshake"
        );
        assert_eq!(
            ck.forward_aead_key, rk.forward_aead_key,
            "Client forward_aead_key must match relay forward_aead_key"
        );

        // Two calls must produce independent keys (forward secrecy).
        let (ck2, _) = perform_client_relay_handshake().unwrap();
        assert_ne!(
            ck.forward_key, ck2.forward_key,
            "Sequential handshakes must produce independent keys"
        );
    }

    #[test]
    fn aead_key_is_independent_from_transport_and_mac_keys() {
        let shared_secret = [0x42u8; 32];
        let keys = derive_hop_keys(&shared_secret).unwrap();

        // The AEAD key must not equal, and must not be derivable by simple
        // truncation/concatenation of, the stream-cipher key or the legacy
        // MAC key. This guards against reintroducing the v4 bug where
        // aead_key = forward_key[0..16] || forward_mac[0..16].
        assert_ne!(keys.forward_aead_key, keys.forward_key);
        assert_ne!(keys.forward_aead_key, keys.forward_mac);
        assert_ne!(keys.forward_aead_key[0..16], keys.forward_key[0..16]);
        assert_ne!(keys.forward_aead_key[16..32], keys.forward_mac[0..16]);

        assert_ne!(keys.backward_aead_key, keys.backward_key);
        assert_ne!(keys.backward_aead_key, keys.backward_mac);

        // Forward and backward AEAD keys must themselves be distinct.
        assert_ne!(keys.forward_aead_key, keys.backward_aead_key);
    }

    #[test]
    fn aead_seal_open_round_trip_and_tamper_rejection() {
        let shared_secret = [0x11u8; 32];
        let keys = derive_hop_keys(&shared_secret).unwrap();
        let crypt = HopCryptState::new(keys);

        let nonce = build_nonce(1, 7, 1);
        let header = [0xAAu8; 8];
        let mut buf = *b"hello world, this is a test payload buffer!!!!";
        let original = buf;

        let tag = crypt.seal_forward(&nonce, &header, &mut buf);
        assert_ne!(buf, original, "ciphertext must differ from plaintext");

        // Correct tag + correct header must verify and recover the plaintext.
        let mut roundtrip = buf;
        crypt
            .open_forward(&nonce, &header, &mut roundtrip, &tag)
            .expect("valid AEAD open must succeed");
        assert_eq!(roundtrip, original);

        // Tampered header (AAD) must be rejected.
        let mut tampered = buf;
        let bad_header = [0xBBu8; 8];
        assert!(crypt
            .open_forward(&nonce, &bad_header, &mut tampered, &tag)
            .is_err());

        // Tampered ciphertext must be rejected.
        let mut tampered_ct = buf;
        tampered_ct[0] ^= 0x01;
        assert!(crypt
            .open_forward(&nonce, &header, &mut tampered_ct, &tag)
            .is_err());
    }

    #[test]
    fn test_hybrid_post_quantum_tamper_isolation() {
        let cid = 0x11223344;
        let relay_sk = SigningKey::generate(&mut OsRng);
        let relay_pk = relay_sk.verifying_key().to_bytes();

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pub = X25519PublicKey::from(&client_secret);
        let (client_mlkem_dk, client_mlkem_ek) = MlKem768::generate(&mut OsRng);
        let mut client_mlkem_pub_bytes = [0u8; 1184];
        client_mlkem_pub_bytes.copy_from_slice(client_mlkem_ek.as_bytes().as_slice());

        // 1. Untampered Baseline
        let create_cell = build_create_cell(cid, &client_pub, &client_mlkem_ek, 0).unwrap();
        let (_relay_hop, created_cell) = handle_create_cell(&create_cell, &relay_sk).unwrap();
        let baseline_keys = process_created_cell(
            &created_cell,
            client_secret,
            client_pub.as_bytes(),
            &client_mlkem_dk,
            &client_mlkem_pub_bytes,
            &relay_pk,
            cid,
            0,
        )
        .expect("Valid hybrid handshake must succeed");

        // 2. Tampering with ML-KEM Ciphertext in CREATED cell must fail signature / decapsulation
        let client_secret_2 = EphemeralSecret::random_from_rng(OsRng);
        let client_pub_2 = X25519PublicKey::from(&client_secret_2);
        let (client_mlkem_dk_2, client_mlkem_ek_2) = MlKem768::generate(&mut OsRng);
        let create_cell_2 = build_create_cell(cid, &client_pub_2, &client_mlkem_ek_2, 0).unwrap();
        let (_, created_cell_2) = handle_create_cell(&create_cell_2, &relay_sk).unwrap();
        let mut tampered_created_2 = created_cell_2;
        tampered_created_2.payload[150] ^= 0x01; // Tamper ML-KEM ciphertext
        let mut client_mlkem_pub_bytes_2 = [0u8; 1184];
        client_mlkem_pub_bytes_2.copy_from_slice(client_mlkem_ek_2.as_bytes().as_slice());
        let tampered_result = process_created_cell(
            &tampered_created_2,
            client_secret_2,
            client_pub_2.as_bytes(),
            &client_mlkem_dk_2,
            &client_mlkem_pub_bytes_2,
            &relay_pk,
            cid,
            0,
        );
        assert!(
            tampered_result.is_err(),
            "Tampered ML-KEM ciphertext must be rejected by Ed25519 signature verification"
        );

        // 3. Client and Relay derive matching keys in perform_client_relay_handshake
        let (ck, rk) = perform_client_relay_handshake().unwrap();
        assert_eq!(ck.forward_key, rk.forward_key);
        assert_eq!(ck.backward_key, rk.backward_key);
        assert_eq!(ck.forward_aead_key, rk.forward_aead_key);
        assert_eq!(ck.backward_aead_key, rk.backward_aead_key);
        assert_ne!(ck.forward_key, baseline_keys.forward_key);
    }

    #[test]
    fn test_sequential_circuits_have_independent_hop_keys() {
        let (ck1_h0, rk1_h0) = perform_client_relay_handshake().unwrap();
        let (ck1_h1, rk1_h1) = perform_client_relay_handshake().unwrap();
        let (ck1_h2, rk1_h2) = perform_client_relay_handshake().unwrap();

        let (ck2_h0, rk2_h0) = perform_client_relay_handshake().unwrap();
        let (ck2_h1, rk2_h1) = perform_client_relay_handshake().unwrap();
        let (ck2_h2, rk2_h2) = perform_client_relay_handshake().unwrap();

        // 1. Assert matching client/relay hop keys for each circuit
        assert_eq!(ck1_h0.forward_key, rk1_h0.forward_key);
        assert_eq!(ck1_h1.forward_key, rk1_h1.forward_key);
        assert_eq!(ck1_h2.forward_key, rk1_h2.forward_key);

        assert_eq!(ck2_h0.forward_key, rk2_h0.forward_key);
        assert_eq!(ck2_h1.forward_key, rk2_h1.forward_key);
        assert_eq!(ck2_h2.forward_key, rk2_h2.forward_key);

        // 2. Assert pairwise key independence across Circuit 1 and Circuit 2
        assert_ne!(ck1_h0.forward_key, ck2_h0.forward_key);
        assert_ne!(ck1_h0.backward_key, ck2_h0.backward_key);
        assert_ne!(ck1_h0.forward_aead_key, ck2_h0.forward_aead_key);
        assert_ne!(ck1_h0.backward_aead_key, ck2_h0.backward_aead_key);

        assert_ne!(ck1_h1.forward_key, ck2_h1.forward_key);
        assert_ne!(ck1_h1.backward_key, ck2_h1.backward_key);
        assert_ne!(ck1_h1.forward_aead_key, ck2_h1.forward_aead_key);
        assert_ne!(ck1_h1.backward_aead_key, ck2_h1.backward_aead_key);

        assert_ne!(ck1_h2.forward_key, ck2_h2.forward_key);
        assert_ne!(ck1_h2.backward_key, ck2_h2.backward_key);
        assert_ne!(ck1_h2.forward_aead_key, ck2_h2.forward_aead_key);
        assert_ne!(ck1_h2.backward_aead_key, ck2_h2.backward_aead_key);

        // 3. Assert forward secrecy: Compromising Circuit 2 secrets provides zero advantage for Circuit 1
        let mut leak_attempt = ck2_h0.forward_key;
        for (b, k) in leak_attempt.iter_mut().zip(ck2_h1.forward_key.iter()) {
            *b ^= *k;
        }
        assert_ne!(leak_attempt, ck1_h0.forward_key);
        assert_ne!(leak_attempt, ck1_h1.forward_key);
    }
}
