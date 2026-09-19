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
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::onion::cell::{CellCommand, OnionCell, ONION_CELL_SIZE};
use thiserror::Error;

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

pub struct HopKeys {
    pub forward_key: [u8; 32],
    pub backward_key: [u8; 32],
    pub forward_mac: [u8; 32],
    pub backward_mac: [u8; 32],
    pub forward_aead_key: [u8; 32],
    pub backward_aead_key: [u8; 32],
}

impl Drop for HopKeys {
    fn drop(&mut self) {
        self.forward_key.fill(0);
        self.backward_key.fill(0);
        self.forward_mac.fill(0);
        self.backward_mac.fill(0);
        self.forward_aead_key.fill(0);
        self.backward_aead_key.fill(0);
    }
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
            .expect("ChaCha20Poly1305 in-place encryption cannot fail for correctly sized buffers");
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
            .expect("ChaCha20Poly1305 in-place encryption cannot fail for correctly sized buffers");
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

/// Key derivation function turning an X25519 shared secret into forward, backward, and MAC keys.
/// Uses RFC 5869 HKDF-SHA256 with domain-separated info labels for key commitment.
/// IKM is the uniform 32-byte X25519 shared secret; salt is empty (uniform input).
pub fn derive_hop_keys(shared_secret: &[u8; 32]) -> Result<HopKeys, CircuitError> {
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
            let (pt, mac_buf) = body.split_at_mut(1000);

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
        let (ct, mac_buf) = body.split_at_mut(1000);

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
            let (pt, mac_buf) = body.split_at_mut(1000);
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

            let cell = OnionCell::parse(raw).map_err(|e| {
                CircuitError::ParseError(format!("MAC verified but cell parse failed: {}", e))
            })?;
            return Ok(PeelOutcome::AddressedToThisRelay {
                command: cell.command,
                len: (cell.length as usize).min(cell.payload.len()),
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
        let (pt, mac_buf) = body.split_at_mut(1000);

        let tag = self.crypt.seal_backward(&nonce, header, pt);
        mac_buf.copy_from_slice(&tag);
        Ok(())
    }
}

/// Builds a CREATE cell carrying the client's ephemeral X25519 public key.
pub fn build_create_cell(
    circuit_id: u32,
    client_pub: &X25519PublicKey,
    hop_index: usize,
) -> Result<OnionCell, CircuitError> {
    let mut payload = [0u8; 33];
    payload[0] = hop_index as u8;
    payload[1..33].copy_from_slice(client_pub.as_bytes());
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
    if create_cell.length < 33 {
        return Err(CircuitError::PayloadTooShort);
    }
    let hop_index = create_cell.payload[0] as usize;
    if hop_index >= MAX_HOPS {
        return Err(CircuitError::HopIndexOutOfRange(hop_index));
    }

    let client_pub_bytes: [u8; 32] = create_cell.payload[1..33]
        .try_into()
        .map_err(|_| CircuitError::ParseError("Failed to extract client public key".to_string()))?;
    let client_pub = X25519PublicKey::from(client_pub_bytes);

    let relay_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_pub = X25519PublicKey::from(&relay_secret);

    let shared = relay_secret.diffie_hellman(&client_pub);
    // Non-contributory DH rejection (V-03)
    if shared.as_bytes() == &[0u8; 32] {
        return Err(CircuitError::General(
            "Non-contributory DH key rejected".to_string(),
        ));
    }

    let keys = derive_hop_keys(shared.as_bytes())?;

    let identity_pub = relay_identity_key.verifying_key();
    let mut preimage = Vec::with_capacity(6 + 32 + 32);
    preimage.extend_from_slice(b"AnonGuard-handshake-v1");
    preimage.extend_from_slice(relay_pub.as_bytes());
    preimage.extend_from_slice(client_pub_bytes.as_ref());
    let handshake_sig: Signature = relay_identity_key.sign(&preimage);

    let mut created_payload = [0u8; 128];
    created_payload[0..32].copy_from_slice(relay_pub.as_bytes());
    created_payload[32..64].copy_from_slice(identity_pub.as_bytes());
    created_payload[64..128].copy_from_slice(&handshake_sig.to_bytes());

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

pub fn process_created_cell(
    created_cell: &OnionCell,
    client_secret: EphemeralSecret,
    client_pub_bytes: &[u8; 32],
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
    if created_cell.length < 128 {
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

    let mut preimage = Vec::with_capacity(6 + 32 + 32);
    preimage.extend_from_slice(b"AnonGuard-handshake-v1");
    preimage.extend_from_slice(&relay_eph_pub_bytes);
    preimage.extend_from_slice(client_pub_bytes);

    verifying_key
        .verify_strict(&preimage, &signature)
        .map_err(|_| {
            CircuitError::General("Handshake Ed25519 signature verification failed".to_string())
        })?;

    let relay_eph_pub = X25519PublicKey::from(relay_eph_pub_bytes);
    let shared = client_secret.diffie_hellman(&relay_eph_pub);
    // V-03: non-contributory DH rejection
    if shared.as_bytes() == &[0u8; 32] {
        return Err(CircuitError::General(
            "Non-contributory DH key rejected".to_string(),
        ));
    }

    derive_hop_keys(shared.as_bytes())
}

pub fn encode_extend_payload(
    next_host: &str,
    next_port: u16,
    client_pub: &X25519PublicKey,
    hop_index: usize,
) -> Result<Vec<u8>, CircuitError> {
    let host_bytes = next_host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(CircuitError::General(
            "Host string exceeds 255 bytes limit".to_string(),
        ));
    }

    let mut payload = Vec::with_capacity(1 + 1 + host_bytes.len() + 2 + 32);
    payload.push(hop_index as u8);
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);
    payload.extend_from_slice(&next_port.to_be_bytes());
    payload.extend_from_slice(client_pub.as_bytes());
    Ok(payload)
}

pub fn decode_extend_payload(
    payload: &[u8],
) -> Result<(String, u16, X25519PublicKey, usize), CircuitError> {
    if payload.len() < 1 + 1 + 2 + 32 {
        return Err(CircuitError::PayloadTooShort);
    }
    let hop_index = payload[0] as usize;
    let host_len = payload[1] as usize;
    if payload.len() < 1 + 1 + host_len + 2 + 32 {
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

    Ok((host, port, client_pub, hop_index))
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

pub fn perform_client_relay_handshake() -> (HopKeys, HopKeys) {
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = X25519PublicKey::from(&client_secret);

    let relay_secret = EphemeralSecret::random_from_rng(OsRng);
    let relay_public = X25519PublicKey::from(&relay_secret);

    let client_shared = client_secret.diffie_hellman(&relay_public);
    let relay_shared = relay_secret.diffie_hellman(&client_public);

    let client_keys = derive_hop_keys(client_shared.as_bytes()).unwrap();
    let relay_keys = derive_hop_keys(relay_shared.as_bytes()).unwrap();

    (client_keys, relay_keys)
}

#[cfg(test)]
mod aead_key_derivation_tests {
    use super::*;

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
}
