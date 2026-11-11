//! Noise secure channels (`docs/spec/pairing.md` §2), without I/O.
//!
//! | Use | Pattern | Prologue |
//! |---|---|---|
//! | Pairing | `Noise_XXpsk3_25519_ChaChaPoly_SHA256` | `"zeropass/v1/pairing"` |
//! | Sync | `Noise_IK_25519_ChaChaPoly_SHA256` | `"zeropass/v1/sync" ‖ 0x00 ‖ vault_id` |
//!
//! Both phases speak in frames of `length(2) ‖ Noise message` on an ordered byte
//! stream. A [`Handshake`] is fed the bytes received and returns the bytes to
//! send; once finished it becomes a [`SecureChannel`], which encrypts outgoing
//! data into frames and decrypts incoming frames back into data.

use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;
use zp_crypto::{ChannelKey, DeviceId, PUBLIC_KEY_LEN, VaultId};
use zp_sync::Registry;

use crate::PairingError;

const PATTERN_PAIRING: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA256";
const PATTERN_SYNC: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const PROLOGUE_PAIRING: &[u8] = b"zeropass/v1/pairing";
const PROLOGUE_SYNC: &[u8] = b"zeropass/v1/sync\0";

/// Largest Noise message.
const MAX_NOISE_MESSAGE: usize = 65535;
/// Length of the Poly1305 tag on every transport message.
const TAG_LEN: usize = 16;
/// Largest plaintext carried by one frame.
pub const MAX_FRAME_PLAINTEXT: usize = MAX_NOISE_MESSAGE - TAG_LEN;
/// Each direction's key is replaced after this many frames.
pub const REKEY_INTERVAL: u64 = 65536;
/// Length of the pre-shared key used for pairing.
pub const PSK_LEN: usize = 32;

/// A device's public channel key.
pub type ChannelPublicKey = [u8; PUBLIC_KEY_LEN];

/// Splits a byte stream into `length(2) ‖ body` frames.
#[derive(Debug, Default)]
struct Deframer {
    buffer: Vec<u8>,
}

impl Deframer {
    fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    fn next_frame(&mut self) -> Option<Vec<u8>> {
        let prefix = self.buffer.first_chunk::<2>()?;
        let length = usize::from(u16::from_be_bytes(*prefix));
        if self.buffer.len() < 2 + length {
            return None;
        }
        let frame = self.buffer[2..2 + length].to_vec();
        self.buffer.drain(..2 + length);
        Some(frame)
    }
}

fn frame(message: &[u8], out: &mut Vec<u8>) {
    debug_assert!(message.len() <= MAX_NOISE_MESSAGE);
    out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    out.extend_from_slice(message);
}

fn noise(_: snow::Error) -> PairingError {
    PairingError::Handshake
}

fn builder<'a>(
    pattern: &str,
    local: &'a ChannelKey,
    prologue: &'a [u8],
) -> Result<Builder<'a>, PairingError> {
    let params: NoiseParams = pattern.parse().map_err(noise)?;
    Builder::new(params)
        .local_private_key(local.secret_bytes())
        .map_err(noise)?
        .prologue(prologue)
        .map_err(noise)
}

/// A Noise handshake in progress.
pub struct Handshake {
    state: Box<HandshakeState>,
    deframer: Deframer,
    rekey_interval: u64,
}

impl Handshake {
    fn new(state: HandshakeState) -> Self {
        Self {
            state: Box::new(state),
            deframer: Deframer::default(),
            rekey_interval: REKEY_INTERVAL,
        }
    }

    /// The pairing handshake (`XXpsk3`). Neither side knows the other's key in
    /// advance; both must hold the one-time secret from the QR code. The side
    /// that scanned the code is the initiator.
    pub fn pairing(
        initiator: bool,
        local: &ChannelKey,
        psk: &[u8; PSK_LEN],
    ) -> Result<Self, PairingError> {
        let builder = builder(PATTERN_PAIRING, local, PROLOGUE_PAIRING)?
            .psk(3, psk)
            .map_err(noise)?;
        let state = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        };
        state.map(Self::new).map_err(noise)
    }

    /// The initiator's side of the sync handshake (`IK`) towards the device that
    /// owns `remote`. The handshake only completes with that device, and only if
    /// both sides belong to `vault_id`.
    pub fn sync_initiator(
        local: &ChannelKey,
        remote: &ChannelPublicKey,
        vault_id: &VaultId,
    ) -> Result<Self, PairingError> {
        let prologue = sync_prologue(vault_id);
        builder(PATTERN_SYNC, local, &prologue)?
            .remote_public_key(remote)
            .map_err(noise)?
            .build_initiator()
            .map(Self::new)
            .map_err(noise)
    }

    /// The responder's side of the sync handshake. The initiator's key becomes
    /// known during the handshake; the caller must check it against the device
    /// registry before using the channel ([`SecureChannel::remote_static`]).
    pub fn sync_responder(local: &ChannelKey, vault_id: &VaultId) -> Result<Self, PairingError> {
        let prologue = sync_prologue(vault_id);
        builder(PATTERN_SYNC, local, &prologue)?
            .build_responder()
            .map(Self::new)
            .map_err(noise)
    }

    /// Uses a shorter rekey interval, so tests can cross it.
    #[cfg(test)]
    fn with_rekey_interval(mut self, interval: u64) -> Self {
        self.rekey_interval = interval;
        self
    }

    /// Advances the handshake with the bytes received so far (possibly none, to
    /// obtain the initiator's first message). Returns the bytes to send.
    ///
    /// Any error is final: the handshake failed and the connection must be
    /// closed. Nothing about the cause is revealed to the peer.
    pub fn step(&mut self, received: &[u8]) -> Result<Vec<u8>, PairingError> {
        self.deframer.push(received);
        let mut out = Vec::new();
        let mut buffer = vec![0u8; MAX_NOISE_MESSAGE];
        loop {
            if self.state.is_handshake_finished() {
                break;
            }
            if self.state.is_my_turn() {
                // Handshake messages carry no application data.
                let length = self.state.write_message(&[], &mut buffer).map_err(noise)?;
                frame(&buffer[..length], &mut out);
            } else {
                let Some(message) = self.deframer.next_frame() else {
                    break;
                };
                let payload = self
                    .state
                    .read_message(&message, &mut buffer)
                    .map_err(noise)?;
                if payload != 0 {
                    return Err(PairingError::Handshake);
                }
            }
        }
        Ok(out)
    }

    /// Whether the handshake is complete and [`Self::into_channel`] can be called.
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Turns the finished handshake into the encrypted channel. Bytes the peer
    /// sent right behind its last handshake message are carried over.
    pub fn into_channel(self) -> Result<SecureChannel, PairingError> {
        if !self.state.is_handshake_finished() {
            return Err(PairingError::Handshake);
        }
        let remote_static: ChannelPublicKey = self
            .state
            .get_remote_static()
            .and_then(|key| key.try_into().ok())
            .ok_or(PairingError::Handshake)?;
        let state = self.state.into_transport_mode().map_err(noise)?;
        Ok(SecureChannel {
            state: Box::new(state),
            deframer: self.deframer,
            remote_static,
            sent: 0,
            received: 0,
            rekey_interval: self.rekey_interval,
            failed: false,
        })
    }
}

fn sync_prologue(vault_id: &VaultId) -> Vec<u8> {
    let mut prologue = PROLOGUE_SYNC.to_vec();
    prologue.extend_from_slice(vault_id.as_bytes());
    prologue
}

/// An established Noise channel over a byte stream.
pub struct SecureChannel {
    state: Box<TransportState>,
    deframer: Deframer,
    remote_static: ChannelPublicKey,
    sent: u64,
    received: u64,
    rekey_interval: u64,
    failed: bool,
}

impl SecureChannel {
    /// The peer's channel key, as authenticated by the handshake.
    pub fn remote_static(&self) -> &ChannelPublicKey {
        &self.remote_static
    }

    /// Identifies the peer in the device registry: the active device that owns
    /// the channel key authenticated by the handshake.
    ///
    /// The sync responder must call this before exchanging anything, because the
    /// `IK` handshake completes with any initiator that knows the responder's
    /// public key. A key that is unknown or belongs to a revoked device is
    /// refused.
    pub fn authenticate(&self, registry: &Registry) -> Result<DeviceId, PairingError> {
        registry
            .active_by_noise_pk(&self.remote_static)
            .map(|record| record.device_id)
            .ok_or(PairingError::UnknownPeer)
    }

    /// Encrypts `data` into frames ready to be written to the stream. Data
    /// longer than one frame is split; the receiver gets the same bytes back in
    /// order.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, PairingError> {
        if self.failed {
            return Err(PairingError::ChannelClosed);
        }
        let mut out =
            Vec::with_capacity(data.len() + (data.len() / MAX_FRAME_PLAINTEXT + 1) * (TAG_LEN + 2));
        let mut buffer = vec![0u8; MAX_NOISE_MESSAGE];
        for chunk in data.chunks(MAX_FRAME_PLAINTEXT) {
            let length = self
                .state
                .write_message(chunk, &mut buffer)
                .map_err(|_| self.fail())?;
            frame(&buffer[..length], &mut out);
            self.sent += 1;
            if self.sent.is_multiple_of(self.rekey_interval) {
                self.state.rekey_outgoing();
            }
        }
        Ok(out)
    }

    /// Takes bytes read from the stream and returns the data of every complete
    /// frame among them, decrypted and in order. Incomplete frames wait for more
    /// bytes.
    ///
    /// A frame that fails to authenticate (modified, replayed, reordered, or
    /// from someone else) closes the channel for good: every later call fails.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, PairingError> {
        if self.failed {
            return Err(PairingError::ChannelClosed);
        }
        self.deframer.push(bytes);
        let mut data = Zeroizing::new(Vec::new());
        let mut buffer = Zeroizing::new(vec![0u8; MAX_NOISE_MESSAGE]);
        while let Some(message) = self.deframer.next_frame() {
            let length = self
                .state
                .read_message(&message, &mut buffer)
                .map_err(|_| self.fail())?;
            data.extend_from_slice(&buffer[..length]);
            self.received += 1;
            if self.received.is_multiple_of(self.rekey_interval) {
                self.state.rekey_incoming();
            }
        }
        Ok(data)
    }

    fn fail(&mut self) -> PairingError {
        self.failed = true;
        PairingError::ChannelClosed
    }
}

impl core::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureChannel")
            .field("sent", &self.sent)
            .field("received", &self.received)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handshake")
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

/// Runs two handshakes against each other in memory. Returns both channels, or
/// the error of the side that failed first.
#[cfg(test)]
pub(crate) fn handshake_in_memory(
    mut initiator: Handshake,
    mut responder: Handshake,
) -> Result<(SecureChannel, SecureChannel), PairingError> {
    let mut to_responder = initiator.step(&[])?;
    for _ in 0..4 {
        let to_initiator = responder.step(&to_responder)?;
        to_responder = initiator.step(&to_initiator)?;
        if initiator.is_finished() && responder.is_finished() && to_responder.is_empty() {
            break;
        }
    }
    // Deliver a last message still in flight.
    let rest = responder.step(&to_responder)?;
    assert!(rest.is_empty());
    Ok((initiator.into_channel()?, responder.into_channel()?))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const VAULT: VaultId = VaultId::from_bytes([1; 16]);
    const PSK: [u8; PSK_LEN] = [0x42; PSK_LEN];

    fn key() -> ChannelKey {
        ChannelKey::generate().unwrap()
    }

    fn sync_pair(a: &ChannelKey, b: &ChannelKey) -> (SecureChannel, SecureChannel) {
        handshake_in_memory(
            Handshake::sync_initiator(a, b.public_bytes(), &VAULT).unwrap(),
            Handshake::sync_responder(b, &VAULT).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn pairing_handshake_authenticates_both_keys() {
        let (a, b) = (key(), key());
        let (mut channel_a, mut channel_b) = handshake_in_memory(
            Handshake::pairing(true, &a, &PSK).unwrap(),
            Handshake::pairing(false, &b, &PSK).unwrap(),
        )
        .unwrap();
        assert_eq!(channel_a.remote_static(), b.public_bytes());
        assert_eq!(channel_b.remote_static(), a.public_bytes());

        let wire = channel_a.send(b"vault keys go here").unwrap();
        assert!(!wire.windows(10).any(|window| window == b"vault keys"));
        assert_eq!(
            channel_b.receive(&wire).unwrap().as_slice(),
            b"vault keys go here"
        );
        let wire = channel_b.send(b"ack").unwrap();
        assert_eq!(channel_a.receive(&wire).unwrap().as_slice(), b"ack");
    }

    #[test]
    fn pairing_fails_without_the_secret_from_the_qr_code() {
        let (a, b) = (key(), key());
        let wrong = [0x43; PSK_LEN];
        let result = handshake_in_memory(
            Handshake::pairing(true, &a, &wrong).unwrap(),
            Handshake::pairing(false, &b, &PSK).unwrap(),
        );
        assert_eq!(result.unwrap_err(), PairingError::Handshake);
    }

    #[test]
    fn sync_handshake_reveals_the_initiator_to_the_responder_only() {
        let (a, b) = (key(), key());
        let mut initiator = Handshake::sync_initiator(&a, b.public_bytes(), &VAULT).unwrap();
        let first = initiator.step(&[]).unwrap();
        // The initiator's static key travels encrypted.
        assert!(!first.windows(32).any(|window| window == a.public_bytes()));

        let (channel_a, channel_b) = sync_pair(&a, &b);
        assert_eq!(channel_b.remote_static(), a.public_bytes());
        assert_eq!(channel_a.remote_static(), b.public_bytes());
    }

    #[test]
    fn sync_handshake_fails_with_the_wrong_device_or_vault() {
        let (a, b, other) = (key(), key(), key());
        // The initiator expects another device than the one answering.
        let result = handshake_in_memory(
            Handshake::sync_initiator(&a, other.public_bytes(), &VAULT).unwrap(),
            Handshake::sync_responder(&b, &VAULT).unwrap(),
        );
        assert_eq!(result.unwrap_err(), PairingError::Handshake);

        // Same devices, different vaults.
        let other_vault = VaultId::from_bytes([2; 16]);
        let result = handshake_in_memory(
            Handshake::sync_initiator(&a, b.public_bytes(), &VAULT).unwrap(),
            Handshake::sync_responder(&b, &other_vault).unwrap(),
        );
        assert_eq!(result.unwrap_err(), PairingError::Handshake);

        // A pairing initiator against a sync responder.
        let result = handshake_in_memory(
            Handshake::pairing(true, &a, &PSK).unwrap(),
            Handshake::sync_responder(&b, &VAULT).unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn the_responder_only_accepts_members_of_the_vault() {
        use zp_sync::{MemoryLog, OpLog};

        // A vault with two members, each with a real channel key.
        let (key_a, key_b, key_stranger) = (key(), key(), key());
        let mut log_a = MemoryLog::new_vault("a", *key_a.public_bytes()).unwrap();
        let log_b = MemoryLog::join(&mut log_a, "b", *key_b.public_bytes()).unwrap();
        let vault_id = log_a.vault_id();
        let connect = |initiator: &ChannelKey| {
            handshake_in_memory(
                Handshake::sync_initiator(initiator, key_a.public_bytes(), &vault_id).unwrap(),
                Handshake::sync_responder(&key_a, &vault_id).unwrap(),
            )
            .unwrap()
        };

        // A member is identified by its channel key.
        let (_, channel) = connect(&key_b);
        assert_eq!(
            channel.authenticate(&log_a.registry().unwrap()),
            Ok(log_b.device_id())
        );

        // Anyone who knows A's public key and the vault identifier can complete
        // the handshake, but is not in the registry.
        let (_, channel) = connect(&key_stranger);
        assert_eq!(
            channel.authenticate(&log_a.registry().unwrap()),
            Err(PairingError::UnknownPeer)
        );

        // A revoked member is refused as well.
        log_a.revoke(log_b.device_id()).unwrap();
        let (_, channel) = connect(&key_b);
        assert_eq!(
            channel.authenticate(&log_a.registry().unwrap()),
            Err(PairingError::UnknownPeer)
        );
    }

    #[test]
    fn garbage_instead_of_a_handshake_fails_cleanly() {
        let b = key();
        for garbage in [&[0u8, 3, 1, 2, 3][..], &[0, 0], &[0xFF; 200]] {
            let mut responder = Handshake::sync_responder(&b, &VAULT).unwrap();
            // Either rejected or (for an incomplete frame) simply waiting.
            let result = responder.step(garbage);
            assert!(matches!(result, Err(PairingError::Handshake) | Ok(_)));
            assert!(!responder.is_finished());
        }
        let unfinished = Handshake::sync_responder(&b, &VAULT).unwrap();
        assert_eq!(
            unfinished.into_channel().unwrap_err(),
            PairingError::Handshake
        );
    }

    #[test]
    fn handshake_bytes_may_arrive_in_pieces() {
        let (a, b) = (key(), key());
        let mut initiator = Handshake::sync_initiator(&a, b.public_bytes(), &VAULT).unwrap();
        let mut responder = Handshake::sync_responder(&b, &VAULT).unwrap();
        let first = initiator.step(&[]).unwrap();
        let mut reply = Vec::new();
        for byte in &first {
            reply.extend(responder.step(std::slice::from_ref(byte)).unwrap());
        }
        for piece in reply.chunks(5) {
            assert!(initiator.step(piece).unwrap().is_empty());
        }
        assert!(initiator.is_finished() && responder.is_finished());
    }

    #[test]
    fn data_pipelined_behind_the_handshake_is_not_lost() {
        let (a, b) = (key(), key());
        let mut initiator = Handshake::sync_initiator(&a, b.public_bytes(), &VAULT).unwrap();
        let mut responder = Handshake::sync_responder(&b, &VAULT).unwrap();
        let first = initiator.step(&[]).unwrap();
        let reply = responder.step(&first).unwrap();
        // The responder is done and sends data right behind its handshake reply.
        let mut channel_b = responder.into_channel().unwrap();
        let mut bytes = reply;
        bytes.extend(channel_b.send(b"hello right away").unwrap());

        assert!(initiator.step(&bytes).unwrap().is_empty());
        let mut channel_a = initiator.into_channel().unwrap();
        assert_eq!(
            channel_a.receive(&[]).unwrap().as_slice(),
            b"hello right away"
        );
    }

    #[test]
    fn large_data_is_split_into_frames_and_reassembled() {
        let (a, b) = (key(), key());
        let (mut channel_a, mut channel_b) = sync_pair(&a, &b);
        let data: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();

        let wire = channel_a.send(&data).unwrap();
        // Four frames: three full ones and the rest.
        assert_eq!(wire.len(), data.len() + 4 * (2 + TAG_LEN));
        let mut received = Vec::new();
        for piece in wire.chunks(1000) {
            received.extend_from_slice(&channel_b.receive(piece).unwrap());
        }
        assert_eq!(received, data);
        // Empty data sends nothing.
        assert!(channel_a.send(&[]).unwrap().is_empty());
    }

    #[test]
    fn a_tampered_replayed_or_reordered_frame_closes_the_channel() {
        let (a, b) = (key(), key());

        // Tampered.
        let (mut channel_a, mut channel_b) = sync_pair(&a, &b);
        let mut wire = channel_a.send(b"first").unwrap();
        wire[5] ^= 1;
        assert_eq!(
            channel_b.receive(&wire).unwrap_err(),
            PairingError::ChannelClosed
        );
        // The channel stays closed, even for a genuine frame.
        let genuine = channel_a.send(b"second").unwrap();
        assert_eq!(
            channel_b.receive(&genuine).unwrap_err(),
            PairingError::ChannelClosed
        );
        assert_eq!(
            channel_b.send(b"x").unwrap_err(),
            PairingError::ChannelClosed
        );

        // Replayed.
        let (mut channel_a, mut channel_b) = sync_pair(&a, &b);
        let wire = channel_a.send(b"first").unwrap();
        channel_b.receive(&wire).unwrap();
        assert_eq!(
            channel_b.receive(&wire).unwrap_err(),
            PairingError::ChannelClosed
        );

        // Reordered.
        let (mut channel_a, mut channel_b) = sync_pair(&a, &b);
        let first = channel_a.send(b"first").unwrap();
        let second = channel_a.send(b"second").unwrap();
        assert_eq!(
            channel_b.receive(&second).unwrap_err(),
            PairingError::ChannelClosed
        );
        let _ = first;

        // Reflected back to its sender.
        let (mut channel_a, _channel_b) = sync_pair(&a, &b);
        let wire = channel_a.send(b"first").unwrap();
        assert_eq!(
            channel_a.receive(&wire).unwrap_err(),
            PairingError::ChannelClosed
        );
    }

    #[test]
    fn frames_of_another_session_are_rejected() {
        let (a, b) = (key(), key());
        let (mut first_a, _first_b) = sync_pair(&a, &b);
        let (_second_a, mut second_b) = sync_pair(&a, &b);
        let wire = first_a.send(b"from another session").unwrap();
        assert_eq!(
            second_b.receive(&wire).unwrap_err(),
            PairingError::ChannelClosed
        );
    }

    #[test]
    fn both_directions_rekey_in_step() {
        let (a, b) = (key(), key());
        let (mut channel_a, mut channel_b) = handshake_in_memory(
            Handshake::sync_initiator(&a, b.public_bytes(), &VAULT)
                .unwrap()
                .with_rekey_interval(3),
            Handshake::sync_responder(&b, &VAULT)
                .unwrap()
                .with_rekey_interval(3),
        )
        .unwrap();
        // Ten frames each way cross several rekeys, in an uneven rhythm.
        for round in 0..10u8 {
            let wire = channel_a.send(&[round; 20]).unwrap();
            assert_eq!(channel_b.receive(&wire).unwrap().as_slice(), [round; 20]);
            if round % 3 == 0 {
                let wire = channel_b.send(&[round; 7]).unwrap();
                assert_eq!(channel_a.receive(&wire).unwrap().as_slice(), [round; 7]);
            }
        }

        // If only one side rekeys, the next frame no longer authenticates.
        let (mut channel_a, mut channel_b) = handshake_in_memory(
            Handshake::sync_initiator(&a, b.public_bytes(), &VAULT)
                .unwrap()
                .with_rekey_interval(2),
            Handshake::sync_responder(&b, &VAULT).unwrap(),
        )
        .unwrap();
        for _ in 0..2 {
            let wire = channel_a.send(b"ok").unwrap();
            channel_b.receive(&wire).unwrap();
        }
        let wire = channel_a.send(b"after the sender's rekey").unwrap();
        assert_eq!(
            channel_b.receive(&wire).unwrap_err(),
            PairingError::ChannelClosed
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn any_data_survives_any_fragmentation(
            messages in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..3000), 1..8),
            cut in 1usize..700,
        ) {
            let (a, b) = (key(), key());
            let (mut channel_a, mut channel_b) = sync_pair(&a, &b);
            let mut wire = Vec::new();
            for message in &messages {
                wire.extend(channel_a.send(message).unwrap());
            }
            let mut received = Vec::new();
            for piece in wire.chunks(cut) {
                received.extend_from_slice(&channel_b.receive(piece).unwrap());
            }
            prop_assert_eq!(received, messages.concat());
        }

        #[test]
        fn arbitrary_bytes_never_authenticate(bytes in proptest::collection::vec(any::<u8>(), 3..200)) {
            let (a, b) = (key(), key());
            let (_channel_a, mut channel_b) = sync_pair(&a, &b);
            // Either an incomplete frame (no data) or a closed channel.
            match channel_b.receive(&bytes) {
                Ok(data) => prop_assert!(data.is_empty()),
                Err(error) => prop_assert_eq!(error, PairingError::ChannelClosed),
            }
        }
    }
}
