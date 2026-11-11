//! The sync session (`docs/spec/sync.md` §7) as a state machine without I/O.
//!
//! Both sides run the same machine. The caller owns the transport: it feeds each
//! received message to [`Session::receive`] and sends whatever
//! [`Session::poll_send`] hands out, until [`Session::is_complete`].
//!
//! ```text
//! Hello → Devices → Vector → Ops … Ops(last) → Done
//! ```
//!
//! Each side sends this sequence and expects the same sequence from its peer.
//! The two directions are independent, except that a side can only choose which
//! ops to send after it has seen the peer's `Vector`, and only sends `Done` after
//! it has taken in all of the peer's ops.

use std::collections::VecDeque;

use zp_crypto::DeviceId;

use crate::wire::{self, Body, Envelope, Hello, Ops};
use crate::{ApplyReport, ChannelPublicKey, Op, OpLog, SyncError, VersionVector};

/// The version of the session protocol implemented here.
pub const PROTOCOL_VERSION: u32 = 1;

/// Ops are batched until a message reaches about this size.
const BATCH_TARGET_LEN: usize = 256 * 1024;
/// At most this many ops are read from the store at a time.
const READ_CHUNK: usize = 256;

/// What the peer may send next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Hello,
    Devices,
    Vector,
    Ops,
    Done,
    Nothing,
}

/// What a finished (or interrupted) session did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionReport {
    /// The device on the other side, once it has introduced itself.
    pub peer: Option<DeviceId>,
    /// What happened to the ops received.
    pub received: ApplyReport,
    /// How many ops were sent.
    pub sent: usize,
    /// Whether the registry changed because of what the peer sent.
    pub registry_changed: bool,
    /// The peer's version vector at the end of the session, once received.
    pub peer_vector: Option<VersionVector>,
}

/// A range of one author's ops still to be sent: `after < seq <= up_to`.
#[derive(Debug, Clone, Copy)]
struct Pending {
    device: DeviceId,
    after: u64,
    up_to: u64,
}

/// One side of a sync session.
#[derive(Debug)]
pub struct Session {
    /// The channel key the transport authenticated for the peer, if any.
    channel_peer: Option<ChannelPublicKey>,
    expect: Expect,
    /// Messages ready to be sent.
    outbox: VecDeque<Vec<u8>>,
    /// Op ranges to send, known once the peer's vector has arrived.
    pending: Option<VecDeque<Pending>>,
    sent_last_ops: bool,
    received_last_ops: bool,
    sent_done: bool,
    report: SessionReport,
}

impl Session {
    /// Starts a session over a channel whose far end the transport
    /// authenticated as the owner of `channel_peer` (the static key of the Noise
    /// handshake).
    ///
    /// The session then only talks to the device that the registry lists with
    /// exactly that channel key. This is checked after the registries have been
    /// exchanged, so a device this side had not heard of yet is accepted if it
    /// brings a valid record of itself; someone who merely completed the
    /// handshake is not. Pass `None` only where there is no channel to bind to
    /// (in-memory tests). The opening messages are queued immediately.
    pub fn start<L: OpLog>(
        log: &L,
        channel_peer: Option<ChannelPublicKey>,
    ) -> Result<Self, L::Error> {
        let registry = log.registry()?;
        let mut outbox = VecDeque::new();
        outbox.push_back(Envelope::encode_body(Body::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            vault_id: log.vault_id().as_bytes().to_vec(),
            device_id: log.device_id().as_bytes().to_vec(),
        }))?);
        outbox.push_back(Envelope::encode_body(Body::Devices(wire::Devices {
            records: registry.records().map(Into::into).collect(),
            revocations: registry.revocations().map(Into::into).collect(),
        }))?);
        outbox.push_back(Envelope::encode_body(Body::Vector(
            (&log.version_vector()?).into(),
        ))?);

        Ok(Self {
            channel_peer,
            expect: Expect::Hello,
            outbox,
            pending: None,
            sent_last_ops: false,
            received_last_ops: false,
            sent_done: false,
            report: SessionReport::default(),
        })
    }

    /// Whether both sides have sent and received everything.
    pub fn is_complete(&self) -> bool {
        self.sent_done && self.expect == Expect::Nothing && self.outbox.is_empty()
    }

    /// What the session has done so far.
    pub fn report(&self) -> &SessionReport {
        &self.report
    }

    /// Handles one message from the peer.
    ///
    /// Any error ends the session: the caller must drop it and close the
    /// channel. Ops applied before the error stay applied; the next session
    /// resumes from the version vectors.
    pub fn receive<L: OpLog>(&mut self, log: &mut L, message: &[u8]) -> Result<(), L::Error> {
        let body = Envelope::decode_body(message)?;
        match (self.expect, body) {
            (Expect::Hello, Body::Hello(hello)) => {
                if hello.protocol_version != PROTOCOL_VERSION {
                    return Err(SyncError::UnsupportedVersion(hello.protocol_version).into());
                }
                if wire::vault_id(&hello.vault_id)? != log.vault_id() {
                    return Err(SyncError::VaultMismatch.into());
                }
                let peer = wire::device_id(&hello.device_id)?;
                if peer == log.device_id() {
                    return Err(SyncError::UnexpectedPeer.into());
                }
                self.report.peer = Some(peer);
                self.expect = Expect::Devices;
            }
            (Expect::Devices, Body::Devices(devices)) => {
                let records = devices
                    .records
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, _>>()?;
                let revocations = devices
                    .revocations
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, _>>()?;
                self.report.registry_changed = log.merge_registry(records, revocations)?;
                // Only members in good standing may sync, by this side's
                // knowledge after merging what the peer knows.
                let peer = self
                    .report
                    .peer
                    .ok_or(SyncError::ProtocolViolation("no hello"))?;
                let registry = log.registry()?;
                if registry.is_revoked(&peer) {
                    return Err(SyncError::RevokedDevice(peer).into());
                }
                let Some(record) = registry.get(&peer) else {
                    return Err(SyncError::UnknownDevice(peer).into());
                };
                if self.channel_peer.is_some_and(|key| key != record.noise_pk) {
                    return Err(SyncError::UnexpectedPeer.into());
                }
                if registry.is_revoked(&log.device_id()) {
                    return Err(SyncError::RevokedDevice(log.device_id()).into());
                }
                self.expect = Expect::Vector;
            }
            (Expect::Vector, Body::Vector(vector)) => {
                let theirs = VersionVector::try_from(vector)?;
                let mine = log.version_vector()?;
                self.pending = Some(
                    mine.ahead_of(&theirs)
                        .into_iter()
                        .map(|(device, after, up_to)| Pending {
                            device,
                            after,
                            up_to,
                        })
                        .collect(),
                );
                self.expect = Expect::Ops;
            }
            (Expect::Ops, Body::Ops(ops)) => {
                let last = ops.last;
                let ops = ops
                    .ops
                    .into_iter()
                    .map(Op::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                self.report.received.absorb(log.apply(ops)?);
                if last {
                    self.received_last_ops = true;
                    self.expect = Expect::Done;
                }
            }
            (Expect::Done, Body::Done(vector)) => {
                self.report.peer_vector = Some(VersionVector::try_from(vector)?);
                self.expect = Expect::Nothing;
            }
            _ => return Err(SyncError::ProtocolViolation("unexpected message").into()),
        }
        Ok(())
    }

    /// The next message to send, if there is one right now.
    ///
    /// Call this until it returns `None` after starting the session and after
    /// every [`Self::receive`]. Ops are read from the store only as they are
    /// handed out, so a slow transport holds back the reading.
    pub fn poll_send<L: OpLog>(&mut self, log: &L) -> Result<Option<Vec<u8>>, L::Error> {
        if let Some(message) = self.outbox.pop_front() {
            return Ok(Some(message));
        }
        if !self.sent_last_ops {
            let Some(pending) = self.pending.as_mut() else {
                // The peer's vector has not arrived yet.
                return Ok(None);
            };
            let mut batch = Vec::new();
            let mut batch_len = 0;
            while batch_len < BATCH_TARGET_LEN {
                let Some(range) = pending.front_mut() else {
                    break;
                };
                let ops = log.ops_after(range.device, range.after, READ_CHUNK)?;
                // The store returns a gap-free run; an empty or short run means
                // the rest cannot be offered (for example, not signed yet).
                let wanted = ops.into_iter().take_while(|op| op.body.seq <= range.up_to);
                let mut taken = 0;
                for op in wanted {
                    let message = wire::OpMsg::from(&op);
                    batch_len += prost::Message::encoded_len(&message) + 4;
                    range.after = op.body.seq;
                    batch.push(message);
                    taken += 1;
                    if batch_len >= BATCH_TARGET_LEN {
                        break;
                    }
                }
                if taken == 0 || range.after >= range.up_to {
                    pending.pop_front();
                }
            }
            let last = pending.is_empty();
            self.report.sent += batch.len();
            self.sent_last_ops = last;
            return Ok(Some(Envelope::encode_body(Body::Ops(Ops {
                ops: batch,
                last,
            }))?));
        }
        if self.received_last_ops && !self.sent_done {
            self.sent_done = true;
            let vector = log.version_vector()?;
            return Ok(Some(Envelope::encode_body(Body::Done((&vector).into()))?));
        }
        Ok(None)
    }
}

/// Runs two sessions against each other in memory until neither has anything
/// left to send. Returns the reports of `a` and `b`.
///
/// This is the whole protocol without a transport; real drivers do the same
/// with a channel in between.
pub fn sync_in_memory<A: OpLog, B: OpLog>(
    a: &mut A,
    b: &mut B,
) -> Result<(SessionReport, SessionReport), InMemoryError<A::Error, B::Error>> {
    let mut session_a = Session::start(a, None).map_err(InMemoryError::A)?;
    let mut session_b = Session::start(b, None).map_err(InMemoryError::B)?;
    loop {
        let mut progressed = false;
        while let Some(message) = session_a.poll_send(a).map_err(InMemoryError::A)? {
            session_b.receive(b, &message).map_err(InMemoryError::B)?;
            progressed = true;
        }
        while let Some(message) = session_b.poll_send(b).map_err(InMemoryError::B)? {
            session_a.receive(a, &message).map_err(InMemoryError::A)?;
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    debug_assert!(session_a.is_complete() && session_b.is_complete());
    Ok((session_a.report, session_b.report))
}

/// Which side of [`sync_in_memory`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InMemoryError<A, B> {
    /// The first store or its session failed.
    #[error("first side: {0}")]
    A(A),
    /// The second store or its session failed.
    #[error("second side: {0}")]
    B(B),
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use zp_crypto::{DomainId, ItemId};

    use super::*;
    use crate::{MemoryLog, Payload};

    fn payload(byte: u8, len: usize) -> Option<Payload> {
        Some(Payload {
            wrapped_dek: vec![byte; 73],
            ciphertext: vec![byte; len],
        })
    }

    fn item(n: u8) -> ItemId {
        ItemId::from_bytes([n; 16])
    }

    /// Devices of one vault. Only the first knows all of them: the others know
    /// the first and themselves, as after pairing.
    fn devices(count: usize) -> Vec<MemoryLog> {
        let mut logs = vec![MemoryLog::new_vault("device 0", [0; 32]).unwrap()];
        for n in 1..count {
            let joined =
                MemoryLog::join(&mut logs[0], &format!("device {n}"), [n as u8; 32]).unwrap();
            logs.push(joined);
        }
        logs
    }

    fn two(logs: &mut [MemoryLog], a: usize, b: usize) -> (&mut MemoryLog, &mut MemoryLog) {
        assert!(a < b);
        let (left, right) = logs.split_at_mut(b);
        (&mut left[a], &mut right[0])
    }

    fn sync(logs: &mut [MemoryLog], a: usize, b: usize) -> (SessionReport, SessionReport) {
        let (first, second) = if a < b {
            two(logs, a, b)
        } else {
            let (x, y) = two(logs, b, a);
            (y, x)
        };
        sync_in_memory(first, second).unwrap()
    }

    #[test]
    fn two_devices_exchange_what_the_other_lacks() {
        let mut logs = devices(2);
        logs[0]
            .write(item(1), DomainId::Password, payload(1, 40))
            .unwrap();
        logs[0]
            .write(item(2), DomainId::Totp, payload(2, 40))
            .unwrap();
        logs[1]
            .write(item(3), DomainId::Password, payload(3, 40))
            .unwrap();

        let (report_a, report_b) = sync(&mut logs, 0, 1);
        assert_eq!((report_a.sent, report_a.received.applied), (2, 1));
        assert_eq!((report_b.sent, report_b.received.applied), (1, 2));
        assert_eq!(report_a.peer, Some(logs[1].device_id()));
        assert_eq!(report_b.peer, Some(logs[0].device_id()));
        assert_eq!(logs[0].snapshot(), logs[1].snapshot());
        // Each side learns the other's final vector, and they agree.
        let final_vector = logs[0].version_vector().unwrap();
        assert_eq!(report_a.peer_vector, Some(final_vector.clone()));
        assert_eq!(report_b.peer_vector, Some(final_vector));

        // A second session has nothing to do.
        let (report_a, report_b) = sync(&mut logs, 0, 1);
        assert_eq!((report_a.sent, report_b.sent), (0, 0));
        assert_eq!(report_a.received, ApplyReport::default());
    }

    #[test]
    fn devices_learn_about_each_other_through_a_common_peer() {
        // Device 1 and device 2 were both introduced by device 0 and have never
        // heard of each other.
        let mut logs = devices(3);
        assert!(
            logs[1]
                .registry()
                .unwrap()
                .get(&logs[2].device_id())
                .is_none()
        );
        logs[2]
            .write(item(1), DomainId::Password, payload(1, 40))
            .unwrap();

        // 2 → 0, then 0 → 1: device 1 receives an op authored by a device it
        // only learns about in the same session.
        sync(&mut logs, 0, 2);
        let (_, report_1) = sync(&mut logs, 0, 1);
        assert!(report_1.registry_changed);
        assert_eq!(report_1.received.applied, 1);
        assert!(logs[1].registry().unwrap().is_active(&logs[2].device_id()));
        assert_eq!(logs[1].snapshot(), logs[2].snapshot());

        // Now 1 and 2 know each other and can sync directly.
        sync(&mut logs, 0, 2);
        logs[1]
            .write(item(2), DomainId::Password, payload(2, 40))
            .unwrap();
        let (_, report_2) = sync(&mut logs, 1, 2);
        assert_eq!(report_2.received.applied, 1);
    }

    #[test]
    fn large_histories_are_sent_in_several_batches() {
        let mut logs = devices(2);
        // ~1.2 MiB of ops: more than fits one message.
        for n in 0..300u32 {
            logs[0]
                .write(
                    item((n % 250) as u8),
                    DomainId::Password,
                    payload(n as u8, 4000),
                )
                .unwrap();
        }
        let (a, b) = two(&mut logs, 0, 1);
        let mut session_a = Session::start(a, None).unwrap();
        let mut session_b = Session::start(b, None).unwrap();
        let mut ops_messages = 0;
        loop {
            let mut progressed = false;
            while let Some(message) = session_a.poll_send(a).unwrap() {
                assert!(message.len() <= wire::MAX_MESSAGE_LEN);
                if matches!(Envelope::decode_body(&message).unwrap(), Body::Ops(_)) {
                    ops_messages += 1;
                }
                session_b.receive(b, &message).unwrap();
                progressed = true;
            }
            while let Some(message) = session_b.poll_send(b).unwrap() {
                session_a.receive(a, &message).unwrap();
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        assert!(session_a.is_complete() && session_b.is_complete());
        assert!(ops_messages >= 4, "{ops_messages} ops messages");
        assert_eq!(session_a.report().sent, 300);
        assert_eq!(a.snapshot(), b.snapshot());
    }

    #[test]
    fn an_interrupted_session_is_resumed_by_the_next_one() {
        let mut logs = devices(2);
        for n in 0..200u32 {
            logs[0]
                .write(item(n as u8), DomainId::Password, payload(n as u8, 4000))
                .unwrap();
        }
        let (a, b) = two(&mut logs, 0, 1);
        let mut session_a = Session::start(a, None).unwrap();
        let mut session_b = Session::start(b, None).unwrap();
        // Opening messages both ways, then only the first batch of ops.
        for _ in 0..3 {
            let message = session_b.poll_send(b).unwrap().unwrap();
            session_a.receive(a, &message).unwrap();
        }
        for _ in 0..4 {
            let message = session_a.poll_send(a).unwrap().unwrap();
            session_b.receive(b, &message).unwrap();
        }
        // The connection drops here.
        assert!(!session_b.is_complete());
        let received = session_b.report().received.applied;
        assert!(received > 0 && received < 200, "{received}");
        drop((session_a, session_b));

        // What arrived is kept, and a new session sends only the rest.
        assert_eq!(
            b.version_vector().unwrap().get(&a.device_id()),
            received as u64
        );
        let (report_a, _) = sync_in_memory(a, b).unwrap();
        assert_eq!(report_a.sent, 200 - received);
        assert_eq!(a.snapshot(), b.snapshot());
    }

    #[test]
    fn strangers_and_other_vaults_are_refused() {
        let mut logs = devices(2);
        let mut other_vault = devices(1).remove(0);
        let (a, b) = two(&mut logs, 0, 1);

        assert_eq!(
            sync_in_memory(a, &mut other_vault),
            Err(InMemoryError::B(SyncError::VaultMismatch))
        );

        // The channel authenticated some other key than the one the registry
        // lists for the device the peer claims to be.
        let mut session = Session::start(a, Some([9; 32])).unwrap();
        let mut peer = Session::start(b, None).unwrap();
        let hello = peer.poll_send(b).unwrap().unwrap();
        let devices_message = peer.poll_send(b).unwrap().unwrap();
        session.receive(a, &hello).unwrap();
        assert_eq!(
            session.receive(a, &devices_message),
            Err(SyncError::UnexpectedPeer)
        );
        // With the right channel key (device 1 has key [1; 32]) it goes through.
        let mut session = Session::start(a, Some([1; 32])).unwrap();
        session.receive(a, &hello).unwrap();
        session.receive(a, &devices_message).unwrap();

        // A device talking to itself.
        let mut session = Session::start(a, None).unwrap();
        let own_hello = Session::start(a, None)
            .unwrap()
            .poll_send(a)
            .unwrap()
            .unwrap();
        assert_eq!(
            session.receive(a, &own_hello),
            Err(SyncError::UnexpectedPeer)
        );

        // A protocol version from the future.
        let mut session = Session::start(a, None).unwrap();
        let future = Envelope::encode_body(Body::Hello(Hello {
            protocol_version: PROTOCOL_VERSION + 1,
            vault_id: a.vault_id().as_bytes().to_vec(),
            device_id: b.device_id().as_bytes().to_vec(),
        }))
        .unwrap();
        assert_eq!(
            session.receive(a, &future),
            Err(SyncError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn a_revoked_device_cannot_sync() {
        let mut logs = devices(3);
        sync(&mut logs, 0, 1);
        sync(&mut logs, 0, 2);
        let revoked = logs[1].device_id();
        logs[0].revoke(revoked).unwrap();

        // Neither device 1 nor device 2 has heard of the revocation yet, so they
        // still sync with each other.
        logs[1]
            .write(item(1), DomainId::Password, payload(1, 40))
            .unwrap();
        sync(&mut logs, 1, 2);

        // The revoking device does not: its registry reaches device 1 first,
        // which learns that it has been revoked and stops.
        let (a, b) = two(&mut logs, 0, 1);
        assert_eq!(
            sync_in_memory(a, b),
            Err(InMemoryError::B(SyncError::RevokedDevice(revoked)))
        );
        // The other direction of the same check: the revoking device refuses a
        // revoked peer as soon as it has introduced itself.
        let mut session = Session::start(a, None).unwrap();
        let mut peer = Session::start(b, None).unwrap();
        for _ in 0..2 {
            let message = peer.poll_send(b).unwrap().unwrap();
            let result = session.receive(a, &message);
            if result.is_err() {
                assert_eq!(result, Err(SyncError::RevokedDevice(revoked)));
            }
        }
        assert_eq!(session.report().peer, Some(revoked));

        // Device 2 hears of the revocation from device 0 and then refuses too.
        sync(&mut logs, 0, 2);
        let (b, c) = two(&mut logs, 1, 2);
        assert!(matches!(
            sync_in_memory(b, c),
            Err(InMemoryError::A(SyncError::RevokedDevice(_))
                | InMemoryError::B(SyncError::RevokedDevice(_)))
        ));
        // What the revoked device wrote before is kept by everyone else.
        assert_eq!(logs[0].snapshot(), logs[2].snapshot());
        assert_eq!(logs[0].snapshot().ops.len(), 1);
    }

    #[test]
    fn messages_out_of_sequence_end_the_session() {
        let mut logs = devices(2);
        let (a, b) = two(&mut logs, 0, 1);
        let opening: Vec<Vec<u8>> = {
            let mut session = Session::start(b, None).unwrap();
            (0..3)
                .map(|_| session.poll_send(b).unwrap().unwrap())
                .collect()
        };
        let (hello, devices_message, vector) = (&opening[0], &opening[1], &opening[2]);

        // Vector before Hello; Hello twice; Ops before Vector.
        let mut session = Session::start(a, None).unwrap();
        assert!(matches!(
            session.receive(a, vector),
            Err(SyncError::ProtocolViolation(_))
        ));
        let mut session = Session::start(a, None).unwrap();
        session.receive(a, hello).unwrap();
        assert!(matches!(
            session.receive(a, hello),
            Err(SyncError::ProtocolViolation(_))
        ));
        let mut session = Session::start(a, None).unwrap();
        session.receive(a, hello).unwrap();
        session.receive(a, devices_message).unwrap();
        let ops = Envelope::encode_body(Body::Ops(Ops {
            ops: Vec::new(),
            last: true,
        }))
        .unwrap();
        assert!(matches!(
            session.receive(a, &ops),
            Err(SyncError::ProtocolViolation(_))
        ));
        // Garbage.
        let mut session = Session::start(a, None).unwrap();
        assert!(matches!(
            session.receive(a, b"not protobuf \xFF"),
            Err(SyncError::MalformedMessage(_))
        ));
    }

    #[test]
    fn a_forged_op_ends_the_session_and_is_not_stored() {
        let mut logs = devices(2);
        logs[0]
            .write(item(1), DomainId::Password, payload(1, 40))
            .unwrap();
        let (a, b) = two(&mut logs, 0, 1);
        let mut session_a = Session::start(a, None).unwrap();
        let mut session_b = Session::start(b, None).unwrap();
        for _ in 0..3 {
            let message = session_b.poll_send(b).unwrap().unwrap();
            session_a.receive(a, &message).unwrap();
        }
        for _ in 0..3 {
            let message = session_a.poll_send(a).unwrap().unwrap();
            session_b.receive(b, &message).unwrap();
        }
        // Something on the path flips a bit in the ciphertext of the op.
        let message = session_a.poll_send(a).unwrap().unwrap();
        let Body::Ops(mut ops) = Envelope::decode_body(&message).unwrap() else {
            panic!("expected ops")
        };
        ops.ops[0].ciphertext[0] ^= 1;
        let tampered = Envelope::encode_body(Body::Ops(ops)).unwrap();
        assert_eq!(
            session_b.receive(b, &tampered),
            Err(SyncError::BadSignature)
        );
        assert!(b.snapshot().ops.is_empty());
    }

    #[derive(Debug, Clone)]
    enum Action {
        Write {
            device: usize,
            item: u8,
            content: Option<u8>,
        },
        /// A full session between two devices.
        Sync { a: usize, b: usize },
        /// A session cut off after `messages` messages have been delivered.
        Interrupted { a: usize, b: usize, messages: usize },
    }

    const DEVICES: usize = 4;

    fn action() -> impl Strategy<Value = Action> {
        prop_oneof![
            4 => (0..DEVICES, 0u8..5, proptest::option::weighted(0.8, any::<u8>()))
                .prop_map(|(device, item, content)| Action::Write { device, item, content }),
            2 => (0..DEVICES, 0..DEVICES).prop_map(|(a, b)| Action::Sync { a, b }),
            2 => (0..DEVICES, 0..DEVICES, 0usize..12)
                .prop_map(|(a, b, messages)| Action::Interrupted { a, b, messages }),
        ]
    }

    /// Runs a session but stops after `budget` delivered messages.
    fn interrupted(a: &mut MemoryLog, b: &mut MemoryLog, mut budget: usize) {
        let (Ok(mut session_a), Ok(mut session_b)) =
            (Session::start(a, None), Session::start(b, None))
        else {
            return;
        };
        loop {
            let mut progressed = false;
            for a_to_b in [true, false] {
                loop {
                    if budget == 0 {
                        return;
                    }
                    let message = if a_to_b {
                        session_a.poll_send(a)
                    } else {
                        session_b.poll_send(b)
                    };
                    let Ok(Some(message)) = message else { break };
                    let result = if a_to_b {
                        session_b.receive(b, &message)
                    } else {
                        session_a.receive(a, &message)
                    };
                    if result.is_err() {
                        return;
                    }
                    budget -= 1;
                    progressed = true;
                }
            }
            if !progressed {
                return;
            }
        }
    }

    proptest! {
        /// The acceptance property of P2-06: after any mix of writes, complete
        /// sessions and sessions cut off at an arbitrary message, a final round
        /// of sessions leaves every device in the same state. Devices that do
        /// not know each other yet simply fail to sync until a common peer has
        /// told them about each other.
        #[test]
        fn sessions_converge(actions in proptest::collection::vec(action(), 1..50)) {
            let mut logs = devices(DEVICES);
            for action in &actions {
                match *action {
                    Action::Write { device, item: n, content } => {
                        logs[device]
                            .write(item(n), DomainId::Password, content.and_then(|byte| payload(byte, 30)))
                            .unwrap();
                    }
                    Action::Sync { a, b } if a != b => {
                        let (first, second) = two(&mut logs, a.min(b), a.max(b));
                        // May fail if the two have not learned of each other yet.
                        let _ = sync_in_memory(first, second);
                    }
                    Action::Interrupted { a, b, messages } if a != b => {
                        let (first, second) = two(&mut logs, a.min(b), a.max(b));
                        interrupted(first, second, messages);
                    }
                    _ => {}
                }
            }
            // Everyone syncs with device 0 (which knows all devices), twice.
            for _ in 0..2 {
                for n in 1..DEVICES {
                    let (first, second) = two(&mut logs, 0, n);
                    sync_in_memory(first, second).unwrap();
                }
            }
            let reference = logs[0].snapshot();
            for log in &logs[1..] {
                prop_assert_eq!(log.snapshot(), reference.clone());
                prop_assert_eq!(log.registry().unwrap(), logs[0].registry().unwrap());
            }
        }
    }
}
