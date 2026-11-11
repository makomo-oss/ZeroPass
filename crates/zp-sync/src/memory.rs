//! An in-memory [`OpLog`]: the reference implementation of the merge rule.
//!
//! It keeps ops in maps instead of a vault file and "encrypts" nothing: payloads
//! are whatever bytes the caller supplies. That makes it the right tool for
//! testing the protocol itself, here and in the crates built on top, and it
//! documents what a real store must do.

use std::collections::BTreeMap;

use zp_crypto::{DeviceId, DeviceSigningKey, DomainId, ItemId, VaultId};

use crate::merge::{ApplyReport, Incoming, OpLog, Placement, check_incoming, place};
use crate::{
    ChannelPublicKey, DeviceRecord, Hlc, Op, OpBody, Payload, Registry, Revocation, SyncError,
    VersionVector,
};

type OpId = (DeviceId, u64);

/// A device's ops and registry, held in memory.
#[derive(Debug)]
pub struct MemoryLog {
    vault_id: VaultId,
    device_id: DeviceId,
    signing_key: DeviceSigningKey,
    registry: Registry,
    ops: BTreeMap<OpId, Op>,
    vector: VersionVector,
    /// The current version of each item.
    current: BTreeMap<ItemId, OpId>,
    clock: Hlc,
    now_ms: u64,
}

/// The observable state of a log, for comparing devices: every op held, and
/// which op is the current version of each item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The identifiers of all ops held.
    pub ops: Vec<(DeviceId, u64)>,
    /// For each item, the op that is its current version.
    pub current: Vec<(ItemId, (DeviceId, u64))>,
}

impl MemoryLog {
    /// The first device of a new vault.
    pub fn new_vault(name: &str, noise_pk: ChannelPublicKey) -> Result<Self, SyncError> {
        let vault_id = VaultId::generate()?;
        let device_id = DeviceId::generate()?;
        let signing_key = DeviceSigningKey::generate()?;
        let root = DeviceRecord::root(&vault_id, device_id, &signing_key, noise_pk, name)?;
        let registry = Registry::with_root(vault_id, root)?;
        Ok(Self::assemble(vault_id, device_id, signing_key, registry))
    }

    /// A new device joining the vault of `introducer`: it is added to the
    /// introducer's registry and starts with a copy of that registry, but with no
    /// ops (it fetches those by syncing).
    pub fn join(
        introducer: &mut MemoryLog,
        name: &str,
        noise_pk: ChannelPublicKey,
    ) -> Result<Self, SyncError> {
        let device_id = DeviceId::generate()?;
        let signing_key = DeviceSigningKey::generate()?;
        let record = DeviceRecord::introduce(
            &introducer.vault_id,
            introducer.device_id,
            &introducer.signing_key,
            device_id,
            signing_key.public_key(),
            noise_pk,
            name,
        )?;
        introducer.registry.accept(record)?;
        let registry = introducer.registry.clone();
        Ok(Self::assemble(
            introducer.vault_id,
            device_id,
            signing_key,
            registry,
        ))
    }

    fn assemble(
        vault_id: VaultId,
        device_id: DeviceId,
        signing_key: DeviceSigningKey,
        registry: Registry,
    ) -> Self {
        Self {
            vault_id,
            device_id,
            signing_key,
            registry,
            ops: BTreeMap::new(),
            vector: VersionVector::new(),
            current: BTreeMap::new(),
            clock: Hlc::resume_after(0),
            now_ms: 1_800_000_000_000,
        }
    }

    /// Sets this device's wall clock.
    pub fn set_now_ms(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// This device's wall clock.
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Revokes a device on behalf of this one.
    pub fn revoke(&mut self, device: DeviceId) -> Result<(), SyncError> {
        let revocation =
            Revocation::sign(&self.vault_id, device, self.device_id, &self.signing_key);
        self.registry.accept_revocation(revocation).map(|_| ())
    }

    /// Writes a new version of an item locally: `Some(payload)` to create or
    /// update it, `None` to delete it. Returns the op.
    pub fn write(
        &mut self,
        item_id: ItemId,
        domain: DomainId,
        payload: Option<Payload>,
    ) -> Result<Op, SyncError> {
        if let Some(existing) = self.current.get(&item_id)
            && self.ops[existing].body.domain != domain
        {
            return Err(SyncError::DomainChanged);
        }
        let body = OpBody {
            device_id: self.device_id,
            seq: self.vector.get(&self.device_id) + 1,
            item_id,
            domain,
            hlc: self
                .clock
                .tick(self.now_ms)
                .ok_or(SyncError::MalformedOp("clock exhausted"))?,
            key_epoch: 1,
            payload,
        };
        body.check_shape()?;
        let op = body.sign(&self.vault_id, &self.signing_key);
        self.store(op.clone());
        Ok(op)
    }

    /// Stores a validated op and updates the derived state.
    fn store(&mut self, op: Op) -> Placement {
        let id = (op.body.device_id, op.body.seq);
        let current = self
            .current
            .get(&op.body.item_id)
            .map(|held| self.ops[held].body.stamp());
        let placement = place(current, op.body.stamp());
        if placement == Placement::Current {
            self.current.insert(op.body.item_id, id);
        }
        self.clock.observe(op.body.hlc);
        self.vector.advance(op.body.device_id, op.body.seq);
        self.ops.insert(id, op);
        placement
    }

    /// The op that is the current version of `item_id`, if the item is known.
    pub fn current(&self, item_id: &ItemId) -> Option<&Op> {
        self.current.get(item_id).map(|id| &self.ops[id])
    }

    /// Every version of `item_id` held, in merge order (oldest first).
    pub fn versions(&self, item_id: &ItemId) -> Vec<&Op> {
        let mut versions: Vec<&Op> = self
            .ops
            .values()
            .filter(|op| op.body.item_id == *item_id)
            .collect();
        versions.sort_by_key(|op| op.body.stamp());
        versions
    }

    /// The observable state, for comparing devices.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            ops: self.ops.keys().copied().collect(),
            current: self.current.iter().map(|(item, id)| (*item, *id)).collect(),
        }
    }

    fn apply_one(&mut self, op: Op, report: &mut ApplyReport) -> Result<(), SyncError> {
        let held = self.vector.get(&op.body.device_id);
        match check_incoming(&op, &self.vault_id, &self.registry, held, self.now_ms)? {
            Incoming::Duplicate => {
                // The same identifier must mean the same op.
                let existing = &self.ops[&(op.body.device_id, op.body.seq)];
                if *existing != op {
                    return Err(SyncError::ConflictingOp {
                        device: op.body.device_id,
                        seq: op.body.seq,
                    });
                }
                report.duplicates += 1;
            }
            Incoming::Next => {
                if let Some(existing) = self.current.get(&op.body.item_id)
                    && self.ops[existing].body.domain != op.body.domain
                {
                    return Err(SyncError::DomainChanged);
                }
                report.applied += 1;
                if self.store(op) == Placement::Current {
                    report.became_current += 1;
                }
            }
        }
        Ok(())
    }
}

impl OpLog for MemoryLog {
    type Error = SyncError;

    fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    fn device_id(&self) -> DeviceId {
        self.device_id
    }

    fn registry(&self) -> Result<Registry, SyncError> {
        Ok(self.registry.clone())
    }

    fn merge_registry(
        &mut self,
        records: Vec<DeviceRecord>,
        revocations: Vec<Revocation>,
    ) -> Result<bool, SyncError> {
        // Work on a copy so that a rejected batch leaves the registry untouched.
        let mut merged = self.registry.clone();
        let changed = merged.merge(records, revocations)?;
        self.registry = merged;
        Ok(changed)
    }

    fn version_vector(&self) -> Result<VersionVector, SyncError> {
        Ok(self.vector.clone())
    }

    fn ops_after(
        &self,
        device: DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Op>, SyncError> {
        let Some(first) = after_seq.checked_add(1) else {
            return Ok(Vec::new());
        };
        Ok(self
            .ops
            .range((device, first)..=(device, u64::MAX))
            .take(limit)
            .map(|(_, op)| op.clone())
            .collect())
    }

    fn apply(&mut self, ops: Vec<Op>) -> Result<ApplyReport, SyncError> {
        // All or nothing: remember what to undo if a later op is rejected.
        let before = (
            self.ops.clone(),
            self.vector.clone(),
            self.current.clone(),
            self.clock,
        );
        let mut report = ApplyReport::default();
        for op in ops {
            if let Err(error) = self.apply_one(op, &mut report) {
                (self.ops, self.vector, self.current, self.clock) = before;
                return Err(error);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::hlc::MAX_CLOCK_SKEW_MS;

    fn payload(byte: u8) -> Option<Payload> {
        Some(Payload {
            wrapped_dek: vec![byte; 8],
            ciphertext: vec![byte; 16],
        })
    }

    fn item(n: u8) -> ItemId {
        ItemId::from_bytes([n; 16])
    }

    /// A vault with `count` devices that all know each other and hold no ops.
    fn devices(count: usize) -> Vec<MemoryLog> {
        let mut logs = vec![MemoryLog::new_vault("device 0", [0; 32]).unwrap()];
        for n in 1..count {
            let joined =
                MemoryLog::join(&mut logs[0], &format!("device {n}"), [n as u8; 32]).unwrap();
            logs.push(joined);
        }
        let (records, revocations): (Vec<_>, Vec<_>) = {
            let registry = logs[0].registry().unwrap();
            (
                registry.records().cloned().collect(),
                registry.revocations().cloned().collect(),
            )
        };
        for log in &mut logs {
            log.merge_registry(records.clone(), revocations.clone())
                .unwrap();
        }
        logs
    }

    /// Sends `to` everything it lacks from `from`, at most `limit` ops per author.
    fn pull(from: &MemoryLog, to: &mut MemoryLog, limit: usize) -> ApplyReport {
        let mut report = ApplyReport::default();
        let ahead = from
            .version_vector()
            .unwrap()
            .ahead_of(&to.version_vector().unwrap());
        for (device, after, _) in ahead {
            let ops = from.ops_after(device, after, limit).unwrap();
            report.absorb(to.apply(ops).unwrap());
        }
        report
    }

    fn sync_all(logs: &mut [MemoryLog]) {
        // Two rounds over all ordered pairs reach every device from every other.
        for _ in 0..2 {
            for from in 0..logs.len() {
                for to in 0..logs.len() {
                    if from != to {
                        let (source, target) = if from < to {
                            let (left, right) = logs.split_at_mut(to);
                            (&left[from], &mut right[0])
                        } else {
                            let (left, right) = logs.split_at_mut(from);
                            (&right[0], &mut left[to])
                        };
                        pull(source, target, usize::MAX);
                    }
                }
            }
        }
    }

    #[test]
    fn local_writes_are_numbered_signed_and_current() {
        let mut logs = devices(1);
        let log = &mut logs[0];
        let first = log.write(item(1), DomainId::Password, payload(1)).unwrap();
        let second = log.write(item(1), DomainId::Password, payload(2)).unwrap();
        assert_eq!((first.body.seq, second.body.seq), (1, 2));
        assert!(second.body.hlc > first.body.hlc);
        assert_eq!(log.current(&item(1)), Some(&second));
        assert_eq!(log.versions(&item(1)), [&first, &second]);
        assert_eq!(log.version_vector().unwrap().get(&log.device_id()), 2);
        second
            .verify(
                &log.vault_id(),
                log.registry().unwrap().sign_pk(&log.device_id()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn a_later_write_wins_on_every_device() {
        let mut logs = devices(2);
        let (a, b) = logs.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);

        a.write(item(1), DomainId::Password, payload(1)).unwrap();
        pull(a, b, usize::MAX);
        // Both edit the item while apart; B's clock is ahead.
        b.set_now_ms(a.now_ms() + 5_000);
        let from_a = a.write(item(1), DomainId::Password, payload(2)).unwrap();
        let from_b = b.write(item(1), DomainId::Password, payload(3)).unwrap();

        let report = pull(a, b, usize::MAX);
        assert_eq!(
            (report.applied, report.became_current),
            (1, 0),
            "A's edit is older"
        );
        let report = pull(b, a, usize::MAX);
        assert_eq!((report.applied, report.became_current), (1, 1));

        assert_eq!(a.current(&item(1)), Some(&from_b));
        assert_eq!(b.current(&item(1)), Some(&from_b));
        assert_eq!(a.snapshot(), b.snapshot());
        // The losing edit is kept as history on both.
        assert!(a.versions(&item(1)).contains(&&from_a));
        assert!(b.versions(&item(1)).contains(&&from_a));
    }

    #[test]
    fn equal_clock_stamps_are_decided_by_device_identifier() {
        let mut logs = devices(2);
        let (a, b) = logs.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);
        // Same wall clock, same counter: identical stamps.
        let from_a = a.write(item(1), DomainId::Password, payload(1)).unwrap();
        let from_b = b.write(item(1), DomainId::Password, payload(2)).unwrap();
        assert_eq!(from_a.body.hlc, from_b.body.hlc);

        pull(a, b, usize::MAX);
        pull(b, a, usize::MAX);
        let winner = if a.device_id() > b.device_id() {
            &from_a
        } else {
            &from_b
        };
        assert_eq!(a.current(&item(1)), Some(winner));
        assert_eq!(b.current(&item(1)), Some(winner));
    }

    #[test]
    fn a_deletion_and_a_later_update_resolve_by_stamp() {
        let mut logs = devices(2);
        let (a, b) = logs.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);
        a.write(item(1), DomainId::Password, payload(1)).unwrap();
        pull(a, b, usize::MAX);

        // A deletes; B, later, updates. The update brings the item back.
        a.write(item(1), DomainId::Password, None).unwrap();
        b.set_now_ms(a.now_ms() + 1_000);
        let update = b.write(item(1), DomainId::Password, payload(2)).unwrap();
        pull(a, b, usize::MAX);
        pull(b, a, usize::MAX);
        assert_eq!(a.current(&item(1)), Some(&update));
        assert_eq!(b.current(&item(1)), Some(&update));

        // The other way round: the later deletion wins.
        b.write(item(2), DomainId::Totp, payload(1)).unwrap();
        pull(b, a, usize::MAX);
        b.write(item(2), DomainId::Totp, payload(2)).unwrap();
        a.set_now_ms(b.now_ms() + 1_000);
        let deletion = a.write(item(2), DomainId::Totp, None).unwrap();
        pull(a, b, usize::MAX);
        pull(b, a, usize::MAX);
        assert_eq!(a.current(&item(2)), Some(&deletion));
        assert_eq!(b.current(&item(2)), Some(&deletion));
        assert!(b.current(&item(2)).unwrap().body.payload.is_none());
    }

    #[test]
    fn ops_are_relayed_through_a_third_device() {
        let mut logs = devices(3);
        logs[0]
            .write(item(1), DomainId::Password, payload(1))
            .unwrap();
        // A → B, then B → C: C never talks to A.
        let (a, rest) = logs.split_at_mut(1);
        let (b, c) = rest.split_at_mut(1);
        pull(&a[0], &mut b[0], usize::MAX);
        let report = pull(&b[0], &mut c[0], usize::MAX);
        assert_eq!(report.applied, 1);
        assert_eq!(c[0].snapshot(), a[0].snapshot());
    }

    #[test]
    fn duplicates_are_ignored_and_out_of_order_ops_are_refused() {
        let mut logs = devices(2);
        let (a, b) = logs.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);
        let ops: Vec<Op> = (0..4)
            .map(|n| a.write(item(n), DomainId::Password, payload(n)).unwrap())
            .collect();

        // Op 2 before op 1.
        assert_eq!(
            b.apply(vec![ops[1].clone()]),
            Err(SyncError::OutOfOrder {
                device: a.device_id(),
                expected: 1,
                got: 2
            })
        );
        // A batch with a gap is refused as a whole.
        assert!(b.apply(vec![ops[0].clone(), ops[2].clone()]).is_err());
        assert!(
            b.snapshot().ops.is_empty(),
            "nothing of a refused batch is kept"
        );

        let report = b.apply(vec![ops[0].clone(), ops[1].clone()]).unwrap();
        assert_eq!(
            report,
            ApplyReport {
                applied: 2,
                duplicates: 0,
                became_current: 2
            }
        );
        // Overlapping redelivery.
        let report = b.apply(ops.clone()).unwrap();
        assert_eq!(
            report,
            ApplyReport {
                applied: 2,
                duplicates: 2,
                became_current: 2
            }
        );
        assert_eq!(b.snapshot(), a.snapshot());
    }

    #[test]
    fn forged_and_invalid_ops_are_refused() {
        let mut logs = devices(2);
        let mut stranger = devices(1).remove(0);
        let (a, b) = logs.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);
        let genuine = a.write(item(1), DomainId::Password, payload(1)).unwrap();

        // Modified after signing.
        let mut tampered = genuine.clone();
        tampered.body.payload = payload(9);
        assert_eq!(b.apply(vec![tampered]), Err(SyncError::BadSignature));
        // A forged tombstone under A's name, signed by someone else.
        let forged = OpBody {
            payload: None,
            ..genuine.body.clone()
        }
        .sign(&a.vault_id(), &stranger.signing_key);
        assert_eq!(b.apply(vec![forged]), Err(SyncError::BadSignature));
        // An op from a device that is not in the registry.
        let foreign = stranger
            .write(item(1), DomainId::Password, payload(1))
            .unwrap();
        assert_eq!(
            b.apply(vec![foreign.clone()]),
            Err(SyncError::UnknownDevice(foreign.body.device_id))
        );

        b.apply(vec![genuine.clone()]).unwrap();
        // Same identifier, different (validly signed) content: equivocation.
        let mut second = OpBody {
            hlc: genuine.body.hlc + 1,
            ..genuine.body.clone()
        };
        second.payload = payload(7);
        let equivocation = second.sign(&a.vault_id(), &a.signing_key);
        assert_eq!(
            b.apply(vec![equivocation]),
            Err(SyncError::ConflictingOp {
                device: a.device_id(),
                seq: 1
            })
        );
        // An op that moves the item to another domain.
        let moved = OpBody {
            seq: 2,
            domain: DomainId::Totp,
            hlc: genuine.body.hlc + 5,
            ..genuine.body.clone()
        }
        .sign(&a.vault_id(), &a.signing_key);
        assert_eq!(b.apply(vec![moved]), Err(SyncError::DomainChanged));
        assert_eq!(b.snapshot().ops.len(), 1);
        // The same rule applies to local writes.
        assert_eq!(
            a.write(item(1), DomainId::Totp, payload(1)),
            Err(SyncError::DomainChanged)
        );
    }

    #[test]
    fn ops_from_the_far_future_are_refused() {
        let mut logs = devices(2);
        let (a, b) = logs.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);

        // Within the tolerated skew: accepted, and B's clock moves past it.
        a.set_now_ms(b.now_ms() + MAX_CLOCK_SKEW_MS);
        let near = a.write(item(1), DomainId::Password, payload(1)).unwrap();
        b.apply(vec![near.clone()]).unwrap();
        let after = b.write(item(2), DomainId::Password, payload(1)).unwrap();
        assert!(after.body.hlc > near.body.hlc);

        // Beyond it: refused, and B's clock is not dragged along.
        a.set_now_ms(b.now_ms() + MAX_CLOCK_SKEW_MS + 60_000);
        let far = a.write(item(3), DomainId::Password, payload(1)).unwrap();
        assert_eq!(b.apply(vec![far.clone()]), Err(SyncError::ClockSkew));
        let next = b.write(item(4), DomainId::Password, payload(1)).unwrap();
        assert!(next.body.hlc < far.body.hlc);
    }

    #[test]
    fn ops_of_a_revoked_device_remain_part_of_the_history() {
        let mut logs = devices(3);
        let op = logs[1]
            .write(item(1), DomainId::Password, payload(1))
            .unwrap();
        let revoked = logs[1].device_id();
        logs[0].revoke(revoked).unwrap();
        assert!(!logs[0].registry().unwrap().is_active(&revoked));
        // A still accepts what B wrote, e.g. relayed by C later.
        assert_eq!(logs[0].apply(vec![op]).unwrap().applied, 1);
    }

    #[derive(Debug, Clone)]
    enum Action {
        /// Device writes item: `Some(byte)` puts content, `None` deletes.
        Write {
            device: usize,
            item: u8,
            content: Option<u8>,
        },
        /// `to` pulls from `from`, at most `limit` ops per author, `repeat` times.
        Pull {
            from: usize,
            to: usize,
            limit: usize,
            repeat: usize,
        },
        /// A device's wall clock moves (possibly backwards).
        Clock { device: usize, delta_ms: i64 },
    }

    const DEVICES: usize = 4;

    fn action() -> impl Strategy<Value = Action> {
        prop_oneof![
            4 => (0..DEVICES, 0u8..5, proptest::option::weighted(0.8, any::<u8>()))
                .prop_map(|(device, item, content)| Action::Write { device, item, content }),
            4 => (0..DEVICES, 0..DEVICES, 1usize..6, 1usize..3)
                .prop_map(|(from, to, limit, repeat)| Action::Pull { from, to, limit, repeat }),
            1 => (0..DEVICES, -120_000i64..600_000)
                .prop_map(|(device, delta_ms)| Action::Clock { device, delta_ms }),
        ]
    }

    fn run(logs: &mut [MemoryLog], actions: &[Action]) {
        for action in actions {
            match *action {
                Action::Write {
                    device,
                    item: n,
                    content,
                } => {
                    logs[device]
                        .write(item(n), DomainId::Password, content.and_then(payload))
                        .unwrap();
                }
                Action::Pull {
                    from,
                    to,
                    limit,
                    repeat,
                } if from != to => {
                    for _ in 0..repeat {
                        let (source, target) = if from < to {
                            let (left, right) = logs.split_at_mut(to);
                            (&left[from], &mut right[0])
                        } else {
                            let (left, right) = logs.split_at_mut(from);
                            (&right[0], &mut left[to])
                        };
                        pull(source, target, limit);
                    }
                }
                Action::Pull { .. } => {}
                Action::Clock { device, delta_ms } => {
                    let now = logs[device].now_ms().saturating_add_signed(delta_ms);
                    logs[device].set_now_ms(now);
                }
            }
        }
    }

    proptest! {
        /// The acceptance property of P2-05: whatever the devices write and
        /// however partially, repeatedly and indirectly they exchange ops, once
        /// everyone has synced they all hold the same state.
        #[test]
        fn devices_converge(actions in proptest::collection::vec(action(), 1..80)) {
            let mut logs = devices(DEVICES);
            run(&mut logs, &actions);
            sync_all(&mut logs);

            let reference = logs[0].snapshot();
            for log in &logs[1..] {
                prop_assert_eq!(log.snapshot(), reference.clone());
            }
            // And the state is the one the rule defines: the current version of
            // each item is the version with the greatest stamp.
            for log in &logs {
                for (item_id, (device, seq)) in &reference.current {
                    let newest = log.versions(item_id).last().map(|op| (op.body.device_id, op.body.seq));
                    prop_assert_eq!(newest, Some((*device, *seq)));
                }
            }
        }

        /// Delivery order does not matter: an observer that receives the same ops
        /// in any interleaving that keeps each author's order, with redeliveries
        /// mixed in, reaches the same state.
        #[test]
        fn any_delivery_order_gives_the_same_state(
            actions in proptest::collection::vec(action(), 1..60),
            picks in proptest::collection::vec(any::<prop::sample::Index>(), 0..400),
            redeliver in proptest::collection::vec(any::<bool>(), 0..400),
        ) {
            let mut logs = devices(DEVICES + 1);
            let (authors, observers) = logs.split_at_mut(DEVICES);
            run(authors, &actions);
            sync_all(authors);

            // Per-author queues of everything that was written.
            let mut queues: Vec<Vec<Op>> = authors
                .iter()
                .map(|log| log.ops_after(log.device_id(), 0, usize::MAX).unwrap())
                .collect();
            for queue in &mut queues {
                queue.reverse();
            }
            let mut delivered: Vec<Op> = Vec::new();
            let observer = &mut observers[0];
            // The observer's clock must not reject anything.
            observer.set_now_ms(u64::MAX >> 17);

            let mut step = 0;
            while queues.iter().any(|queue| !queue.is_empty()) {
                let pending: Vec<usize> =
                    (0..queues.len()).filter(|&n| !queues[n].is_empty()).collect();
                let choice = picks.get(step).map_or(0, |pick| pick.index(pending.len()));
                let op = queues[pending[choice]].pop().unwrap();
                observer.apply(vec![op.clone()]).unwrap();
                if redeliver.get(step).copied().unwrap_or(false) && !delivered.is_empty() {
                    let again = delivered[step % delivered.len()].clone();
                    prop_assert_eq!(observer.apply(vec![again]).unwrap().duplicates, 1);
                }
                delivered.push(op);
                step += 1;
            }
            prop_assert_eq!(observer.snapshot(), authors[0].snapshot());
        }
    }
}
