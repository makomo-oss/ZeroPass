//! The merge rule (`docs/spec/sync.md` §5): how a device takes in ops authored
//! elsewhere so that all devices end up in the same state.
//!
//! The rule itself is two small pure functions, [`check_incoming`] and
//! [`place`]. [`OpLog`] is the interface a store offers to the sync session; the
//! in-memory [`MemoryLog`](crate::MemoryLog) and the vault file both implement
//! it with these functions.

use zp_crypto::{DeviceId, VaultId};

use crate::hlc::is_acceptable;
use crate::{DeviceRecord, Op, Registry, Revocation, Stamp, SyncError, VersionVector};

/// What to do with an op that passed [`check_incoming`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incoming {
    /// The op is already held; ignore it (after checking it is the same op).
    Duplicate,
    /// The op is the next one from its author; store it.
    Next,
}

/// Where a newly stored version of an item goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// It becomes the item's current version; the previous one moves to history.
    Current,
    /// It is older than the current version and goes straight to history.
    History,
}

/// Validates an op received from another device (`sync.md` §5.1), given how many
/// of its author's ops are already held.
///
/// Checks, in order: shape and signature (against the registry), position in the
/// author's sequence, and the clock stamp against the local time `now_ms`.
/// Neither a vault key nor an unlocked vault is needed.
pub fn check_incoming(
    op: &Op,
    vault_id: &VaultId,
    registry: &Registry,
    held_seq: u64,
    now_ms: u64,
) -> Result<Incoming, SyncError> {
    // Ops of revoked devices stay verifiable: they are part of the history.
    op.verify(vault_id, registry.sign_pk(&op.body.device_id)?)?;
    if op.body.seq <= held_seq {
        return Ok(Incoming::Duplicate);
    }
    if op.body.seq != held_seq + 1 {
        return Err(SyncError::OutOfOrder {
            device: op.body.device_id,
            expected: held_seq + 1,
            got: op.body.seq,
        });
    }
    if !is_acceptable(op.body.hlc, now_ms) {
        return Err(SyncError::ClockSkew);
    }
    Ok(Incoming::Next)
}

/// Decides where a new version goes, given the stamp of the item's current
/// version (if it has one).
///
/// The current version of an item is always the one with the greatest stamp
/// among all versions held, whatever order they arrived in.
pub fn place(current: Option<Stamp>, incoming: Stamp) -> Placement {
    match current {
        Some(current) if current >= incoming => Placement::History,
        _ => Placement::Current,
    }
}

/// What applying a batch of ops did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Ops that were new and have been stored.
    pub applied: usize,
    /// Ops that were already held.
    pub duplicates: usize,
    /// Stored ops that became the current version of their item.
    pub became_current: usize,
}

impl ApplyReport {
    /// Adds another report to this one.
    pub fn absorb(&mut self, other: ApplyReport) {
        self.applied += other.applied;
        self.duplicates += other.duplicates;
        self.became_current += other.became_current;
    }
}

/// A store of ops that can take part in sync.
///
/// Implementations hold ciphertext and signatures only; nothing here needs a
/// vault key, so sync works while the vault is locked.
pub trait OpLog {
    /// The store's error type. Protocol violations surface as [`SyncError`].
    type Error: From<SyncError> + core::fmt::Debug + core::fmt::Display;

    /// The vault this store belongs to.
    fn vault_id(&self) -> VaultId;

    /// The device this store belongs to.
    fn device_id(&self) -> DeviceId;

    /// The device registry.
    fn registry(&self) -> Result<Registry, Self::Error>;

    /// Takes in device records and revocations received from a sync partner.
    /// Returns whether the registry changed.
    fn merge_registry(
        &mut self,
        records: Vec<DeviceRecord>,
        revocations: Vec<Revocation>,
    ) -> Result<bool, Self::Error>;

    /// For each device, up to which sequence number its ops are held.
    fn version_vector(&self) -> Result<VersionVector, Self::Error>;

    /// The ops authored by `device` after `after_seq`, in order and without
    /// gaps, at most `limit` of them.
    fn ops_after(
        &self,
        device: DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Op>, Self::Error>;

    /// Validates and stores a batch of received ops. Either the whole batch is
    /// taken in, or (on any error) none of it.
    fn apply(&mut self, ops: Vec<Op>) -> Result<ApplyReport, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(hlc: u64, device: u8) -> Stamp {
        Stamp {
            hlc,
            device_id: DeviceId::from_bytes([device; 16]),
        }
    }

    #[test]
    fn the_greater_stamp_becomes_current() {
        assert_eq!(place(None, stamp(1, 1)), Placement::Current);
        assert_eq!(place(Some(stamp(5, 1)), stamp(6, 1)), Placement::Current);
        assert_eq!(place(Some(stamp(5, 1)), stamp(4, 9)), Placement::History);
        // Equal clocks: the device identifier decides, the same way everywhere.
        assert_eq!(place(Some(stamp(5, 1)), stamp(5, 2)), Placement::Current);
        assert_eq!(place(Some(stamp(5, 2)), stamp(5, 1)), Placement::History);
        // The same version again changes nothing.
        assert_eq!(place(Some(stamp(5, 2)), stamp(5, 2)), Placement::History);
    }

    #[test]
    fn reports_add_up() {
        let mut total = ApplyReport {
            applied: 1,
            duplicates: 2,
            became_current: 1,
        };
        total.absorb(ApplyReport {
            applied: 3,
            duplicates: 0,
            became_current: 2,
        });
        assert_eq!(
            total,
            ApplyReport {
                applied: 4,
                duplicates: 2,
                became_current: 3
            }
        );
    }
}
