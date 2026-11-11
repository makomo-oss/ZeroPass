//! The vault file as an [`OpLog`]: what the sync session reads and writes
//! (`docs/spec/sync.md` §5 and §7).
//!
//! Nothing here needs a vault key. Received ops are verified by signature and
//! stored as ciphertext, so a vault syncs while it is locked.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use zp_crypto::{DeviceId, VaultId};
use zp_sync::{
    ApplyReport, DeviceRecord, Incoming, Op, OpLog, Placement, Registry, Revocation, Stamp,
    SyncError, VersionVector, check_incoming, place,
};

use crate::items::{
    ItemRow, current_row, held_seq, insert_version, make_current, set_held_seq, set_hlc_max,
};
use crate::{Store, VaultError};

/// The signature stored for an op already held (`None` if the op is unsigned).
fn stored_signature(
    tx: &Transaction<'_>,
    device: DeviceId,
    seq: u64,
) -> Result<Option<Vec<u8>>, VaultError> {
    let seq = i64::try_from(seq).map_err(|_| VaultError::Corrupt("sequence overflow"))?;
    let signature: Option<Option<Vec<u8>>> = tx
        .prepare_cached(
            "SELECT signature FROM items WHERE device_id = ?1 AND seq = ?2
             UNION ALL
             SELECT signature FROM item_history WHERE device_id = ?1 AND seq = ?2",
        )?
        .query_row(params![device.as_bytes(), seq], |row| row.get(0))
        .optional()?;
    signature.ok_or(VaultError::Corrupt(
        "the version vector covers an op that is not stored",
    ))
}

impl OpLog for Store {
    type Error = VaultError;

    fn vault_id(&self) -> VaultId {
        Store::vault_id(self)
    }

    fn device_id(&self) -> DeviceId {
        Store::device_id(self)
    }

    fn registry(&self) -> Result<Registry, VaultError> {
        Store::registry(self)
    }

    fn merge_registry(
        &mut self,
        records: Vec<DeviceRecord>,
        revocations: Vec<Revocation>,
    ) -> Result<bool, VaultError> {
        let mut registry = Store::registry(self)?;
        let changed = registry.merge(records, revocations)?;
        if changed {
            self.write_registry(&registry)?;
        }
        Ok(changed)
    }

    fn version_vector(&self) -> Result<VersionVector, VaultError> {
        Store::version_vector(self)
    }

    fn ops_after(
        &self,
        device: DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Op>, VaultError> {
        Store::ops_after(self, device, after_seq, limit)
    }

    fn apply(&mut self, ops: Vec<Op>) -> Result<ApplyReport, VaultError> {
        let registry = Store::registry(self)?;
        let (vault_id, now_ms) = (Store::vault_id(self), self.now_ms());

        // One transaction per batch: a rejected op leaves nothing behind.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut held: BTreeMap<DeviceId, u64> = BTreeMap::new();
        let mut newest_stamp = 0;
        let mut report = ApplyReport::default();

        for op in ops {
            let device = op.body.device_id;
            let held_from_author = match held.get(&device) {
                Some(seq) => *seq,
                None => held_seq(&tx, device)?,
            };
            match check_incoming(&op, &vault_id, &registry, held_from_author, now_ms)? {
                Incoming::Duplicate => {
                    // The same identifier must mean the same op. Ed25519 signatures
                    // are deterministic, so equal signatures mean equal content.
                    if let Some(signature) = stored_signature(&tx, device, op.body.seq)?
                        && signature != op.signature
                    {
                        return Err(SyncError::ConflictingOp {
                            device,
                            seq: op.body.seq,
                        }
                        .into());
                    }
                    report.duplicates += 1;
                }
                Incoming::Next => {
                    let current = current_row(&tx, op.body.item_id)?;
                    if current
                        .as_ref()
                        .is_some_and(|row| row.domain != op.body.domain)
                    {
                        return Err(SyncError::DomainChanged.into());
                    }
                    let current_stamp = current.map(|row| Stamp {
                        hlc: row.hlc,
                        device_id: row.device_id,
                    });
                    newest_stamp = newest_stamp.max(op.body.hlc);
                    held.insert(device, op.body.seq);

                    let placement = place(current_stamp, op.body.stamp());
                    let row = ItemRow::from_op(op);
                    match placement {
                        Placement::Current => {
                            make_current(&tx, &row)?;
                            report.became_current += 1;
                        }
                        Placement::History => insert_version(&tx, "item_history", &row)?,
                    }
                    report.applied += 1;
                }
            }
        }

        for (device, seq) in held {
            set_held_seq(&tx, device, seq)?;
        }
        // Later local versions must order after everything received.
        set_hlc_max(&tx, newest_stamp)?;
        tx.commit()?;
        Ok(report)
    }
}
