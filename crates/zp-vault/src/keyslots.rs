//! Reading and writing key slots (`docs/spec/crypto.md` §6): the wrapped vault
//! keys stored in the vault file.

use rusqlite::{OptionalExtension, params};
use zp_crypto::{DomainId, KDF_SALT_LEN, KdfParams};

use crate::{Store, VaultError};

/// The kind of key that wraps a vault key in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SlotKind {
    /// Wrapped by `KEK-P`, derived from the master password. Password domain only.
    Password = 1,
    /// Wrapped by a hardware key store. TOTP and passkey domains only.
    Hardware = 2,
    /// Wrapped by a key derived from the recovery key.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "recovery slots arrive with P1-14")
    )]
    Recovery = 3,
}

/// The password slot of the password domain, with the parameters needed to
/// re-derive `KEK-P`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasswordSlot {
    pub(crate) blob: Vec<u8>,
    pub(crate) salt: [u8; KDF_SALT_LEN],
    pub(crate) params: KdfParams,
}

/// A slot without key-derivation parameters (hardware or recovery).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PlainSlot<'a> {
    pub(crate) domain: DomainId,
    pub(crate) kind: SlotKind,
    pub(crate) blob: &'a [u8],
}

const UPSERT: &str = "
    INSERT INTO key_slots (domain, kind, blob, kdf_salt, kdf_m_kib, kdf_t, kdf_p)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    ON CONFLICT (domain, kind) DO UPDATE SET
        blob = excluded.blob,
        kdf_salt = excluded.kdf_salt,
        kdf_m_kib = excluded.kdf_m_kib,
        kdf_t = excluded.kdf_t,
        kdf_p = excluded.kdf_p";

impl Store {
    /// Reads the password slot, if the vault has one.
    pub(crate) fn password_slot(&self) -> Result<Option<PasswordSlot>, VaultError> {
        let row = self
            .conn
            .query_row(
                "SELECT blob, kdf_salt, kdf_m_kib, kdf_t, kdf_p FROM key_slots
                 WHERE domain = ?1 AND kind = ?2",
                params![DomainId::Password.as_u8(), SlotKind::Password as u8],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, u32>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((blob, salt, m_kib, t, p)) = row else {
            return Ok(None);
        };
        Ok(Some(PasswordSlot {
            blob,
            salt: salt
                .try_into()
                .map_err(|_| VaultError::Corrupt("malformed KDF salt"))?,
            // Out-of-range parameters are refused here, before any memory is committed.
            params: KdfParams::new(m_kib, t, p)?,
        }))
    }

    /// Reads a hardware or recovery slot.
    pub(crate) fn slot(
        &self,
        domain: DomainId,
        kind: SlotKind,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(self
            .conn
            .query_row(
                "SELECT blob FROM key_slots WHERE domain = ?1 AND kind = ?2",
                params![domain.as_u8(), kind as u8],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Writes (or replaces) several slots atomically.
    pub(crate) fn write_slots(
        &mut self,
        password: Option<&PasswordSlot>,
        plain: &[PlainSlot<'_>],
    ) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        if let Some(slot) = password {
            tx.execute(
                UPSERT,
                params![
                    DomainId::Password.as_u8(),
                    SlotKind::Password as u8,
                    slot.blob,
                    slot.salt.as_slice(),
                    slot.params.m_kib(),
                    slot.params.t(),
                    slot.params.p(),
                ],
            )?;
        }
        let none: Option<u32> = None;
        for slot in plain {
            debug_assert_ne!(slot.kind, SlotKind::Password);
            tx.execute(
                UPSERT,
                params![
                    slot.domain.as_u8(),
                    slot.kind as u8,
                    slot.blob,
                    Option::<&[u8]>::None,
                    none,
                    none,
                    none
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(&dir.path().join("vault.zpvault")).unwrap();
        (dir, store)
    }

    fn password_slot(byte: u8) -> PasswordSlot {
        PasswordSlot {
            blob: vec![byte; 73],
            salt: [byte; 16],
            params: KdfParams::MINIMUM,
        }
    }

    #[test]
    fn slots_round_trip_and_can_be_replaced() {
        let (_dir, mut store) = store();
        assert_eq!(store.password_slot().unwrap(), None);
        assert_eq!(
            store.slot(DomainId::Totp, SlotKind::Hardware).unwrap(),
            None
        );

        let hardware = PlainSlot {
            domain: DomainId::Totp,
            kind: SlotKind::Hardware,
            blob: &[2; 9],
        };
        let recovery = PlainSlot {
            domain: DomainId::Password,
            kind: SlotKind::Recovery,
            blob: &[3; 9],
        };
        store
            .write_slots(Some(&password_slot(1)), &[hardware, recovery])
            .unwrap();

        assert_eq!(store.password_slot().unwrap(), Some(password_slot(1)));
        assert_eq!(
            store.slot(DomainId::Totp, SlotKind::Hardware).unwrap(),
            Some(vec![2; 9])
        );
        assert_eq!(
            store.slot(DomainId::Password, SlotKind::Recovery).unwrap(),
            Some(vec![3; 9])
        );
        assert_eq!(
            store.slot(DomainId::Passkey, SlotKind::Hardware).unwrap(),
            None
        );

        store.write_slots(Some(&password_slot(4)), &[]).unwrap();
        assert_eq!(store.password_slot().unwrap(), Some(password_slot(4)));
    }

    #[test]
    fn a_rejected_slot_aborts_the_whole_write() {
        let (_dir, mut store) = store();
        // A hardware slot for the password domain violates the schema.
        let invalid = PlainSlot {
            domain: DomainId::Password,
            kind: SlotKind::Hardware,
            blob: &[2; 9],
        };
        assert!(
            store
                .write_slots(Some(&password_slot(1)), &[invalid])
                .is_err()
        );
        assert_eq!(store.password_slot().unwrap(), None);
    }

    #[test]
    fn out_of_range_kdf_parameters_on_disk_are_refused() {
        let (_dir, mut store) = store();
        store.write_slots(Some(&password_slot(1)), &[]).unwrap();
        store
            .conn
            .execute(
                "UPDATE key_slots SET kdf_m_kib = 4000000 WHERE kind = 1",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.password_slot(),
            Err(VaultError::Crypto(zp_crypto::CryptoError::InvalidKdfParams))
        ));
    }
}
