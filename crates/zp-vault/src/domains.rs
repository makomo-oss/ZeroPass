//! The TOTP and passkey domains of a device that does not have them yet
//! (ADR-0011).
//!
//! A device without a hardware key store has no slot for these domains. Other
//! devices of the vault may have them all the same: then their keys are to be
//! received from such a device. This module tells whether there are signs of
//! that.

use rusqlite::params;
use zp_crypto::{DomainId, HardwareBound, HardwareKeyStore, Password, VaultKey};

use crate::keyslots::{PlainSlot, SlotKind};
use crate::store::{get_meta, set_meta};
use crate::{Store, Vault, VaultError};

/// The domains whose keys a pairing grant carried but this device could not
/// keep, one byte per domain.
const META_GRANTED_ELSEWHERE: &str = "granted_elsewhere";

/// The domains that need a hardware key store.
pub(crate) const HARDWARE_DOMAINS: [DomainId; 2] = [DomainId::Totp, DomainId::Passkey];

impl Store {
    /// Records that the pairing grant carried the keys of `domains`, which this
    /// device did not keep.
    pub(crate) fn note_granted_elsewhere(&self, domains: &[DomainId]) -> Result<(), VaultError> {
        if domains.is_empty() {
            return Ok(());
        }
        let bytes: Vec<u8> = domains.iter().map(|domain| domain.as_u8()).collect();
        set_meta(&self.conn, META_GRANTED_ELSEWHERE, &bytes)
    }

    /// Whether the pairing grant carried the keys of `domain`.
    fn granted_elsewhere(&self, domain: DomainId) -> Result<bool, VaultError> {
        Ok(get_meta(&self.conn, META_GRANTED_ELSEWHERE)?
            .is_some_and(|bytes| bytes.contains(&domain.as_u8())))
    }

    /// Whether the vault file holds anything of `domain` that another device
    /// wrote: an item or a version of one (deleted or not), or a key update.
    fn holds_traces_of(&self, domain: DomainId) -> Result<bool, VaultError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM items WHERE domain = ?1)
                 OR EXISTS (SELECT 1 FROM item_history WHERE domain = ?1)
                 OR EXISTS (SELECT 1 FROM key_updates WHERE domain = ?1)",
            params![domain.as_u8()],
            |row| row.get(0),
        )?)
    }
}

impl Vault {
    /// For a domain this device does not have: whether there are signs that
    /// other devices of the vault have it. Its keys came with the pairing, or
    /// the vault holds its items or key updates. `false` for a domain this
    /// device has.
    ///
    /// The signs are not proof either way: a device that has the domain but
    /// has written nothing with it leaves none.
    pub fn domain_elsewhere(&self, domain: DomainId) -> Result<bool, VaultError> {
        if self.has_domain(domain)? {
            return Ok(false);
        }
        Ok(self.store.granted_elsewhere(domain)? || self.store.holds_traces_of(domain)?)
    }

    /// The hardware-bound domains this device does not have although other
    /// devices seem to (see [`Self::domain_elsewhere`]). Revoking a device from
    /// here leaves their keys unreplaced, and loses them if the revoked device
    /// holds the last copy.
    pub fn domains_at_risk(&self) -> Result<Vec<DomainId>, VaultError> {
        let mut at_risk = Vec::new();
        for domain in HARDWARE_DOMAINS {
            if self.domain_elsewhere(domain)? {
                at_risk.push(domain);
            }
        }
        Ok(at_risk)
    }

    /// Makes hardware-bound domain `D` on this device, for a vault that has it
    /// nowhere (ADR-0011 §2): a new vault key of generation 1, wrapped by
    /// `hardware` (which verifies the user), and a slot for the device signing
    /// key. The domain is left unlocked.
    ///
    /// The password domain must be unlocked (it holds the device signing key).
    /// Fails with [`VaultError::DomainPresent`] if this device has the domain,
    /// and with [`VaultError::DomainElsewhere`] if other devices seem to have
    /// it: then its keys are to be received from one of them.
    pub fn set_up_domain<D: HardwareBound>(
        &mut self,
        hardware: &dyn HardwareKeyStore,
    ) -> Result<(), VaultError> {
        self.enforce_auto_lock();
        if self.has_domain(D::ID)? {
            return Err(VaultError::DomainPresent(D::ID));
        }
        if self.domain_elsewhere(D::ID)? {
            return Err(VaultError::DomainElsewhere(D::ID));
        }
        let signer = self
            .signer_from::<Password>()?
            .ok_or(VaultError::Locked(DomainId::Password))?;
        let vault_id = self.store.vault_id();
        let key = VaultKey::<D>::generate()?;
        // The user is verified here, before anything is written.
        let blob = key.wrap_with_hardware(hardware, &vault_id)?;
        self.store.write_slots(
            None,
            &[PlainSlot {
                domain: D::ID,
                kind: SlotKind::Hardware,
                epoch: 1,
                blob: &blob,
            }],
        )?;
        self.store.add_device_key_slot(&signer, &key)?;
        let ring = self.store.key_ring(key, 1)?;
        self.keys.insert(ring, self.store.now_ms());
        Ok(())
    }
}
