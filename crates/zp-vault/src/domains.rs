//! The TOTP and passkey domains of a device that does not have them yet
//! (ADR-0011).
//!
//! A device without a hardware key store has no slot for these domains. Other
//! devices of the vault may have them all the same: then their keys are to be
//! received from such a device. This module tells whether there are signs of
//! that.

use rusqlite::params;
use zp_crypto::{
    DomainId, HardwareBound, HardwareKeyStore, Passkey, Password, Totp, VaultId, VaultKey,
};

use crate::keyslots::{PlainSlot, SlotKind};
use crate::store::{get_meta, set_meta};
use crate::{GrantedKey, Store, Vault, VaultError};

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

    /// The keys of the hardware-bound domains this device has, every
    /// generation, for a registered device that asks for them over the pairing
    /// channel (ADR-0011 §1). Within a domain, the key to write with comes last.
    ///
    /// Each of these domains must be unlocked. The caller must have checked
    /// that the asking device is a member in good standing at the other end of
    /// the channel, and that the user agreed.
    pub fn hand_over_keys(&mut self) -> Result<Vec<GrantedKey>, VaultError> {
        self.enforce_auto_lock();
        let mut keys = Vec::new();
        if self.has_domain(DomainId::Totp)? {
            keys.extend(self.granted_keys::<Totp>()?);
        }
        if self.has_domain(DomainId::Passkey)? {
            keys.extend(self.granted_keys::<Passkey>()?);
        }
        if keys.is_empty() {
            return Err(VaultError::NoKeysToHandOver);
        }
        Ok(keys)
    }

    /// Takes in the keys another device of vault `vault_id` handed over
    /// ([`Self::hand_over_keys`]). Returns the domains that gained keys.
    ///
    /// * A domain this device lacks gets a hardware slot for the key to write
    ///   with (wrapped by `hardware`, which verifies the user), links for the
    ///   other generations, and a slot for the device signing key. The password
    ///   domain must be unlocked (it holds that key).
    /// * A domain this device has (it must be unlocked) gains the keys its ring
    ///   lacks, linked under its slot key: two devices that each made the domain
    ///   on their own read each other's items once each has taken in the
    ///   other's keys (ADR-0011 §3).
    ///
    /// Everything is checked before the first write.
    pub fn take_keys(
        &mut self,
        vault_id: VaultId,
        keys: &[GrantedKey],
        hardware: &dyn HardwareKeyStore,
    ) -> Result<Vec<DomainId>, VaultError> {
        self.enforce_auto_lock();
        if vault_id != self.store.vault_id() {
            return Err(VaultError::InvalidGrant("the keys belong to another vault"));
        }
        if keys
            .iter()
            .any(|key| !HARDWARE_DOMAINS.contains(&key.domain) || key.epoch == 0)
        {
            return Err(VaultError::InvalidGrant(
                "only one-time code and passkey keys are handed over",
            ));
        }
        let totp = keys_of::<Totp>(keys);
        let passkey = keys_of::<Passkey>(keys);
        // What is needed for each domain, before anything is written.
        for (domain, wanted) in [
            (DomainId::Totp, !totp.is_empty()),
            (DomainId::Passkey, !passkey.is_empty()),
        ] {
            if !wanted {
                continue;
            }
            let needed = if self.has_domain(domain)? {
                domain
            } else {
                DomainId::Password
            };
            if !self.keys.is_unlocked(needed) {
                return Err(VaultError::Locked(needed));
            }
        }
        let mut changed = Vec::new();
        if self.take_domain(totp, hardware)? {
            changed.push(DomainId::Totp);
        }
        if self.take_domain(passkey, hardware)? {
            changed.push(DomainId::Passkey);
        }
        Ok(changed)
    }

    /// Takes in the keys of domain `D` (in the order handed over). Returns
    /// whether anything changed.
    fn take_domain<D: HardwareBound>(
        &mut self,
        mut keys: Vec<(u32, VaultKey<D>)>,
        hardware: &dyn HardwareKeyStore,
    ) -> Result<bool, VaultError> {
        let now_ms = self.store.now_ms();
        if !self.has_domain(D::ID)? {
            let Some((epoch, slot_key)) = keys.pop() else {
                return Ok(false);
            };
            let signer = self
                .signer_from::<Password>()?
                .ok_or(VaultError::Locked(DomainId::Password))?;
            // The user is verified here, before anything is written.
            let blob = slot_key.wrap_with_hardware(hardware, &self.store.vault_id())?;
            self.store.write_slots(
                None,
                &[PlainSlot {
                    domain: D::ID,
                    kind: SlotKind::Hardware,
                    epoch,
                    blob: &blob,
                }],
            )?;
            for (other_epoch, other) in &keys {
                self.store
                    .add_key_link(&slot_key, epoch, other, *other_epoch)?;
            }
            let ring = self.store.key_ring(slot_key, epoch)?;
            self.store.add_device_key_slot(&signer, &ring)?;
            self.keys.insert(ring, now_ms);
            return Ok(true);
        }

        let ring = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        keys.retain(|(epoch, key)| !ring.holds(*epoch, key));
        if keys.is_empty() {
            return Ok(false);
        }
        let (base_epoch, base) = ring.base();
        let base = VaultKey::<D>::from_transfer_bytes(&base.to_transfer_bytes());
        for (epoch, key) in &keys {
            self.store.add_key_link(&base, base_epoch, key, *epoch)?;
        }
        // Key links do not change what the ring was built from: build it anew.
        let ring = self.store.key_ring(base, base_epoch)?;
        self.keys.insert(ring, now_ms);
        Ok(true)
    }
}

/// The keys of domain `D` among `keys`, in their order.
fn keys_of<D: HardwareBound>(keys: &[GrantedKey]) -> Vec<(u32, VaultKey<D>)> {
    keys.iter()
        .filter(|key| key.domain == D::ID)
        .map(|key| (key.epoch, VaultKey::from_transfer_bytes(&key.key)))
        .collect()
}
