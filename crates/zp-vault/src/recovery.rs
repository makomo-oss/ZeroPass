//! The recovery kit (`docs/spec/crypto.md` §8).
//!
//! There is no server to fall back on: if every device is lost, the vault can
//! only be restored from a backup copy of the vault file plus the recovery key
//! the user wrote down. Creating a kit stores each domain's vault key wrapped
//! under a key derived from that recovery key; recovering unwraps them and sets
//! up a new master password and the new device's hardware key store.

use std::path::Path;

use zp_crypto::{
    CryptoError, Domain, DomainId, HardwareBound, HardwareKeyStore, Passkey, Password, RecoveryKey,
    Totp, VaultId, VaultKey,
};

use crate::clock::Clock;
use crate::device::default_device_name;
use crate::keyslots::{PlainSlot, SlotKind};
use crate::vault::{Keys, check_master_password, new_password_slot};
use crate::{AutoLock, CreateOptions, KdfChoice, Store, Vault, VaultError};

fn wrong_key(error: CryptoError) -> VaultError {
    match error {
        CryptoError::Decrypt => VaultError::WrongRecoveryKey,
        other => VaultError::Crypto(other),
    }
}

/// Opens the recovery slot of domain `D`, if the kit covers that domain. Returns
/// the key in the slot and its generation.
fn open_recovery_slot<D: Domain>(
    store: &Store,
    recovery_key: &RecoveryKey,
) -> Result<Option<(VaultKey<D>, u32)>, VaultError> {
    let Some(slot) = store.slot(D::ID, SlotKind::Recovery)? else {
        return Ok(None);
    };
    let vault_id = store.vault_id();
    let kek = recovery_key.kek::<D>(&vault_id)?;
    let key = VaultKey::unwrap(&kek, &vault_id, &slot).map_err(wrong_key)?;
    Ok(Some((key, store.slot_epoch(D::ID, SlotKind::Recovery)?)))
}

/// Restores a hardware-bound domain onto this device's key store. Returns the new
/// hardware slot and the generation of its key, or `None` if the kit does not
/// cover the domain.
fn restore_hardware_domain<D: HardwareBound>(
    store: &Store,
    recovery_key: &RecoveryKey,
    hardware: &dyn HardwareKeyStore,
    keys: &mut Keys,
) -> Result<Option<(u32, Vec<u8>)>, VaultError> {
    let Some((vault_key, epoch)) = open_recovery_slot::<D>(store, recovery_key)? else {
        return Ok(None);
    };
    let slot = vault_key.wrap_with_hardware(hardware, &store.vault_id())?;
    keys.insert(store.key_ring(vault_key, epoch)?, store.now_ms());
    Ok(Some((epoch, slot)))
}

impl Vault {
    /// Whether a recovery kit exists for this vault.
    pub fn has_recovery_kit(&self) -> Result<bool, VaultError> {
        Ok(self
            .store
            .slot(DomainId::Password, SlotKind::Recovery)?
            .is_some())
    }

    fn recovery_slot<D: Domain>(
        &mut self,
        recovery_key: &RecoveryKey,
        vault_id: &VaultId,
    ) -> Result<(u32, Vec<u8>), VaultError> {
        // The kit holds the same key as this device's own slot, so that it
        // reaches exactly the generations this device reaches.
        let (epoch, key) = self.keys.get::<D>(self.store.now_ms())?.base();
        Ok((
            epoch,
            key.wrap(&recovery_key.kek::<D>(vault_id)?, vault_id)?,
        ))
    }

    /// Creates a recovery kit and returns the recovery key for the user to write
    /// down. It is shown once and stored nowhere.
    ///
    /// Every domain of the vault must be unlocked, so creating a kit takes the
    /// master password *and* hardware verification. Creating a new kit replaces
    /// the previous one: the old recovery key stops working.
    pub fn create_recovery_kit(&mut self) -> Result<RecoveryKey, VaultError> {
        self.enforce_auto_lock();
        let vault_id = self.store.vault_id();
        let recovery_key = RecoveryKey::generate()?;

        let mut slots = vec![(
            DomainId::Password,
            self.recovery_slot::<Password>(&recovery_key, &vault_id)?,
        )];
        if self.has_domain(DomainId::Totp)? {
            slots.push((
                DomainId::Totp,
                self.recovery_slot::<Totp>(&recovery_key, &vault_id)?,
            ));
        }
        if self.has_domain(DomainId::Passkey)? {
            slots.push((
                DomainId::Passkey,
                self.recovery_slot::<Passkey>(&recovery_key, &vault_id)?,
            ));
        }

        let plain: Vec<PlainSlot<'_>> = slots
            .iter()
            .map(|(domain, (epoch, blob))| PlainSlot {
                domain: *domain,
                kind: SlotKind::Recovery,
                epoch: *epoch,
                blob,
            })
            .collect();
        self.store.write_slots(None, &plain)?;
        Ok(recovery_key)
    }

    /// Restores access to a vault file with its recovery key.
    ///
    /// Sets `new_master_password` and, if a hardware key store is given, re-wraps
    /// the TOTP and passkey vault keys for this device. Without one, only the
    /// password domain is restored; the other domains remain recoverable later on
    /// a device that has a hardware key store. The copy also receives a new device
    /// identifier.
    ///
    /// The recovery kit stays valid afterwards. Fails with
    /// [`VaultError::WrongRecoveryKey`] if the key does not match this vault and
    /// leaves the file untouched in that case.
    pub fn recover(
        path: &Path,
        recovery_key: &RecoveryKey,
        new_master_password: &str,
        hardware: Option<&dyn HardwareKeyStore>,
        options: CreateOptions,
    ) -> Result<Self, VaultError> {
        check_master_password(new_master_password)?;
        if let KdfChoice::Fixed(params) = options.kdf
            && !params.meets_minimum()
        {
            return Err(VaultError::WeakKdf);
        }
        let clock = options.clock.unwrap_or_else(Clock::system);
        let mut store = Store::open_with_clock(path, clock)?;
        let vault_id = store.vault_id();
        let mut keys = Keys::default();

        // Everything is unwrapped and re-wrapped before the first write.
        let (vault_key, epoch) = open_recovery_slot::<Password>(&store, recovery_key)?
            .ok_or(VaultError::NoRecoveryKit)?;
        let password_slot = new_password_slot(
            &vault_key,
            &vault_id,
            new_master_password,
            options.kdf,
            epoch,
        )?;
        keys.insert(store.key_ring(vault_key, epoch)?, store.now_ms());

        let mut hardware_slots = Vec::new();
        if let Some(hardware) = hardware {
            if let Some(slot) =
                restore_hardware_domain::<Totp>(&store, recovery_key, hardware, &mut keys)?
            {
                hardware_slots.push((DomainId::Totp, slot));
            }
            if let Some(slot) =
                restore_hardware_domain::<Passkey>(&store, recovery_key, hardware, &mut keys)?
            {
                hardware_slots.push((DomainId::Passkey, slot));
            }
        }
        let plain: Vec<PlainSlot<'_>> = hardware_slots
            .iter()
            .map(|(domain, (epoch, blob))| PlainSlot {
                domain: *domain,
                kind: SlotKind::Hardware,
                epoch: *epoch,
                blob,
            })
            .collect();

        store.write_slots(Some(&password_slot), &plain)?;
        // The restored copy is a new device with its own identity.
        let device_name = options.device_name.unwrap_or_else(default_device_name);
        let signer = store.become_new_device(&device_name)?;
        let now_ms = store.now_ms();
        store.add_device_key_slot(&signer, keys.get::<Password>(now_ms)?)?;
        if keys.is_unlocked(DomainId::Totp) {
            store.add_device_key_slot(&signer, keys.get::<Totp>(now_ms)?)?;
        }
        if keys.is_unlocked(DomainId::Passkey) {
            store.add_device_key_slot(&signer, keys.get::<Passkey>(now_ms)?)?;
        }
        let mut vault = Self {
            store,
            keys,
            auto_lock: AutoLock::default(),
        };
        // Every earlier device has just been revoked, so the keys they hold are
        // replaced like after any other revocation (`sync.md` §8).
        vault.rotate_key::<Password>()?;
        if vault.keys.is_unlocked(DomainId::Totp) {
            vault.rotate_key::<Totp>()?;
        }
        if vault.keys.is_unlocked(DomainId::Passkey) {
            vault.rotate_key::<Passkey>()?;
        }
        Ok(vault)
    }
}
