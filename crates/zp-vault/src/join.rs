//! Adding a device to a vault (`docs/spec/pairing.md` §3.3).
//!
//! The joining device generates its keys ([`JoinIdentity`]) and describes itself
//! to an existing device. That device, with every domain unlocked, introduces it
//! and hands over the vault keys ([`Vault::grant`]). The joining device then
//! creates its own vault file from the grant ([`Vault::join`]) and fetches the
//! content by syncing.
//!
//! The types here are plain data; carrying them between the devices over the
//! pairing channel is the job of `zp-pairing`.

use core::fmt;
use std::path::Path;

use zeroize::Zeroizing;
use zp_crypto::{
    ChannelKey, DeviceId, DeviceSigningKey, DomainId, HardwareBound, HardwareKeyStore, KEY_LEN,
    Passkey, Password, SignPublicKey, Totp, VaultId, VaultKey,
};
use zp_sync::{ChannelPublicKey, DeviceRecord, Revocation};

use crate::clock::Clock;
use crate::keyslots::{PlainSlot, SlotKind};
use crate::vault::{Keys, check_master_password, new_password_slot};
use crate::{AutoLock, CreateOptions, KdfChoice, Store, Vault, VaultError};

/// The key generation every grant currently carries.
const FIRST_EPOCH: u32 = 1;

/// The keys a device generates for itself before it joins a vault.
pub struct JoinIdentity {
    device_id: DeviceId,
    signing_key: DeviceSigningKey,
    channel_key: ChannelKey,
}

impl JoinIdentity {
    /// Generates a device identifier, a signing key and a channel key.
    pub fn generate() -> Result<Self, VaultError> {
        Ok(Self {
            device_id: DeviceId::generate()?,
            signing_key: DeviceSigningKey::generate()?,
            channel_key: ChannelKey::generate()?,
        })
    }

    /// The identifier this device chose for itself.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The public half of the signing key.
    pub fn sign_pk(&self) -> SignPublicKey {
        self.signing_key.public_key()
    }

    /// The channel key, also used as the static key of the pairing handshake so
    /// that the existing device can tie the request to the channel.
    pub fn channel_key(&self) -> &ChannelKey {
        &self.channel_key
    }
}

impl fmt::Debug for JoinIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JoinIdentity({})", self.device_id)
    }
}

/// One vault key handed to a joining device.
pub struct GrantedKey {
    /// The domain the key belongs to.
    pub domain: DomainId,
    /// The generation of the key.
    pub epoch: u32,
    /// The raw vault key. Only ever travels inside the pairing channel.
    pub key: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for GrantedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GrantedKey({:?}, epoch {}, <redacted>)",
            self.domain, self.epoch
        )
    }
}

/// Everything a joining device needs from the device that introduces it.
#[derive(Debug)]
pub struct VaultGrant {
    /// The vault being joined.
    pub vault_id: VaultId,
    /// The device registry, including the record of the joining device.
    pub records: Vec<DeviceRecord>,
    /// The revocations known to the introducing device.
    pub revocations: Vec<Revocation>,
    /// The vault keys of every domain of the vault.
    pub keys: Vec<GrantedKey>,
}

impl Vault {
    /// This device's key pair for the Noise channels.
    pub fn channel_key(&self) -> Result<ChannelKey, VaultError> {
        self.store.channel_key()
    }

    /// Admits a new device to the vault: signs its record into the registry and
    /// returns the grant to send it over the pairing channel.
    ///
    /// Every domain of this vault must be unlocked, so admitting a device takes
    /// the master password *and* hardware verification on this device. The
    /// caller must have confirmed with the user that `name` is the device they
    /// mean to add.
    pub fn grant(
        &mut self,
        device_id: DeviceId,
        sign_pk: SignPublicKey,
        noise_pk: ChannelPublicKey,
        name: &str,
    ) -> Result<VaultGrant, VaultError> {
        self.enforce_auto_lock();
        let now_ms = self.store.now_ms();

        // Collect the keys first: nothing is written unless all are available.
        let mut keys = vec![GrantedKey {
            domain: DomainId::Password,
            epoch: FIRST_EPOCH,
            key: self.keys.get::<Password>(now_ms)?.to_transfer_bytes(),
        }];
        if self.has_domain(DomainId::Totp)? {
            keys.push(GrantedKey {
                domain: DomainId::Totp,
                epoch: FIRST_EPOCH,
                key: self.keys.get::<Totp>(now_ms)?.to_transfer_bytes(),
            });
        }
        if self.has_domain(DomainId::Passkey)? {
            keys.push(GrantedKey {
                domain: DomainId::Passkey,
                epoch: FIRST_EPOCH,
                key: self.keys.get::<Passkey>(now_ms)?.to_transfer_bytes(),
            });
        }

        let key = self.keys.get::<Password>(now_ms)?;
        self.store
            .introduce_device(key, device_id, sign_pk, noise_pk, name)?;
        let registry = self.store.registry()?;
        Ok(VaultGrant {
            vault_id: self.store.vault_id(),
            records: registry.records().cloned().collect(),
            revocations: registry.revocations().cloned().collect(),
            keys,
        })
    }

    /// Creates this device's vault file from a grant.
    ///
    /// The password domain is protected by `master_password`, which is this
    /// device's own and may differ from the other devices'. With a hardware key
    /// store the TOTP and passkey vault keys are wrapped by it; without one they
    /// are discarded, and those domains sync as ciphertext this device cannot
    /// open.
    ///
    /// The returned vault is unlocked but empty: its content arrives by syncing.
    pub fn join(
        path: &Path,
        identity: JoinIdentity,
        grant: VaultGrant,
        master_password: &str,
        hardware: Option<&dyn HardwareKeyStore>,
        options: CreateOptions,
    ) -> Result<Self, VaultError> {
        check_master_password(master_password)?;
        if let KdfChoice::Fixed(params) = options.kdf
            && !params.meets_minimum()
        {
            return Err(VaultError::WeakKdf);
        }
        if grant.keys.iter().any(|key| key.epoch != FIRST_EPOCH) {
            return Err(VaultError::InvalidGrant("unsupported key generation"));
        }
        let clock = options.clock.unwrap_or_else(Clock::system);
        let store = Store::create_for_vault(path, grant.vault_id, identity.device_id, clock)?;
        let result = Self::install_grant(
            store,
            identity,
            grant,
            master_password,
            hardware,
            options.kdf,
        );
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn install_grant(
        mut store: Store,
        identity: JoinIdentity,
        grant: VaultGrant,
        master_password: &str,
        hardware: Option<&dyn HardwareKeyStore>,
        kdf: KdfChoice,
    ) -> Result<Self, VaultError> {
        let vault_id = store.vault_id();
        let now_ms = store.now_ms();
        let granted = |domain: DomainId| grant.keys.iter().find(|key| key.domain == domain);

        store.adopt_channel_key(&identity.channel_key)?;
        // Fails unless the registry contains this device with exactly its keys.
        store.import_registry(
            &identity.signing_key,
            grant.records.clone(),
            grant.revocations.clone(),
        )?;

        let vk_p = granted(DomainId::Password)
            .map(|key| VaultKey::<Password>::from_transfer_bytes(&key.key))
            .ok_or(VaultError::InvalidGrant(
                "the password domain key is missing",
            ))?;
        let password_slot = new_password_slot(&vk_p, &vault_id, master_password, kdf)?;

        // The hardware-bound domains need a key store on this device.
        let vk_t = hardware
            .and_then(|_| granted(DomainId::Totp))
            .map(|key| VaultKey::<Totp>::from_transfer_bytes(&key.key));
        let vk_k = hardware
            .and_then(|_| granted(DomainId::Passkey))
            .map(|key| VaultKey::<Passkey>::from_transfer_bytes(&key.key));
        let mut hardware_slots = Vec::new();
        if let Some(hardware) = hardware {
            if let Some(vk) = &vk_t {
                hardware_slots.push((DomainId::Totp, hardware_slot(vk, hardware, &vault_id)?));
            }
            if let Some(vk) = &vk_k {
                hardware_slots.push((DomainId::Passkey, hardware_slot(vk, hardware, &vault_id)?));
            }
        }
        let plain: Vec<PlainSlot<'_>> = hardware_slots
            .iter()
            .map(|(domain, blob)| PlainSlot {
                domain: *domain,
                kind: SlotKind::Hardware,
                blob,
            })
            .collect();
        store.write_slots(Some(&password_slot), &plain)?;

        let mut keys = Keys::default();
        store.add_device_key_slot(&identity.signing_key, &vk_p)?;
        keys.insert(vk_p, now_ms);
        if let Some(vk) = vk_t {
            store.add_device_key_slot(&identity.signing_key, &vk)?;
            keys.insert(vk, now_ms);
        }
        if let Some(vk) = vk_k {
            store.add_device_key_slot(&identity.signing_key, &vk)?;
            keys.insert(vk, now_ms);
        }
        Ok(Self {
            store,
            keys,
            auto_lock: AutoLock::default(),
        })
    }
}

fn hardware_slot<D: HardwareBound>(
    key: &VaultKey<D>,
    hardware: &dyn HardwareKeyStore,
    vault_id: &VaultId,
) -> Result<Vec<u8>, VaultError> {
    Ok(key.wrap_with_hardware(hardware, vault_id)?)
}
