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
    ChannelKey, DeviceId, DeviceSigningKey, Domain, DomainId, HardwareBound, HardwareKeyStore,
    KEY_LEN, Passkey, Password, SignPublicKey, Totp, VaultId, VaultKey,
};
use zp_sync::{ChannelPublicKey, DeviceRecord, Revocation};

use crate::clock::Clock;
use crate::keyslots::{PlainSlot, SlotKind};
use crate::vault::{Keys, check_master_password, new_password_slot};
use crate::{AutoLock, CreateOptions, KdfChoice, Store, Vault, VaultError};

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
    /// The vault keys of every domain of the vault, of every generation the
    /// introducing device holds. Within a domain, the key to write with (and to
    /// keep in the key slot) comes last.
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
        let mut keys = self.granted_keys::<Password>()?;
        if self.has_domain(DomainId::Totp)? {
            keys.extend(self.granted_keys::<Totp>()?);
        }
        if self.has_domain(DomainId::Passkey)? {
            keys.extend(self.granted_keys::<Passkey>()?);
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

    /// The keys of domain `D` as a joining device needs them.
    fn granted_keys<D: Domain>(&mut self) -> Result<Vec<GrantedKey>, VaultError> {
        let ring = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        Ok(ring
            .export()
            .into_iter()
            .map(|(epoch, key)| GrantedKey {
                domain: D::ID,
                epoch,
                key,
            })
            .collect())
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
        if grant.keys.iter().any(|key| key.epoch == 0) {
            return Err(VaultError::InvalidGrant("key generations start at 1"));
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

        store.adopt_channel_key(&identity.channel_key)?;
        // Fails unless the registry contains this device with exactly its keys.
        store.import_registry(
            &identity.signing_key,
            grant.records.clone(),
            grant.revocations.clone(),
        )?;

        let vk_p = Granted::<Password>::from(&grant).ok_or(VaultError::InvalidGrant(
            "the password domain key is missing",
        ))?;
        let password_slot =
            new_password_slot(&vk_p.slot_key, &vault_id, master_password, kdf, vk_p.epoch)?;

        // The hardware-bound domains need a key store on this device.
        let vk_t = hardware.and_then(|_| Granted::<Totp>::from(&grant));
        let vk_k = hardware.and_then(|_| Granted::<Passkey>::from(&grant));
        let mut hardware_slots = Vec::new();
        if let Some(hardware) = hardware {
            if let Some(vk) = &vk_t {
                hardware_slots.push((
                    DomainId::Totp,
                    vk.epoch,
                    hardware_slot(&vk.slot_key, hardware, &vault_id)?,
                ));
            }
            if let Some(vk) = &vk_k {
                hardware_slots.push((
                    DomainId::Passkey,
                    vk.epoch,
                    hardware_slot(&vk.slot_key, hardware, &vault_id)?,
                ));
            }
        }
        let plain: Vec<PlainSlot<'_>> = hardware_slots
            .iter()
            .map(|(domain, epoch, blob)| PlainSlot {
                domain: *domain,
                kind: SlotKind::Hardware,
                epoch: *epoch,
                blob,
            })
            .collect();
        store.write_slots(Some(&password_slot), &plain)?;

        let mut keys = Keys::default();
        vk_p.install(&mut store, &identity.signing_key, &mut keys, now_ms)?;
        if let Some(vk) = vk_t {
            vk.install(&mut store, &identity.signing_key, &mut keys, now_ms)?;
        }
        if let Some(vk) = vk_k {
            vk.install(&mut store, &identity.signing_key, &mut keys, now_ms)?;
        }
        Ok(Self {
            store,
            keys,
            auto_lock: AutoLock::default(),
        })
    }
}

/// The keys of one domain as they came in a grant.
struct Granted<D: Domain> {
    /// The key to write with: it goes into the key slot.
    slot_key: VaultKey<D>,
    epoch: u32,
    /// The keys of the other generations, needed to read older versions.
    others: Vec<(u32, VaultKey<D>)>,
}

impl<D: Domain> Granted<D> {
    fn from(grant: &VaultGrant) -> Option<Self> {
        let mut keys: Vec<(u32, VaultKey<D>)> = grant
            .keys
            .iter()
            .filter(|key| key.domain == D::ID)
            .map(|key| (key.epoch, VaultKey::from_transfer_bytes(&key.key)))
            .collect();
        let (epoch, slot_key) = keys.pop()?;
        Some(Self {
            slot_key,
            epoch,
            others: keys,
        })
    }

    /// After the key slot has been written: stores the other keys wrapped
    /// under the slot key, gives the domain the device signing key and unlocks
    /// it.
    fn install(
        self,
        store: &mut Store,
        signing_key: &DeviceSigningKey,
        keys: &mut Keys,
        now_ms: u64,
    ) -> Result<(), VaultError> {
        for (epoch, key) in &self.others {
            store.add_key_link(&self.slot_key, self.epoch, key, *epoch)?;
        }
        let ring = store.key_ring(self.slot_key, self.epoch)?;
        store.add_device_key_slot(signing_key, &ring)?;
        keys.insert(ring, now_ms);
        Ok(())
    }
}

fn hardware_slot<D: HardwareBound>(
    key: &VaultKey<D>,
    hardware: &dyn HardwareKeyStore,
    vault_id: &VaultId,
) -> Result<Vec<u8>, VaultError> {
    Ok(key.wrap_with_hardware(hardware, vault_id)?)
}
