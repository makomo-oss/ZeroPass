//! The vault: a vault file plus the keys of the domains that are currently
//! unlocked.
//!
//! Each key domain is unlocked and locked independently:
//!
//! | Domain | Unlocked by | Default idle timeout |
//! |---|---|---|
//! | Password | the master password | 5 minutes |
//! | TOTP | a hardware key store (user verification) | 1 minute |
//! | Passkey | a hardware key store (user verification) | 1 minute |
//!
//! Unlocking the password domain never unlocks the other two.

use std::any::Any;
use std::path::Path;
use std::time::Duration;

use zp_crypto::{
    CryptoError, DeviceId, DeviceSigningKey, Domain, DomainId, HardwareBound, HardwareKeyError,
    HardwareKeyStore, ItemId, KdfParams, Passkey, Password, Totp, VaultId, VaultKey,
    derive_password_kek, rng,
};

use zp_sync::{Registry, VersionVector};

use crate::clock::Clock;
use crate::device::default_device_name;
use crate::keyslots::{PasswordSlot, PlainSlot, SlotKind};
use crate::model::{Content, Item, TotpEntry};
use crate::totp::{self, TotpCode};
use crate::{HistoryEntry, Store, VaultError};

/// Minimum length of a master password, in characters.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;

/// How the Argon2id parameters of a password slot are chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfChoice {
    /// Measure this machine and aim for the given derivation time.
    Calibrate(Duration),
    /// Use exactly these parameters. They must meet [`KdfParams::MINIMUM`].
    Fixed(KdfParams),
}

impl Default for KdfChoice {
    /// Calibrate for about half a second.
    fn default() -> Self {
        KdfChoice::Calibrate(Duration::from_millis(500))
    }
}

impl KdfChoice {
    fn resolve(self) -> Result<KdfParams, VaultError> {
        let params = match self {
            KdfChoice::Calibrate(target) => KdfParams::calibrate(target)?,
            KdfChoice::Fixed(params) => params,
        };
        if params.meets_minimum() {
            Ok(params)
        } else {
            Err(VaultError::WeakKdf)
        }
    }
}

/// Options for [`Vault::create`].
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// Key-derivation cost for the master password.
    pub kdf: KdfChoice,
    /// Time source; the system clock if `None`.
    pub clock: Option<Clock>,
    /// Name of this device in the registry; taken from the environment if `None`.
    pub device_name: Option<String>,
}

/// Idle timeouts after which a domain locks itself. `None` disables the timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoLock {
    /// Timeout of the password domain.
    pub password: Option<Duration>,
    /// Timeout of the hardware-bound domains (TOTP and passkey).
    pub hardware: Option<Duration>,
}

impl Default for AutoLock {
    fn default() -> Self {
        Self {
            password: Some(Duration::from_secs(5 * 60)),
            hardware: Some(Duration::from_secs(60)),
        }
    }
}

impl AutoLock {
    fn for_domain(&self, domain: DomainId) -> Option<Duration> {
        match domain {
            DomainId::Password => self.password,
            DomainId::Totp | DomainId::Passkey => self.hardware,
        }
    }
}

/// An unlocked vault key, type-erased so the three domains can share one table.
/// Dropping it wipes the key.
struct Unlocked {
    key: Box<dyn Any + Send + Sync>,
    last_used_ms: u64,
}

/// The keys of the currently unlocked domains.
#[derive(Default)]
pub(crate) struct Keys([Option<Unlocked>; 3]);

impl Keys {
    const fn index(domain: DomainId) -> usize {
        domain.as_u8() as usize - 1
    }

    pub(crate) fn insert<D: Domain>(&mut self, key: VaultKey<D>, now_ms: u64) {
        self.0[Self::index(D::ID)] = Some(Unlocked {
            key: Box::new(key),
            last_used_ms: now_ms,
        });
    }

    /// Borrows the key of domain `D` and records the use.
    pub(crate) fn get<D: Domain>(&mut self, now_ms: u64) -> Result<&VaultKey<D>, VaultError> {
        let unlocked = self.0[Self::index(D::ID)]
            .as_mut()
            .ok_or(VaultError::Locked(D::ID))?;
        unlocked.last_used_ms = now_ms;
        unlocked.key.downcast_ref().ok_or(VaultError::Locked(D::ID))
    }

    fn remove(&mut self, domain: DomainId) {
        self.0[Self::index(domain)] = None;
    }

    pub(crate) fn is_unlocked(&self, domain: DomainId) -> bool {
        self.0[Self::index(domain)].is_some()
    }

    /// Locks every domain that has been idle for at least its timeout.
    pub(crate) fn expire(&mut self, now_ms: u64, auto_lock: &AutoLock) {
        for domain in DomainId::ALL {
            let Some(timeout) = auto_lock.for_domain(domain) else {
                continue;
            };
            let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
            let idle_too_long = self.0[Self::index(domain)]
                .as_ref()
                .is_some_and(|unlocked| now_ms.saturating_sub(unlocked.last_used_ms) >= timeout_ms);
            if idle_too_long {
                self.remove(domain);
            }
        }
    }
}

/// An open vault.
pub struct Vault {
    pub(crate) store: Store,
    pub(crate) keys: Keys,
    pub(crate) auto_lock: AutoLock,
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let unlocked: Vec<DomainId> = DomainId::ALL
            .into_iter()
            .filter(|&domain| self.keys.is_unlocked(domain))
            .collect();
        f.debug_struct("Vault")
            .field("vault_id", &self.store.vault_id())
            .field("unlocked", &unlocked)
            .finish_non_exhaustive()
    }
}

pub(crate) fn check_master_password(password: &str) -> Result<(), VaultError> {
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword);
    }
    Ok(())
}

pub(crate) fn new_password_slot(
    vault_key: &VaultKey<Password>,
    vault_id: &VaultId,
    master_password: &str,
    kdf: KdfChoice,
) -> Result<PasswordSlot, VaultError> {
    check_master_password(master_password)?;
    let params = kdf.resolve()?;
    let salt = rng::array()?;
    let kek = derive_password_kek(master_password, &salt, &params)?;
    Ok(PasswordSlot {
        blob: vault_key.wrap(&kek, vault_id)?,
        salt,
        params,
    })
}

impl Vault {
    /// Creates a new vault file protected by `master_password`.
    ///
    /// With a hardware key store, the TOTP and passkey domains are created too,
    /// wrapped only by that store. Without one they do not exist in this vault:
    /// they are never protected by the master password.
    ///
    /// The returned vault has every created domain unlocked.
    pub fn create(
        path: &Path,
        master_password: &str,
        hardware: Option<&dyn HardwareKeyStore>,
        options: CreateOptions,
    ) -> Result<Self, VaultError> {
        // Check cheap preconditions before anything touches the disk.
        check_master_password(master_password)?;
        if let KdfChoice::Fixed(params) = options.kdf
            && !params.meets_minimum()
        {
            return Err(VaultError::WeakKdf);
        }
        let clock = options.clock.unwrap_or_else(Clock::system);
        let store = Store::create_with_clock(path, clock)?;
        let device_name = options.device_name.unwrap_or_else(default_device_name);
        let result = Self::initialise(store, master_password, hardware, options.kdf, &device_name);
        if result.is_err() {
            // A vault without key slots is useless; do not leave it behind.
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn initialise(
        mut store: Store,
        master_password: &str,
        hardware: Option<&dyn HardwareKeyStore>,
        kdf: KdfChoice,
        device_name: &str,
    ) -> Result<Self, VaultError> {
        let vault_id = store.vault_id();
        let now_ms = store.now_ms();

        let vk_p = VaultKey::<Password>::generate()?;
        let password_slot = new_password_slot(&vk_p, &vault_id, master_password, kdf)?;

        let mut hardware_keys = None;
        let mut hardware_slots = Vec::new();
        if let Some(hardware) = hardware {
            let vk_t = VaultKey::<Totp>::generate()?;
            let vk_k = VaultKey::<Passkey>::generate()?;
            hardware_slots.push((
                DomainId::Totp,
                vk_t.wrap_with_hardware(hardware, &vault_id)?,
            ));
            hardware_slots.push((
                DomainId::Passkey,
                vk_k.wrap_with_hardware(hardware, &vault_id)?,
            ));
            hardware_keys = Some((vk_t, vk_k));
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

        // This device's identity: every domain can sign what it writes.
        let signer = store.provision_device(device_name)?;
        store.add_device_key_slot(&signer, &vk_p)?;
        let mut keys = Keys::default();
        keys.insert(vk_p, now_ms);
        if let Some((vk_t, vk_k)) = hardware_keys {
            store.add_device_key_slot(&signer, &vk_t)?;
            store.add_device_key_slot(&signer, &vk_k)?;
            keys.insert(vk_t, now_ms);
            keys.insert(vk_k, now_ms);
        }

        Ok(Self {
            store,
            keys,
            auto_lock: AutoLock::default(),
        })
    }

    /// Opens an existing vault file. Every domain starts locked.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        Self::open_with_clock(path, Clock::system())
    }

    /// Like [`Self::open`], with an explicit time source.
    pub fn open_with_clock(path: &Path, clock: Clock) -> Result<Self, VaultError> {
        let store = Store::open_with_clock(path, clock)?;
        if store.password_slot()?.is_none() {
            return Err(VaultError::Corrupt("the vault has no password slot"));
        }
        Ok(Self {
            store,
            keys: Keys::default(),
            auto_lock: AutoLock::default(),
        })
    }

    /// The identifier of this vault.
    pub fn vault_id(&self) -> VaultId {
        self.store.vault_id()
    }

    /// The identifier of this device's copy of the vault.
    pub fn device_id(&self) -> DeviceId {
        self.store.device_id()
    }

    /// The devices of this vault, as far as this device knows. Readable while
    /// locked: the registry is public information among the devices.
    pub fn registry(&self) -> Result<Registry, VaultError> {
        self.store.registry()
    }

    /// For each device, up to which sequence number its changes are held here.
    pub fn version_vector(&self) -> Result<VersionVector, VaultError> {
        self.store.version_vector()
    }

    /// The Argon2id parameters currently protecting the master password.
    pub fn kdf_params(&self) -> Result<KdfParams, VaultError> {
        Ok(self.password_slot()?.params)
    }

    fn password_slot(&self) -> Result<PasswordSlot, VaultError> {
        self.store
            .password_slot()?
            .ok_or(VaultError::Corrupt("the vault has no password slot"))
    }

    /// Derives `KEK-P` from `master_password` and opens the password slot with it.
    fn open_password_slot(&self, master_password: &str) -> Result<VaultKey<Password>, VaultError> {
        let slot = self.password_slot()?;
        let kek = derive_password_kek(master_password, &slot.salt, &slot.params)?;
        VaultKey::unwrap(&kek, &self.store.vault_id(), &slot.blob).map_err(|error| match error {
            CryptoError::Decrypt => VaultError::WrongPassword,
            other => VaultError::Crypto(other),
        })
    }

    /// The device signing key, taken from domain `D` if it is unlocked and has a
    /// slot for it.
    fn signer_from<D: Domain>(&mut self) -> Result<Option<DeviceSigningKey>, VaultError> {
        if !self.keys.is_unlocked(D::ID) || !self.store.has_device_key_slot(D::ID)? {
            return Ok(None);
        }
        let key = self.keys.get::<D>(self.store.now_ms())?;
        self.store.signer(key).map(Some)
    }

    /// Gives domain `D` a slot for the device signing key if it is unlocked and
    /// lacks one.
    fn give_device_key<D: Domain>(&mut self, signer: &DeviceSigningKey) -> Result<(), VaultError> {
        if self.keys.is_unlocked(D::ID) && !self.store.has_device_key_slot(D::ID)? {
            let key = self.keys.get::<D>(self.store.now_ms())?;
            self.store.add_device_key_slot(signer, key)?;
        }
        Ok(())
    }

    /// Runs after domain `D` has been unlocked. Completes what a vault file
    /// written by an earlier format lacks: the device identity, the device
    /// signing key for every unlocked domain, and signatures on this device's
    /// earlier versions in `D`. A no-op for up-to-date vaults.
    fn after_unlock<D: Domain>(&mut self) -> Result<(), VaultError> {
        if !self.store.is_provisioned()? {
            let signer = self.store.provision_device(&default_device_name())?;
            self.give_device_key::<D>(&signer)?;
        }
        let signer = match self.signer_from::<Password>()? {
            Some(signer) => Some(signer),
            None => match self.signer_from::<Totp>()? {
                Some(signer) => Some(signer),
                None => self.signer_from::<Passkey>()?,
            },
        };
        if let Some(signer) = signer {
            self.give_device_key::<Password>(&signer)?;
            self.give_device_key::<Totp>(&signer)?;
            self.give_device_key::<Passkey>(&signer)?;
        }
        if self.store.has_device_key_slot(D::ID)? {
            let key = self.keys.get::<D>(self.store.now_ms())?;
            self.store.sign_unsigned(key)?;
        }
        Ok(())
    }

    /// Unlocks the password domain, and only the password domain.
    pub fn unlock_password(&mut self, master_password: &str) -> Result<(), VaultError> {
        let key = self.open_password_slot(master_password)?;
        self.keys.insert(key, self.store.now_ms());
        self.after_unlock::<Password>()
    }

    /// Whether this vault has domain `domain` at all. The TOTP and passkey
    /// domains exist only if the vault was created with a hardware key store.
    pub fn has_domain(&self, domain: DomainId) -> Result<bool, VaultError> {
        let kind = match domain {
            DomainId::Password => SlotKind::Password,
            DomainId::Totp | DomainId::Passkey => SlotKind::Hardware,
        };
        Ok(self.store.slot(domain, kind)?.is_some())
    }

    /// Unlocks a hardware-bound domain (TOTP or passkey). The key store verifies
    /// the user; a dismissed prompt surfaces as
    /// [`HardwareKeyError::UserCancelled`].
    pub fn unlock_hardware<D: HardwareBound>(
        &mut self,
        hardware: &dyn HardwareKeyStore,
    ) -> Result<(), VaultError> {
        let slot = self
            .store
            .slot(D::ID, SlotKind::Hardware)?
            .ok_or(VaultError::DomainUnavailable(D::ID))?;
        let key = VaultKey::<D>::unwrap_with_hardware(hardware, &self.store.vault_id(), &slot)?;
        self.keys.insert(key, self.store.now_ms());
        self.after_unlock::<D>()
    }

    /// Locks one domain, wiping its key from memory.
    pub fn lock(&mut self, domain: DomainId) {
        self.keys.remove(domain);
    }

    /// Locks every domain.
    pub fn lock_all(&mut self) {
        for domain in DomainId::ALL {
            self.keys.remove(domain);
        }
    }

    /// Whether `domain` is currently unlocked, after applying idle timeouts.
    pub fn is_unlocked(&mut self, domain: DomainId) -> bool {
        self.enforce_auto_lock();
        self.keys.is_unlocked(domain)
    }

    /// The idle timeouts in effect.
    pub fn auto_lock(&self) -> AutoLock {
        self.auto_lock
    }

    /// Changes the idle timeouts.
    pub fn set_auto_lock(&mut self, auto_lock: AutoLock) {
        self.auto_lock = auto_lock;
        self.enforce_auto_lock();
    }

    /// Locks the domains whose idle timeout has passed. Every operation calls
    /// this first; a long-running host should also call it periodically so keys
    /// do not linger in memory while nothing happens.
    pub fn enforce_auto_lock(&mut self) {
        self.keys.expire(self.store.now_ms(), &self.auto_lock);
    }

    /// Replaces the master password.
    ///
    /// `current` is always verified, whether or not the password domain is
    /// unlocked. Only the password slot is rewritten (new salt and parameters);
    /// the vault key and all items stay as they are.
    pub fn change_master_password(
        &mut self,
        current: &str,
        new: &str,
        kdf: KdfChoice,
    ) -> Result<(), VaultError> {
        let vault_key = self.open_password_slot(current)?;
        let slot = new_password_slot(&vault_key, &self.store.vault_id(), new, kdf)?;
        self.store.write_slots(Some(&slot), &[])
    }

    /// The key of domain `D`, if it is unlocked and not idle for too long.
    fn key<'k, D: Domain>(
        keys: &'k mut Keys,
        store: &Store,
        auto_lock: &AutoLock,
    ) -> Result<&'k VaultKey<D>, VaultError> {
        let now_ms = store.now_ms();
        keys.expire(now_ms, auto_lock);
        keys.get(now_ms)
    }

    /// Stores a new item and returns its identifier.
    pub fn insert<I: Item>(&mut self, item: I) -> Result<ItemId, VaultError> {
        let key = Self::key::<I::Domain>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.insert_item(key, item)
    }

    /// Replaces the content of an item, keeping the previous version in history.
    pub fn update<I: Item>(&mut self, item_id: ItemId, item: I) -> Result<(), VaultError> {
        let key = Self::key::<I::Domain>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.update_item(key, item_id, item)
    }

    /// Reads an item of kind `I`.
    pub fn get<I: Item>(&mut self, item_id: ItemId) -> Result<I, VaultError> {
        let key = Self::key::<I::Domain>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.get_item(key, item_id)
    }

    /// Reads an item of any kind stored in domain `D`.
    pub fn get_content<D: Domain>(&mut self, item_id: ItemId) -> Result<Content, VaultError> {
        let key = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.get_content(key, item_id)
    }

    /// Lists every live item of domain `D`.
    pub fn list<D: Domain>(&mut self) -> Result<Vec<(ItemId, Content)>, VaultError> {
        let key = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.list_items(key)
    }

    /// The key domain a live item is stored in, or `None` if there is no such
    /// item. This is plaintext metadata and needs no unlocked domain.
    pub fn item_domain(&self, item_id: ItemId) -> Result<Option<DomainId>, VaultError> {
        Ok(self
            .store
            .current_row(item_id)?
            .filter(|row| row.payload.is_some())
            .map(|row| row.domain))
    }

    /// Stores several new items of one kind atomically; see
    /// [`Store::insert_items`].
    pub fn insert_many<I: Item>(
        &mut self,
        items: impl IntoIterator<Item = I>,
    ) -> Result<Vec<ItemId>, VaultError> {
        let key = Self::key::<I::Domain>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.insert_items(key, items)
    }

    /// The live items of domain `D` matching `query`; see [`Content::matches`].
    pub fn search<D: Domain>(&mut self, query: &str) -> Result<Vec<(ItemId, Content)>, VaultError> {
        let key = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.search_items(key, query)
    }

    /// Deletes an item of domain `D`. The domain must be unlocked.
    pub fn delete<D: Domain>(&mut self, item_id: ItemId) -> Result<(), VaultError> {
        let key = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.delete_item(key, item_id)
    }

    /// Generates the current one-time code of a TOTP entry. The TOTP domain must
    /// be unlocked.
    pub fn totp_code(&mut self, item_id: ItemId) -> Result<TotpCode, VaultError> {
        let entry: TotpEntry = self.get(item_id)?;
        Ok(totp::generate(&entry, self.store.now_ms() / 1000)?)
    }

    /// The superseded versions of an item of domain `D`, newest first.
    pub fn history<D: Domain>(&mut self, item_id: ItemId) -> Result<Vec<HistoryEntry>, VaultError> {
        let key = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        self.store.item_history(key, item_id)
    }
}

/// Whether an error means that the user declined or failed hardware verification.
pub fn is_user_cancelled(error: &VaultError) -> bool {
    matches!(
        error,
        VaultError::Crypto(CryptoError::HardwareKey(HardwareKeyError::UserCancelled))
    )
}
