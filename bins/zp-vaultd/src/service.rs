//! The daemon's state and what it does with each request.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;
use zp_crypto::{
    Domain, DomainId, HardwareKeyError, HardwareKeyStore, InsecureSoftwareKeyStore, ItemId,
    KEY_LEN, PUBLIC_KEY_LEN, Passkey, Password, RecoveryKey, SealingKey, Totp, seal_to,
};
use zp_ipc::RelayEnd;
use zp_ipc::proto::{self, ErrorCode, request, response};
use zp_vault::model::Content;
use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError};

use crate::convert::{self, NewItem, bad_request, domain_name, locked, vault_error};
use crate::port::{self, KeyAgentPort};

/// Which key store protects the TOTP and passkey domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyStoreChoice {
    /// The platform's hardware key store, if this device has one.
    Platform,
    /// None: password domain only.
    None,
    /// The development-only software key store, kept in a file beside the vault.
    InsecureSoftware,
}

/// Which of the daemon's processes this is, and so which vault keys it may
/// ever hold (ADR-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The process the clients talk to. Holds the password domain only.
    Front,
    /// The worker of one hardware-bound domain. Holds that domain only.
    Domain(DomainId),
    /// A short-lived process for what needs the keys of every domain at
    /// once: creating, recovering and joining a vault, admitting a device,
    /// the recovery kit, revoking a device.
    Whole,
}

impl Scope {
    /// Whether a process of this scope may hold the keys of `domain`.
    pub(crate) fn holds(self, domain: DomainId) -> bool {
        match self {
            Scope::Whole => true,
            Scope::Front => domain == DomainId::Password,
            Scope::Domain(own) => own == domain,
        }
    }

    /// The word for this scope on the command line and in messages.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Scope::Front => "front",
            Scope::Domain(domain) => domain_name(domain),
            Scope::Whole => "whole",
        }
    }
}

pub(crate) type Reply = Result<response::Body, proto::Error>;

/// The associated data of a vault key sealed for another process of the daemon.
fn transfer_context(domain: DomainId, epoch: u32) -> Vec<u8> {
    let mut context = b"zeropass/v1/key-transfer".to_vec();
    context.push(domain.as_u8());
    context.extend_from_slice(&epoch.to_be_bytes());
    context
}

fn internal(message: impl Into<String>) -> proto::Error {
    proto::Error::new(ErrorCode::Internal, message)
}

fn done() -> Reply {
    Ok(response::Body::Done(proto::Done {}))
}

fn counts(summary: &zp_vault::export::ExportSummary) -> proto::ItemCounts {
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    proto::ItemCounts {
        logins: count(summary.logins),
        notes: count(summary.notes),
        totp: count(summary.totp),
        passkeys: count(summary.passkeys),
    }
}

/// An export error as the clients see it.
fn export_error(error: zp_vault::export::ExportError) -> proto::Error {
    use zp_vault::export::ExportError;
    match error {
        ExportError::WeakPassphrase => {
            proto::Error::new(ErrorCode::WeakPassword, error.to_string())
        }
        ExportError::WrongPassphrase => {
            proto::Error::new(ErrorCode::WrongPassword, error.to_string())
        }
        ExportError::NotAnExport | ExportError::UnsupportedVersion(_) | ExportError::Damaged => {
            proto::Error::new(ErrorCode::InvalidInput, error.to_string())
        }
        ExportError::Vault(error) => vault_error(error),
        ExportError::Crypto(error) => internal(error.to_string()),
    }
}

pub(crate) fn log(message: &str) {
    let _ = writeln!(io::stderr(), "zp-vaultd: {message}");
}

/// The one vault this daemon serves. `None` until the file exists and a request
/// needed it.
#[derive(Default)]
pub(crate) struct State {
    pub(crate) vault: Option<Vault>,
    /// The pairing offer that waits for the other device, if any.
    pub(crate) offer: Option<crate::pairing::PendingOffer>,
}

/// One process's hold on the vault: the vault file and the keys of the domains
/// this process may have (its [`Scope`]).
pub(crate) struct Service {
    pub(crate) path: PathBuf,
    pub(crate) key_store: KeyStoreChoice,
    pub(crate) scope: Scope,
    /// The way to the platform's hardware key store.
    port: Arc<dyn KeyAgentPort>,
    /// Receives the vault keys other processes of the daemon hand to this one.
    sealing: SealingKey,
    state: Mutex<State>,
}

impl Service {
    pub(crate) fn new(
        path: PathBuf,
        key_store: KeyStoreChoice,
        scope: Scope,
        port: Arc<dyn KeyAgentPort>,
    ) -> Result<Self, proto::Error> {
        Ok(Self {
            path,
            key_store,
            scope,
            port,
            sealing: SealingKey::generate().map_err(|error| internal(error.to_string()))?,
            state: Mutex::new(State::default()),
        })
    }

    /// Fails unless this process may hold the keys of every domain.
    pub(crate) fn whole(&self) -> Result<(), proto::Error> {
        if self.scope == Scope::Whole {
            Ok(())
        } else {
            Err(internal("this process does not hold every domain"))
        }
    }

    /// Fails unless this process may hold the keys of `domain`.
    fn holds(&self, domain: DomainId) -> Result<(), proto::Error> {
        if self.scope.holds(domain) {
            Ok(())
        } else {
            Err(internal(format!(
                "the {} process does not hold the {} domain",
                self.scope.name(),
                domain_name(domain)
            )))
        }
    }

    /// Forgets the open vault file: another process has replaced what it
    /// holds (recovery gives this copy a new identity).
    pub(crate) fn reset(&self) {
        *self.state() = State::default();
    }

    /// Whether the vault file exists.
    pub(crate) fn exists(&self) -> bool {
        self.state().vault.is_some() || self.path.exists()
    }

    /// The public key to seal a vault key to that is meant for this process.
    pub(crate) fn import_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.sealing.public_bytes()
    }

    /// Hands the unlocked `domain` to another process of the daemon: its slot
    /// key, sealed to the key that process gave.
    pub(crate) fn export(
        &self,
        domain: DomainId,
        to: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(u32, Vec<u8>), proto::Error> {
        let mut state = self.state();
        let vault = self.vault(&mut state)?;
        let (epoch, key) = match domain {
            DomainId::Password => vault.export_slot_key::<Password>(),
            DomainId::Totp => vault.export_slot_key::<Totp>(),
            DomainId::Passkey => vault.export_slot_key::<Passkey>(),
        }
        .map_err(vault_error)?;
        let sealed = seal_to(to, &transfer_context(domain, epoch), key.as_slice())
            .map_err(|error| internal(error.to_string()))?;
        Ok((epoch, sealed))
    }

    /// Unlocks `domain` with the slot key another process of the daemon
    /// sealed to [`Self::import_key`].
    pub(crate) fn import(
        &self,
        domain: DomainId,
        epoch: u32,
        sealed: &[u8],
    ) -> Result<(), proto::Error> {
        self.holds(domain)?;
        let key = self
            .sealing
            .open(&transfer_context(domain, epoch), sealed)
            .map_err(|_| internal("the handed-over key could not be opened"))?;
        let key: &[u8; KEY_LEN] = key
            .as_slice()
            .try_into()
            .map_err(|_| internal("the handed-over key has the wrong length"))?;
        let mut state = self.state();
        let vault = self.vault(&mut state)?;
        match domain {
            DomainId::Password => vault.adopt_slot_key::<Password>(epoch, key),
            DomainId::Totp => vault.adopt_slot_key::<Totp>(epoch, key),
            DomainId::Passkey => vault.adopt_slot_key::<Passkey>(epoch, key),
        }
        .map_err(vault_error)
    }

    /// The domain a live item is stored in, which needs no key.
    pub(crate) fn item_domain(&self, id: &[u8]) -> Result<DomainId, proto::Error> {
        let id = convert::item_id(id)?;
        let mut state = self.state();
        Self::domain_of(self.vault(&mut state)?, id)
    }

    /// Checks that a login belongs to the page the extension names
    /// (`docs/spec/extension.md` §4), for a request another process answers.
    pub(crate) fn bridge_check(
        &self,
        origin: &str,
        top: &str,
        item_id: &[u8],
    ) -> Result<(), proto::Error> {
        let mut state = self.state();
        crate::bridge::check(self.vault(&mut state)?, origin, top, item_id)
    }

    /// Whether the vault has `domain`. `false` if there is no vault yet.
    pub(crate) fn has_domain(&self, domain: DomainId) -> Result<bool, proto::Error> {
        if !self.exists() {
            return Ok(false);
        }
        let mut state = self.state();
        self.vault(&mut state)?
            .has_domain(domain)
            .map_err(vault_error)
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        // A panic in a request must not take the daemon's other clients with it.
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Locks the domains that have been idle for too long. Called periodically,
    /// so that keys do not stay in memory while nobody asks for anything.
    pub(crate) fn tick(&self) {
        let mut state = self.state();
        Self::expire_offer(&mut state);
        if let Some(vault) = state.vault.as_mut() {
            vault.enforce_auto_lock();
        }
    }

    /// Wipes every key.
    pub(crate) fn lock_all(&self) {
        if let Some(vault) = self.state().vault.as_mut() {
            vault.lock_all();
        }
    }

    pub(crate) fn dev_key_path(&self) -> PathBuf {
        self.path.with_extension("devkey")
    }

    /// The key store for the TOTP and passkey domains; `None` if this device
    /// has none. With `create`, the store's key is created if it is missing.
    pub(crate) fn hardware(
        &self,
        create: bool,
    ) -> Result<Option<Box<dyn HardwareKeyStore>>, proto::Error> {
        self.hardware_or_why(create).map(Result::ok)
    }

    /// Like [`Self::hardware`]; `Ok(Err)` says why this device has no key store.
    fn hardware_or_why(
        &self,
        create: bool,
    ) -> Result<Result<Box<dyn HardwareKeyStore>, String>, proto::Error> {
        let missing = |why: &str| Ok(Err(why.to_owned()));
        match self.key_store {
            KeyStoreChoice::None => missing("the daemon was started without one"),
            KeyStoreChoice::Platform => match port::key_store(&self.port, create) {
                Ok(store) => Ok(store),
                Err(HardwareKeyError::UserCancelled) => Err(proto::Error::new(
                    ErrorCode::UserCancelled,
                    HardwareKeyError::UserCancelled.to_string(),
                )),
                Err(error) => Err(internal(error.to_string())),
            },
            KeyStoreChoice::InsecureSoftware => {
                let path = self.dev_key_path();
                let store = if create {
                    let store = InsecureSoftwareKeyStore::generate()
                        .map_err(|error| internal(error.to_string()))?;
                    std::fs::write(&path, store.key_bytes().as_slice())
                        .map_err(|error| internal(format!("{}: {error}", path.display())))?;
                    store
                } else {
                    let bytes = match std::fs::read(&path) {
                        Ok(bytes) => Zeroizing::new(bytes),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            return missing("the software key store file is missing");
                        }
                        Err(error) => {
                            return Err(internal(format!("{}: {error}", path.display())));
                        }
                    };
                    let key: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        internal("the software key store file is malformed".to_owned())
                    })?;
                    InsecureSoftwareKeyStore::from_key_bytes(key)
                };
                Ok(Ok(Box::new(store)))
            }
        }
    }

    /// The open vault, opening the file on first use.
    pub(crate) fn vault<'s>(&self, state: &'s mut State) -> Result<&'s mut Vault, proto::Error> {
        let vault = match state.vault.take() {
            Some(vault) => vault,
            None => {
                if !self.path.exists() {
                    return Err(vault_error(VaultError::NotFound));
                }
                Vault::open(&self.path).map_err(vault_error)?
            }
        };
        Ok(state.vault.insert(vault))
    }

    fn status(&self, state: &mut State) -> Result<proto::StatusReply, proto::Error> {
        if state.vault.is_none() && !self.path.exists() {
            return Ok(proto::StatusReply {
                sandboxed: zp_sandbox::is_sandboxed(),
                pid: std::process::id(),
                ..proto::StatusReply::default()
            });
        }
        let vault = self.vault(state)?;
        let mut domains = Vec::new();
        for domain in DomainId::ALL {
            domains.push(proto::DomainStatus {
                domain: convert::domain_to_proto(domain) as i32,
                available: vault.has_domain(domain).map_err(vault_error)?,
                unlocked: vault.is_unlocked(domain),
            });
        }
        Ok(proto::StatusReply {
            vault_exists: true,
            vault_id: vault.vault_id().as_bytes().to_vec(),
            device_id: vault.device_id().as_bytes().to_vec(),
            domains,
            has_recovery_kit: vault.has_recovery_kit().map_err(vault_error)?,
            sandboxed: zp_sandbox::is_sandboxed(),
            pid: std::process::id(),
        })
    }

    fn create_vault(&self, state: &mut State, request: &proto::CreateVault) -> Reply {
        self.whole()?;
        if state.vault.is_some() || self.path.exists() {
            return Err(vault_error(VaultError::AlreadyExists));
        }
        let hardware = self.hardware(true)?;
        let created = Vault::create(
            &self.path,
            &request.master_password,
            hardware.as_deref(),
            CreateOptions::default(),
        );
        match created {
            Ok(vault) => state.vault = Some(vault),
            Err(error) => {
                if self.key_store == KeyStoreChoice::InsecureSoftware {
                    let _ = std::fs::remove_file(self.dev_key_path());
                }
                return Err(vault_error(error));
            }
        }
        self.status(state).map(response::Body::Status)
    }

    fn recover_vault(&self, state: &mut State, request: &proto::RecoverVault) -> Reply {
        self.whole()?;
        if !self.path.exists() {
            return Err(vault_error(VaultError::NotFound));
        }
        let recovery_key = RecoveryKey::from_code(&request.recovery_key)
            .map_err(|error| vault_error(error.into()))?;
        let hardware = self.hardware(true)?;
        // Recovery gives this copy a new device identity: what is open is stale.
        state.vault = None;
        let vault = Vault::recover(
            &self.path,
            &recovery_key,
            &request.new_master_password,
            hardware.as_deref(),
            CreateOptions::default(),
        )
        .map_err(vault_error)?;
        state.vault = Some(vault);
        self.status(state).map(response::Body::Status)
    }

    fn unlock(&self, state: &mut State, request: &proto::Unlock) -> Reply {
        let domain = convert::domain_from_proto(request.domain)?;
        self.holds(domain)?;
        let vault = self.vault(state)?;
        if domain == DomainId::Password {
            vault
                .unlock_password(&request.master_password)
                .map_err(vault_error)?;
            return done();
        }
        if !vault.has_domain(domain).map_err(vault_error)? {
            return Err(vault_error(VaultError::DomainUnavailable(domain)));
        }
        let hardware = self.hardware_or_why(false)?.map_err(|why| {
            proto::Error::about(
                ErrorCode::HardwareUnavailable,
                convert::domain_to_proto(domain),
                format!("no hardware key store is available to unlock this domain: {why}"),
            )
        })?;
        match domain {
            DomainId::Totp => vault.unlock_hardware::<Totp>(hardware.as_ref()),
            _ => vault.unlock_hardware::<Passkey>(hardware.as_ref()),
        }
        .map_err(vault_error)?;
        done()
    }

    fn list_items(&self, state: &mut State, request: &proto::ListItems) -> Reply {
        fn list<D: Domain>(
            vault: &mut Vault,
            query: &str,
        ) -> Result<Vec<(ItemId, Content)>, VaultError> {
            if query.is_empty() {
                vault.list::<D>()
            } else {
                vault.search::<D>(query)
            }
        }
        let vault = self.vault(state)?;
        let mut items = match convert::domain_from_proto(request.domain)? {
            DomainId::Password => list::<Password>(vault, &request.query),
            DomainId::Totp => list::<Totp>(vault, &request.query),
            DomainId::Passkey => list::<Passkey>(vault, &request.query),
        }
        .map_err(vault_error)?;
        items.sort_by(|a, b| a.1.title().cmp(b.1.title()).then(a.0.cmp(&b.0)));
        Ok(response::Body::Items(proto::Items {
            items: items
                .iter()
                .map(|(id, content)| convert::summary(*id, content))
                .collect(),
        }))
    }

    /// The domain an item is stored in.
    fn domain_of(vault: &Vault, id: ItemId) -> Result<DomainId, proto::Error> {
        vault
            .item_domain(id)
            .map_err(vault_error)?
            .ok_or_else(|| vault_error(VaultError::ItemNotFound))
    }

    fn get_item(&self, state: &mut State, request: &proto::GetItem) -> Reply {
        let id = convert::item_id(&request.item_id)?;
        let vault = self.vault(state)?;
        let content = match Self::domain_of(vault, id)? {
            DomainId::Password => vault.get_content::<Password>(id),
            DomainId::Totp => vault.get_content::<Totp>(id),
            DomainId::Passkey => vault.get_content::<Passkey>(id),
        }
        .map_err(vault_error)?;
        Ok(response::Body::Item(convert::item(id, &content)))
    }

    fn add_item(&self, state: &mut State, request: proto::AddItem) -> Reply {
        let item = convert::new_item(request.item)?;
        let vault = self.vault(state)?;
        // Report a locked domain before a missing one would be reported as an
        // internal error by the insert.
        Self::require_domain(vault, item.domain())?;
        let id = match item {
            NewItem::Login(login) => vault.insert(login),
            NewItem::Note(note) => vault.insert(note),
            NewItem::Totp(entry) => vault.insert(entry),
        }
        .map_err(vault_error)?;
        Ok(response::Body::ItemAdded(proto::ItemAdded {
            item_id: id.as_bytes().to_vec(),
        }))
    }

    fn update_item(&self, state: &mut State, request: proto::UpdateItem) -> Reply {
        let id = convert::item_id(&request.item_id)?;
        let item = convert::new_item(request.item)?;
        let vault = self.vault(state)?;
        match item {
            NewItem::Login(login) => vault.update(id, login),
            NewItem::Note(note) => vault.update(id, note),
            NewItem::Totp(entry) => vault.update(id, entry),
        }
        .map_err(vault_error)?;
        done()
    }

    fn delete_item(&self, state: &mut State, request: &proto::DeleteItem) -> Reply {
        let id = convert::item_id(&request.item_id)?;
        let vault = self.vault(state)?;
        match Self::domain_of(vault, id)? {
            DomainId::Password => vault.delete::<Password>(id),
            DomainId::Totp => vault.delete::<Totp>(id),
            DomainId::Passkey => vault.delete::<Passkey>(id),
        }
        .map_err(vault_error)?;
        done()
    }

    fn totp_code(&self, state: &mut State, request: &proto::TotpCode) -> Reply {
        let id = convert::item_id(&request.item_id)?;
        let vault = self.vault(state)?;
        let code = vault.totp_code(id).map_err(vault_error)?;
        Ok(response::Body::TotpCode(proto::TotpCodeReply {
            code: code.as_str().to_owned(),
            seconds_remaining: code.seconds_remaining(),
        }))
    }

    /// Fails unless the vault has `domain`.
    fn require_domain(vault: &Vault, domain: DomainId) -> Result<(), proto::Error> {
        if vault.has_domain(domain).map_err(vault_error)? {
            Ok(())
        } else {
            Err(vault_error(VaultError::DomainUnavailable(domain)))
        }
    }

    /// Fails with `Locked` for the first domain of the vault that is not
    /// unlocked: some operations need all of them.
    pub(crate) fn require_every_domain(vault: &mut Vault) -> Result<(), proto::Error> {
        for domain in DomainId::ALL {
            if vault.has_domain(domain).map_err(vault_error)? && !vault.is_unlocked(domain) {
                return Err(locked(domain));
            }
        }
        Ok(())
    }

    fn create_recovery_kit(&self, state: &mut State, request: proto::CreateRecoveryKit) -> Reply {
        self.whole()?;
        let vault = self.vault(state)?;
        if vault.has_recovery_kit().map_err(vault_error)? && !request.replace {
            return Err(proto::Error::new(
                ErrorCode::RecoveryKitExists,
                "a recovery kit already exists; replacing it invalidates the old recovery key",
            ));
        }
        Self::require_every_domain(vault)?;
        let recovery_key = vault.create_recovery_kit().map_err(vault_error)?;
        Ok(response::Body::RecoveryKit(proto::RecoveryKit {
            recovery_key: recovery_key.to_code().as_str().to_owned(),
        }))
    }

    fn export_vault(&self, state: &mut State, request: &proto::ExportVault) -> Reply {
        self.whole()?;
        let params = zp_crypto::KdfParams::calibrate(std::time::Duration::from_millis(500))
            .map_err(|error| internal(error.to_string()))?;
        let vault = self.vault(state)?;
        let (data, summary) = vault
            .export_encrypted(&request.passphrase, &params)
            .map_err(export_error)?;
        Ok(response::Body::Exported(proto::Exported {
            data,
            counts: Some(counts(&summary)),
        }))
    }

    fn import_export(&self, state: &mut State, request: &proto::ImportExport) -> Reply {
        self.whole()?;
        let vault = self.vault(state)?;
        let summary = vault
            .import_encrypted(&request.data, &request.passphrase)
            .map_err(export_error)?;
        Ok(response::Body::ImportedItems(proto::ImportedItems {
            counts: Some(counts(&summary)),
        }))
    }

    fn list_devices(&self, state: &mut State) -> Reply {
        let vault = self.vault(state)?;
        let registry = vault.registry().map_err(vault_error)?;
        let vector = vault.version_vector().map_err(vault_error)?;
        let own = vault.device_id();
        let devices = registry
            .records()
            .map(|record| {
                let state = if registry.is_revoked(&record.device_id) {
                    proto::DeviceState::Revoked
                } else if record.device_id == own {
                    proto::DeviceState::ThisDevice
                } else {
                    proto::DeviceState::Active
                };
                proto::Device {
                    device_id: record.device_id.as_bytes().to_vec(),
                    name: record.name.clone(),
                    state: state as i32,
                    changes_held: vector.get(&record.device_id),
                }
            })
            .collect();
        Ok(response::Body::Devices(proto::Devices { devices }))
    }

    fn revoke_device(&self, state: &mut State, request: &proto::RevokeDevice) -> Reply {
        self.whole()?;
        let id = convert::device_id(&request.device_id)?;
        let vault = self.vault(state)?;
        Self::revocable(vault, id)?;
        Self::require_every_domain(vault)?;
        vault.revoke_device(id).map_err(vault_error)?;
        done()
    }

    /// Fails unless `id` is another device of the vault that is not revoked.
    fn revocable(vault: &Vault, id: zp_crypto::DeviceId) -> Result<(), proto::Error> {
        let not_found = |message: &str| proto::Error::new(ErrorCode::DeviceNotFound, message);
        let registry = vault.registry().map_err(vault_error)?;
        if id == vault.device_id() {
            return Err(vault_error(VaultError::CannotRevokeSelf));
        }
        if !registry.records().any(|record| record.device_id == id) {
            return Err(not_found("no device of this vault has that identifier"));
        }
        if registry.is_revoked(&id) {
            return Err(not_found("that device has already been revoked"));
        }
        Ok(())
    }

    fn dispatch(&self, state: &mut State, request: request::Body) -> Reply {
        use request::Body;
        match request {
            Body::Hello(_) => Err(bad_request("Hello was already sent")),
            Body::Status(_) => self.status(state).map(response::Body::Status),
            Body::CreateVault(request) => self.create_vault(state, &request),
            Body::RecoverVault(request) => self.recover_vault(state, &request),
            Body::Unlock(request) => self.unlock(state, &request),
            Body::Lock(request) => {
                let vault = self.vault(state)?;
                match request.domain {
                    Some(domain) => vault.lock(convert::domain_from_proto(domain)?),
                    None => vault.lock_all(),
                }
                done()
            }
            Body::ListItems(request) => self.list_items(state, &request),
            Body::GetItem(request) => self.get_item(state, &request),
            Body::AddItem(request) => self.add_item(state, request),
            Body::UpdateItem(request) => self.update_item(state, request),
            Body::DeleteItem(request) => self.delete_item(state, &request),
            Body::TotpCode(request) => self.totp_code(state, &request),
            Body::ChangeMasterPassword(request) => {
                let vault = self.vault(state)?;
                vault
                    .change_master_password(&request.current, &request.new, KdfChoice::default())
                    .map_err(vault_error)?;
                // What the old password unlocked does not stay open under the new one.
                vault.lock(DomainId::Password);
                done()
            }
            Body::CreateRecoveryKit(request) => self.create_recovery_kit(state, request),
            Body::ExportVault(request) => self.export_vault(state, &request),
            Body::ImportExport(request) => self.import_export(state, &request),
            Body::ListDevices(_) => self.list_devices(state),
            Body::RevokeDevice(request) => self.revoke_device(state, &request),
            Body::Shutdown(_) => {
                if let Some(vault) = state.vault.as_mut() {
                    vault.lock_all();
                }
                done()
            }
            Body::PairOffer(request) => self.pair_offer(state, &request),
            Body::BridgeFind(request) => crate::bridge::find(self.vault(state)?, &request),
            Body::BridgeFill(request) => crate::bridge::fill(self.vault(state)?, &request),
            Body::BridgeCompare(request) => crate::bridge::compare(self.vault(state)?, &request),
            Body::BridgeSave(request) => crate::bridge::save(self.vault(state)?, &request),
            Body::BridgeUpdate(request) => crate::bridge::update(self.vault(state)?, &request),
            Body::PasskeyCreate(request) => {
                self.holds(DomainId::Passkey)?;
                crate::passkey::create(self.vault(state)?, &request)
            }
            Body::PasskeyList(request) => {
                self.holds(DomainId::Passkey)?;
                crate::passkey::list(self.vault(state)?, &request)
            }
            Body::PasskeyGetAssertion(request) => {
                self.holds(DomainId::Passkey)?;
                crate::passkey::get_assertion(self.vault(state)?, &request)
            }
            // These start a relay and do not arrive here.
            Body::PairAdmit(_) | Body::PairJoin(_) => {
                Err(bad_request("this request needs a relay"))
            }
            // These belong to a relay that is already running.
            Body::RelayAttach(_)
            | Body::LinkData(_)
            | Body::PairConfirm(_)
            | Body::KeyAgentReply(_) => Err(bad_request("there is no relay on this connection")),
            // The key agent attaches to the process the clients talk to; the
            // sync daemon's requests are not this daemon's.
            Body::KeyAgentAttach(_)
            | Body::SyncdStatus(_)
            | Body::SyncNow(_)
            | Body::PairListen(_)
            | Body::PairConnect(_) => {
                Err(bad_request("that request is not one this process answers"))
            }
            request => crate::sync::handle(self.vault(state)?, request),
        }
    }
}

impl Service {
    /// Answers one request with what this process holds. Who may ask what
    /// is decided where the clients connect (`front`).
    pub(crate) fn serve(&self, request: request::Body) -> response::Body {
        let mut state = self.state();
        match self.dispatch(&mut state, request) {
            Ok(reply) => reply,
            Err(error) => response::Body::Error(error),
        }
    }

    /// Runs a relay request: pairing over the link the client relays.
    pub(crate) fn relay(&self, request: &request::Body, relay: RelayEnd) -> response::Body {
        let outcome = match request {
            request::Body::PairAdmit(_) => self.pair_admit(relay),
            request::Body::PairJoin(join) => self.pair_join(join, relay),
            _ => Err(bad_request("not a relay request")),
        };
        outcome.unwrap_or_else(response::Body::Error)
    }

    /// Whether `domain` is unlocked in this process.
    pub(crate) fn unlocked(&self, domain: DomainId) -> bool {
        self.state()
            .vault
            .as_mut()
            .is_some_and(|vault| vault.is_unlocked(domain))
    }

    /// Fails unless `device_id` names a device of the vault that can be
    /// revoked. Needs no key.
    pub(crate) fn check_revocable(&self, device_id: &[u8]) -> Result<(), proto::Error> {
        let id = convert::device_id(device_id)?;
        let mut state = self.state();
        Self::revocable(self.vault(&mut state)?, id)
    }

    /// Whether the vault has a recovery kit. Needs no key.
    pub(crate) fn has_recovery_kit(&self) -> Result<bool, proto::Error> {
        let mut state = self.state();
        self.vault(&mut state)?
            .has_recovery_kit()
            .map_err(vault_error)
    }
}

/// Lower-case names of the domains, for the start-up message.
pub(crate) fn domain_names() -> String {
    DomainId::ALL.map(domain_name).join(", ")
}
