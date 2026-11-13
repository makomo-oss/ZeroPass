//! The daemon's state and what it does with each request.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use zeroize::Zeroizing;
use zp_crypto::{
    Domain, DomainId, HardwareKeyError, HardwareKeyStore, InsecureSoftwareKeyStore, ItemId,
    Passkey, Password, RecoveryKey, Totp,
};
use zp_ipc::proto::{self, ErrorCode, Role, request, response};
use zp_ipc::{Handler, Peer, PeerProcess};
use zp_vault::model::Content;
use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError};

use crate::convert::{self, NewItem, bad_request, domain_name, locked, vault_error};

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

type Reply = Result<response::Body, proto::Error>;

fn done() -> Reply {
    Ok(response::Body::Done(proto::Done {}))
}

pub(crate) fn log(message: &str) {
    let _ = writeln!(io::stderr(), "zp-vaultd: {message}");
}

/// The one vault this daemon serves. `None` until the file exists and a request
/// needed it.
#[derive(Default)]
struct State {
    vault: Option<Vault>,
}

/// The vault daemon: owns the vault file and its keys.
pub(crate) struct Service {
    path: PathBuf,
    key_store: KeyStoreChoice,
    state: Mutex<State>,
}

impl Service {
    pub(crate) fn new(path: PathBuf, key_store: KeyStoreChoice) -> Self {
        Self {
            path,
            key_store,
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A panic in a request must not take the daemon's other clients with it.
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Locks the domains that have been idle for too long. Called periodically,
    /// so that keys do not stay in memory while nobody asks for anything.
    pub(crate) fn tick(&self) {
        if let Some(vault) = self.state().vault.as_mut() {
            vault.enforce_auto_lock();
        }
    }

    /// Wipes every key.
    pub(crate) fn lock_all(&self) {
        if let Some(vault) = self.state().vault.as_mut() {
            vault.lock_all();
        }
    }

    fn dev_key_path(&self) -> PathBuf {
        self.path.with_extension("devkey")
    }

    /// The key store for the TOTP and passkey domains; `None` if this device
    /// has none. With `create`, the store's key is created if it is missing.
    fn hardware(&self, create: bool) -> Result<Option<Box<dyn HardwareKeyStore>>, proto::Error> {
        let internal = |message: String| proto::Error::new(ErrorCode::Internal, message);
        match self.key_store {
            KeyStoreChoice::None => Ok(None),
            KeyStoreChoice::Platform => match zp_hwkey::platform_key_store(create) {
                Ok(store) => Ok(Some(store)),
                Err(HardwareKeyError::Unavailable(_)) => Ok(None),
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
                        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                        Err(error) => {
                            return Err(internal(format!("{}: {error}", path.display())));
                        }
                    };
                    let key: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        internal("the software key store file is malformed".to_owned())
                    })?;
                    InsecureSoftwareKeyStore::from_key_bytes(key)
                };
                Ok(Some(Box::new(store)))
            }
        }
    }

    /// The open vault, opening the file on first use.
    fn vault<'s>(&self, state: &'s mut State) -> Result<&'s mut Vault, proto::Error> {
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
            return Ok(proto::StatusReply::default());
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
        })
    }

    fn create_vault(&self, state: &mut State, request: &proto::CreateVault) -> Reply {
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
        let hardware = self.hardware(false)?.ok_or_else(|| {
            proto::Error::about(
                ErrorCode::HardwareUnavailable,
                convert::domain_to_proto(domain),
                "no hardware key store is available to unlock this domain",
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
    fn require_every_domain(vault: &mut Vault) -> Result<(), proto::Error> {
        for domain in DomainId::ALL {
            if vault.has_domain(domain).map_err(vault_error)? && !vault.is_unlocked(domain) {
                return Err(locked(domain));
            }
        }
        Ok(())
    }

    fn create_recovery_kit(&self, state: &mut State, request: proto::CreateRecoveryKit) -> Reply {
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
        let id = convert::device_id(&request.device_id)?;
        let vault = self.vault(state)?;
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
        Self::require_every_domain(vault)?;
        vault.revoke_device(id).map_err(vault_error)?;
        done()
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
            Body::ListDevices(_) => self.list_devices(state),
            Body::RevokeDevice(request) => self.revoke_device(state, &request),
            Body::Shutdown(_) => {
                if let Some(vault) = state.vault.as_mut() {
                    vault.lock_all();
                }
                done()
            }
        }
    }
}

/// Whether a connection with `role` may make `request` (`docs/spec/ipc.md` §5).
fn permitted(role: Role, request: &request::Body) -> bool {
    match role {
        Role::Ui => true,
        // What these roles may ask beyond the state of the vault is defined
        // together with the components themselves (P3-05, P4-04, P7-01).
        Role::Bridge | Role::Broker | Role::Sync => matches!(request, request::Body::Status(_)),
        Role::Unspecified => false,
    }
}

impl Handler for Service {
    fn handle(&self, peer: &Peer, request: request::Body) -> response::Body {
        if !permitted(peer.role, &request) {
            return response::Body::Error(proto::Error::new(
                ErrorCode::Denied,
                "this client is not allowed to make that request",
            ));
        }
        let mut state = self.state();
        match self.dispatch(&mut state, request) {
            Ok(reply) => reply,
            Err(error) => response::Body::Error(error),
        }
    }

    fn rejected(&self, process: &PeerProcess) {
        let who = process
            .executable
            .as_deref()
            .map_or_else(|| "an unidentified process".to_owned(), describe);
        log(&format!("refused a connection from {who}"));
    }
}

fn describe(path: &Path) -> String {
    path.display().to_string()
}

/// Lower-case names of the domains, for the start-up message.
pub(crate) fn domain_names() -> String {
    DomainId::ALL.map(domain_name).join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_ipc::proto::{Domain as D, new_item};

    const PASSWORD: &str = "correct horse battery staple";
    const TOTP_URI: &str =
        "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

    struct Fixture {
        service: Service,
        _dir: tempfile::TempDir,
    }

    fn fixture(key_store: KeyStoreChoice) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        Fixture {
            service: Service::new(dir.path().join("test.zpvault"), key_store),
            _dir: dir,
        }
    }

    fn peer(role: Role) -> Peer {
        Peer {
            process: PeerProcess {
                pid: None,
                executable: None,
            },
            role,
        }
    }

    impl Fixture {
        fn call_as(&self, role: Role, request: request::Body) -> Reply {
            match self.service.handle(&peer(role), request) {
                response::Body::Error(error) => Err(error),
                reply => Ok(reply),
            }
        }

        fn call(&self, request: request::Body) -> Reply {
            self.call_as(Role::Ui, request)
        }

        fn code(&self, request: request::Body) -> ErrorCode {
            let error = self.call(request).expect_err("an error");
            ErrorCode::try_from(error.code).unwrap()
        }

        fn create(&self) {
            self.call(request::Body::CreateVault(proto::CreateVault {
                master_password: PASSWORD.into(),
            }))
            .unwrap();
        }

        fn status(&self) -> proto::StatusReply {
            match self.call(request::Body::Status(proto::Status {})).unwrap() {
                response::Body::Status(status) => status,
                _ => panic!("not a status"),
            }
        }

        fn unlocked(&self, domain: D) -> bool {
            self.status()
                .domains
                .iter()
                .any(|status| status.domain == domain as i32 && status.unlocked)
        }

        fn lock(&self) {
            self.call(request::Body::Lock(proto::Lock { domain: None }))
                .unwrap();
        }

        fn unlock(&self, domain: D, password: &str) -> Reply {
            self.call(request::Body::Unlock(proto::Unlock {
                domain: domain as i32,
                master_password: password.into(),
            }))
        }

        fn add(&self, content: new_item::Content) -> Vec<u8> {
            let request = request::Body::AddItem(proto::AddItem {
                item: Some(proto::NewItem {
                    content: Some(content),
                }),
            });
            match self.call(request).unwrap() {
                response::Body::ItemAdded(added) => added.item_id,
                _ => panic!("not added"),
            }
        }

        fn list(&self, domain: D, query: &str) -> Vec<proto::ItemSummary> {
            let request = request::Body::ListItems(proto::ListItems {
                domain: domain as i32,
                query: query.into(),
            });
            match self.call(request).unwrap() {
                response::Body::Items(items) => items.items,
                _ => panic!("not a list"),
            }
        }
    }

    fn login(title: &str, password: &str) -> new_item::Content {
        new_item::Content::Login(proto::Login {
            title: title.into(),
            username: "alice".into(),
            password: password.into(),
            urls: vec!["https://example.com".into()],
            notes: String::new(),
        })
    }

    fn get(id: &[u8]) -> request::Body {
        request::Body::GetItem(proto::GetItem {
            item_id: id.to_vec(),
        })
    }

    #[test]
    fn a_vault_is_created_used_locked_and_unlocked() {
        let fixture = fixture(KeyStoreChoice::InsecureSoftware);
        assert!(!fixture.status().vault_exists);
        assert_eq!(fixture.code(get(&[0; 16])), ErrorCode::NoVault);

        fixture.create();
        let status = fixture.status();
        assert!(status.vault_exists);
        assert_eq!(status.vault_id.len(), 16);
        assert!(status.domains.iter().all(|d| d.available && d.unlocked));
        assert_eq!(
            fixture.code(request::Body::CreateVault(proto::CreateVault {
                master_password: PASSWORD.into(),
            })),
            ErrorCode::VaultExists
        );

        let bank = fixture.add(login("Bank", "hunter2-hunter2"));
        fixture.add(login("Airline", "another-password"));
        fixture.add(new_item::Content::Note(proto::Note {
            title: "Wi-Fi".into(),
            body: "the passphrase".into(),
        }));
        let titles: Vec<String> = fixture
            .list(D::Password, "")
            .into_iter()
            .map(|item| item.title)
            .collect();
        assert_eq!(titles, ["Airline", "Bank", "Wi-Fi"]);
        assert_eq!(fixture.list(D::Password, "bank").len(), 1);

        match fixture.call(get(&bank)).unwrap() {
            response::Body::Item(item) => match item.content {
                Some(proto::item::Content::Login(login)) => {
                    assert_eq!(login.password, "hunter2-hunter2");
                }
                _ => panic!("not a login"),
            },
            _ => panic!("not an item"),
        }

        // Locked: nothing can be read, and the error names the domain.
        fixture.lock();
        assert!(!fixture.unlocked(D::Password));
        let error = fixture.call(get(&bank)).err().unwrap();
        assert_eq!(error.code, ErrorCode::Locked as i32);
        assert_eq!(error.domain, Some(D::Password as i32));
        assert_eq!(
            fixture
                .unlock(D::Password, "not the password")
                .err()
                .unwrap()
                .code,
            ErrorCode::WrongPassword as i32
        );
        fixture.unlock(D::Password, PASSWORD).unwrap();
        assert!(fixture.unlocked(D::Password));
        // The password does not open the other domains.
        assert!(!fixture.unlocked(D::Totp));
        fixture.call(get(&bank)).unwrap();

        // Update and delete.
        fixture
            .call(request::Body::UpdateItem(proto::UpdateItem {
                item_id: bank.clone(),
                item: Some(proto::NewItem {
                    content: Some(login("Bank", "a-new-password")),
                }),
            }))
            .unwrap();
        fixture
            .call(request::Body::DeleteItem(proto::DeleteItem {
                item_id: bank.clone(),
            }))
            .unwrap();
        assert_eq!(fixture.code(get(&bank)), ErrorCode::ItemNotFound);
    }

    #[test]
    fn totp_codes_come_out_but_the_seed_does_not() {
        let fixture = fixture(KeyStoreChoice::InsecureSoftware);
        fixture.create();
        let id = fixture.add(new_item::Content::Totp(proto::NewTotp {
            otpauth_uri: TOTP_URI.into(),
            login_id: None,
        }));
        match fixture
            .call(request::Body::TotpCode(proto::TotpCode {
                item_id: id.clone(),
            }))
            .unwrap()
        {
            response::Body::TotpCode(code) => {
                assert_eq!(code.code.len(), 6);
                assert!((1..=30).contains(&code.seconds_remaining));
            }
            _ => panic!("not a code"),
        }
        match fixture.call(get(&id)).unwrap() {
            response::Body::Item(item) => {
                assert!(matches!(
                    item.content,
                    Some(proto::item::Content::Totp(ref info)) if info.issuer == "Example"
                ));
            }
            _ => panic!("not an item"),
        }
        assert_eq!(fixture.list(D::Totp, "").len(), 1);

        // After locking, the hardware-bound domain opens without the master
        // password (the software key store asks for nothing).
        fixture.lock();
        assert_eq!(
            fixture.code(request::Body::TotpCode(proto::TotpCode {
                item_id: id.clone()
            })),
            ErrorCode::Locked
        );
        fixture.unlock(D::Totp, "").unwrap();
        assert!(fixture.unlocked(D::Totp));
        assert!(!fixture.unlocked(D::Password));

        let bad = new_item::Content::Totp(proto::NewTotp {
            otpauth_uri: "not a uri".into(),
            login_id: None,
        });
        let request = request::Body::AddItem(proto::AddItem {
            item: Some(proto::NewItem { content: Some(bad) }),
        });
        assert_eq!(fixture.code(request), ErrorCode::InvalidInput);
    }

    #[test]
    fn without_a_key_store_the_hardware_domains_do_not_exist() {
        let fixture = fixture(KeyStoreChoice::None);
        fixture.create();
        let status = fixture.status();
        let available: Vec<bool> = status.domains.iter().map(|d| d.available).collect();
        assert_eq!(available, [true, false, false]);
        assert_eq!(
            fixture.unlock(D::Totp, "").err().unwrap().code,
            ErrorCode::DomainUnavailable as i32
        );
        let totp = new_item::Content::Totp(proto::NewTotp {
            otpauth_uri: TOTP_URI.into(),
            login_id: None,
        });
        let request = request::Body::AddItem(proto::AddItem {
            item: Some(proto::NewItem {
                content: Some(totp),
            }),
        });
        assert_eq!(fixture.code(request), ErrorCode::DomainUnavailable);
    }

    #[test]
    fn the_recovery_kit_needs_every_domain_and_restores_access() {
        let fixture = fixture(KeyStoreChoice::InsecureSoftware);
        fixture.create();
        let id = fixture.add(login("Bank", "hunter2-hunter2"));
        fixture.lock();
        fixture.unlock(D::Password, PASSWORD).unwrap();
        let kit = request::Body::CreateRecoveryKit(proto::CreateRecoveryKit { replace: false });
        let error = fixture.call(kit.clone()).err().unwrap();
        assert_eq!(error.code, ErrorCode::Locked as i32);
        assert_eq!(error.domain, Some(D::Totp as i32));
        fixture.unlock(D::Totp, "").unwrap();
        fixture.unlock(D::Passkey, "").unwrap();
        let recovery_key = match fixture.call(kit.clone()).unwrap() {
            response::Body::RecoveryKit(kit) => kit.recovery_key.clone(),
            _ => panic!("not a kit"),
        };
        assert!(fixture.status().has_recovery_kit);
        assert_eq!(fixture.code(kit), ErrorCode::RecoveryKitExists);

        let recover = |key: &str| {
            request::Body::RecoverVault(proto::RecoverVault {
                recovery_key: key.into(),
                new_master_password: "an entirely different passphrase".into(),
            })
        };
        assert_eq!(fixture.code(recover("garbage")), ErrorCode::InvalidInput);
        fixture.call(recover(&recovery_key)).unwrap();
        fixture.lock();
        assert_eq!(
            fixture.unlock(D::Password, PASSWORD).err().unwrap().code,
            ErrorCode::WrongPassword as i32
        );
        fixture
            .unlock(D::Password, "an entirely different passphrase")
            .unwrap();
        fixture.call(get(&id)).unwrap();
    }

    #[test]
    fn the_master_password_can_be_changed() {
        let fixture = fixture(KeyStoreChoice::None);
        fixture.create();
        let change = |current: &str| {
            request::Body::ChangeMasterPassword(proto::ChangeMasterPassword {
                current: current.into(),
                new: "an entirely different passphrase".into(),
            })
        };
        assert_eq!(fixture.code(change("wrong")), ErrorCode::WrongPassword);
        fixture.call(change(PASSWORD)).unwrap();
        fixture.lock();
        assert!(fixture.unlock(D::Password, PASSWORD).is_err());
        fixture
            .unlock(D::Password, "an entirely different passphrase")
            .unwrap();
        let weak = request::Body::ChangeMasterPassword(proto::ChangeMasterPassword {
            current: "an entirely different passphrase".into(),
            new: "short".into(),
        });
        assert_eq!(fixture.code(weak), ErrorCode::WeakPassword);
    }

    #[test]
    fn devices_are_listed_and_this_device_cannot_be_revoked() {
        let fixture = fixture(KeyStoreChoice::None);
        fixture.create();
        let devices = match fixture
            .call(request::Body::ListDevices(proto::ListDevices {}))
            .unwrap()
        {
            response::Body::Devices(devices) => devices.devices,
            _ => panic!("not devices"),
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].state, proto::DeviceState::ThisDevice as i32);
        assert_eq!(devices[0].device_id, fixture.status().device_id);
        let revoke =
            |id: Vec<u8>| request::Body::RevokeDevice(proto::RevokeDevice { device_id: id });
        assert_eq!(
            fixture.code(revoke(devices[0].device_id.clone())),
            ErrorCode::DeviceNotFound
        );
        let unknown = vec![9; devices[0].device_id.len()];
        assert_eq!(fixture.code(revoke(unknown)), ErrorCode::DeviceNotFound);
        assert_eq!(fixture.code(revoke(vec![1, 2, 3])), ErrorCode::BadRequest);
    }

    #[test]
    fn only_a_user_interface_may_do_more_than_ask_for_the_status() {
        let fixture = fixture(KeyStoreChoice::None);
        fixture.create();
        let id = fixture.add(login("Bank", "hunter2-hunter2"));
        for role in [Role::Bridge, Role::Broker, Role::Sync] {
            fixture
                .call_as(role, request::Body::Status(proto::Status {}))
                .unwrap();
            for request in [
                get(&id),
                request::Body::ListItems(proto::ListItems {
                    domain: D::Password as i32,
                    query: String::new(),
                }),
                request::Body::Lock(proto::Lock { domain: None }),
                request::Body::Shutdown(proto::Shutdown {}),
            ] {
                let error = fixture.call_as(role, request).err().unwrap();
                assert_eq!(error.code, ErrorCode::Denied as i32, "{role:?}");
            }
        }
        // Nothing was locked by the refused requests.
        assert!(fixture.unlocked(D::Password));
        assert!(
            fixture
                .call_as(Role::Unspecified, request::Body::Status(proto::Status {}))
                .is_err()
        );
    }

    #[test]
    fn shutdown_locks_everything() {
        let fixture = fixture(KeyStoreChoice::None);
        fixture.create();
        fixture
            .call(request::Body::Shutdown(proto::Shutdown {}))
            .unwrap();
        assert!(!fixture.unlocked(D::Password));
    }

    #[test]
    fn idle_domains_are_locked_by_the_tick() {
        let fixture = fixture(KeyStoreChoice::None);
        fixture.create();
        {
            let mut state = fixture.service.state();
            let vault = state.vault.as_mut().unwrap();
            vault.set_auto_lock(zp_vault::AutoLock {
                password: Some(std::time::Duration::ZERO),
                hardware: None,
            });
            // `set_auto_lock` applies the timeout at once; unlock again so that
            // the tick has something to do.
            vault.unlock_password(PASSWORD).unwrap();
        }
        fixture.service.tick();
        let state = fixture.service.state();
        assert!(format!("{:?}", state.vault).contains("unlocked: []"));
    }
}
