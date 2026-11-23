//! The app process's side of the vault (ADR-0012, `docs/spec/android.md` §2):
//! a client of the vault process, which also stores the vault file for it
//! (the image host) and answers for the hardware key store (the key agent).
//!
//! Nothing here opens the vault file with its keys: the file is read and
//! written as opaque bytes, and every request goes to the vault process.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use zeroize::Zeroizing;
use zp_crypto::seal_to;
use zp_ipc::proto::{
    self, IMAGE_CHUNK, KeyStoreProblem, key_agent_reply::Outcome, key_agent_request::Ask, new_item,
    request, response,
};
use zp_ipc::{Client, Uplink};

use crate::error::{Problem, ZpError};
use crate::link::LinkError;
use crate::{Domain, hex, parse_hex};

/// Opens a connection to the vault process.
pub(crate) type Connect = Arc<dyn Fn() -> Result<Client, ZpError> + Send + Sync>;

/// Opens connections to the vault process, implemented by the app: it makes a
/// socket pair, hands one end to the vault service through Binder
/// (`IVaultService.connect`) and returns the other.
#[uniffi::export(with_foreign)]
pub trait VaultConnector: Send + Sync {
    /// A new connection: this process's end of the socket pair, as a file
    /// descriptor that Rust then owns and closes.
    fn connect(&self) -> Result<i32, LinkError>;
}

/// Why the platform's key store could not answer.
///
/// The app raises it and Rust receives it, so it must not be a flat error.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HardwareError {
    /// This device cannot protect keys this way (no secure lock screen, no
    /// biometrics, no hardware-backed store).
    #[error("no hardware key store: {reason}")]
    Unavailable {
        /// Why, for the user.
        reason: String,
    },
    /// The user turned down or failed the prompt.
    #[error("the user did not confirm")]
    Cancelled,
    /// The store reported an error.
    #[error("the key store failed: {reason}")]
    Failed {
        /// What the store said.
        reason: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HardwareError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed {
            reason: error.reason,
        }
    }
}

/// The platform's hardware key store, as the key agent uses it
/// (`docs/spec/crypto.md` §7, `docs/spec/android.md` §3), implemented by the
/// app. Both calls may block while the user answers a prompt.
#[uniffi::export(with_foreign)]
pub trait PlatformKeyStore: Send + Sync {
    /// Whether this device has the store; with `create`, its key is made if it
    /// is missing. Returns the implementation identifier, the first byte of
    /// the key slots it protects.
    fn probe(&self, create: bool) -> Result<u8, HardwareError>;

    /// The deterministic keyed hash of `challenge` with the hardware key,
    /// after the user is verified for this one use.
    fn sign(&self, challenge: Vec<u8>) -> Result<Vec<u8>, HardwareError>;
}

/// The domains of the vault (`docs/spec/crypto.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct DomainState {
    /// Which domain.
    pub domain: Domain,
    /// Whether this device has it.
    pub available: bool,
    /// Whether it is unlocked now.
    pub unlocked: bool,
    /// Whether another device has it while this one does not (ADR-0011).
    pub elsewhere: bool,
}

/// The state of the vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultStatus {
    /// Whether there is a vault on this device.
    pub exists: bool,
    /// The vault's identifier (hexadecimal); empty without a vault.
    pub vault_id: String,
    /// This device's identifier (hexadecimal); empty without a vault.
    pub device_id: String,
    /// The domains.
    pub domains: Vec<DomainState>,
    /// Whether a recovery kit was made.
    pub has_recovery_kit: bool,
}

impl VaultStatus {
    fn from_proto(reply: proto::StatusReply) -> Self {
        Self {
            exists: reply.vault_exists,
            vault_id: hex(&reply.vault_id),
            device_id: hex(&reply.device_id),
            domains: reply
                .domains
                .iter()
                .filter_map(|state| {
                    Some(DomainState {
                        domain: Domain::from_proto(state.domain)?,
                        available: state.available,
                        unlocked: state.unlocked,
                        elsewhere: state.elsewhere,
                    })
                })
                .collect(),
            has_recovery_kit: reply.has_recovery_kit,
        }
    }
}

/// What an item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ItemKind {
    /// A login.
    Login,
    /// A secure note.
    Note,
    /// A TOTP entry.
    Totp,
    /// A passkey.
    Passkey,
}

/// An item as shown in a list: no secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemSummary {
    /// The item's identifier (hexadecimal).
    pub id: String,
    /// What it is.
    pub kind: ItemKind,
    /// Its title (for a passkey, the site).
    pub title: String,
    /// The user name or account.
    pub username: String,
    /// The addresses of a login.
    pub urls: Vec<String>,
}

/// The items of a domain.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemList {
    /// The items this device can open.
    pub items: Vec<ItemSummary>,
    /// How many items this device has no keys for (ADR-0011).
    pub unreadable: u32,
}

/// What an item holds, as far as the app may see it (`docs/spec/ipc.md` §6):
/// never a TOTP seed or a private key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ItemContent {
    /// A login, with its password.
    Login {
        /// The title.
        title: String,
        /// The user name.
        username: String,
        /// The password.
        password: String,
        /// The addresses it is for.
        urls: Vec<String>,
        /// Free text.
        notes: String,
    },
    /// A secure note.
    Note {
        /// The title.
        title: String,
        /// The text.
        body: String,
    },
    /// A TOTP entry, without its seed.
    Totp {
        /// Who issued it.
        issuer: String,
        /// The account.
        account: String,
        /// How many digits a code has.
        digits: u32,
        /// How many seconds a code lasts.
        period: u32,
        /// The login it belongs to, if any.
        login_id: Option<String>,
    },
    /// A passkey, without its private key.
    Passkey {
        /// The site.
        rp_id: String,
        /// The account at the site.
        user_name: String,
    },
}

/// A one-time code.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpCode {
    /// The code.
    pub code: String,
    /// How long it is valid.
    pub seconds_remaining: u32,
}

/// What a device of the vault is to this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceState {
    /// This device.
    ThisDevice,
    /// Another device that syncs.
    Active,
    /// A revoked device.
    Revoked,
}

/// A device of the vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceInfo {
    /// Its identifier (hexadecimal).
    pub id: String,
    /// Its name.
    pub name: String,
    /// What it is to this device.
    pub state: DeviceState,
    /// How many changes written by it this device holds.
    pub changes_held: u64,
}

pub(crate) type SharedUplink = Arc<Mutex<Option<Uplink>>>;

pub(crate) fn send_up(uplink: &SharedUplink, body: request::Body) -> bool {
    uplink
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .as_mut()
        .is_some_and(|uplink| uplink.send(body).is_ok())
}

pub(crate) fn close_up(uplink: &SharedUplink) {
    uplink
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .take();
}

/// Starts the relay `request` on two new connections. Returns its downlink
/// and uplink.
pub(crate) fn relay(
    connect: &Connect,
    request: request::Body,
) -> Result<(zp_ipc::Downlink, SharedUplink), ZpError> {
    let (id, mut downlink) = connect()?.start_relay(request)?;
    match connect()?.attach_relay(id) {
        Ok(uplink) => Ok((downlink, Arc::new(Mutex::new(Some(uplink))))),
        // The vault process ended the relay at once; why is on the downlink.
        Err(attach) => Err(match downlink.receive() {
            Err(reason) => reason.into(),
            Ok(_) => attach.into(),
        }),
    }
}

/// Writes `bytes` to `path` so that a crash leaves either the old file or the
/// new one (`docs/spec/android.md` §2.1).
pub(crate) fn store_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?
        .to_os_string();
    name.push(".tmp");
    let temporary = path.with_file_name(name);
    {
        let mut file = File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    // The rename itself reaches the disk with the directory.
    #[cfg(unix)]
    if let Some(directory) = path.parent() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

/// Attaches the image host: gives the vault process the stored file and
/// stores every new image of it.
fn attach_image_host(connect: &Connect, path: &Path) -> Result<SharedUplink, ZpError> {
    let image = match fs::read(path) {
        Ok(image) => image,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            return Err(ZpError::failed(format!(
                "the vault file cannot be read: {error}"
            )));
        }
    };
    let (mut downlink, uplink) = relay(
        connect,
        request::Body::ImageHostAttach(proto::ImageHostAttach {}),
    )?;
    let mut chunks = image.chunks(IMAGE_CHUNK).peekable();
    if chunks.peek().is_none() {
        send_up(
            &uplink,
            request::Body::ImageChunk(proto::ImageChunk {
                data: Vec::new(),
                last: true,
            }),
        );
    }
    while let Some(data) = chunks.next() {
        let chunk = proto::ImageChunk {
            data: data.to_vec(),
            last: chunks.peek().is_none(),
        };
        if !send_up(&uplink, request::Body::ImageChunk(chunk)) {
            break;
        }
    }
    drop(image);
    match downlink.receive()? {
        response::Body::Listening(_) => {}
        _ => return Err(ZpError::failed("the vault process did not open the vault")),
    }

    let path = path.to_path_buf();
    let up = Arc::clone(&uplink);
    thread::spawn(move || {
        let mut image = Vec::new();
        while let Ok(response::Body::ImageChunk(chunk)) = downlink.receive() {
            image.extend_from_slice(&chunk.data);
            if !chunk.last {
                continue;
            }
            let error = match store_atomically(&path, &image) {
                Ok(()) => String::new(),
                Err(error) => error.to_string(),
            };
            image.clear();
            if !send_up(
                &up,
                request::Body::ImageStored(proto::ImageStored { error }),
            ) {
                break;
            }
        }
    });
    Ok(uplink)
}

fn failure(problem: KeyStoreProblem, message: impl Into<String>) -> Outcome {
    Outcome::Failed(proto::KeyStoreFailure {
        problem: problem as i32,
        message: message.into(),
    })
}

/// The key agent's answer (`docs/spec/ipc.md` §13.2): the signature goes back
/// sealed to the key the vault process gave, never in the clear.
pub(crate) fn answer(store: &dyn PlatformKeyStore, ask: Ask) -> Outcome {
    let failed = |error: HardwareError| match error {
        HardwareError::Unavailable { reason } => failure(KeyStoreProblem::Unavailable, reason),
        HardwareError::Cancelled => {
            failure(KeyStoreProblem::UserCancelled, "the user did not confirm")
        }
        HardwareError::Failed { reason } => failure(KeyStoreProblem::Platform, reason),
    };
    match ask {
        Ask::Probe(probe) => match store.probe(probe.create) {
            Ok(id) => Outcome::Available(proto::KeyStoreAvailable {
                implementation_id: u32::from(id),
            }),
            Err(error) => failed(error),
        },
        Ask::Sign(sign) => {
            // Only what wraps a vault key: a 32-byte challenge.
            if sign.challenge.len() != 32 {
                return failure(KeyStoreProblem::Platform, "not a challenge");
            }
            let Ok(reply_key) = <[u8; 32]>::try_from(sign.reply_key.as_slice()) else {
                return failure(KeyStoreProblem::Platform, "not a reply key");
            };
            match store.sign(sign.challenge.clone()) {
                Ok(signature) => {
                    let signature = Zeroizing::new(signature);
                    if signature.is_empty() {
                        return failure(KeyStoreProblem::Platform, "an empty signature");
                    }
                    match seal_to(&reply_key, &sign.challenge, &signature) {
                        Ok(sealed) => Outcome::Signature(sealed),
                        Err(error) => failure(KeyStoreProblem::Platform, error.to_string()),
                    }
                }
                Err(error) => failed(error),
            }
        }
    }
}

/// Attaches the key agent: answers the vault process's questions with the
/// platform's key store.
fn attach_key_agent(
    connect: &Connect,
    store: Arc<dyn PlatformKeyStore>,
) -> Result<SharedUplink, ZpError> {
    let (mut downlink, uplink) = relay(
        connect,
        request::Body::KeyAgentAttach(proto::KeyAgentAttach {}),
    )?;
    match downlink.receive()? {
        response::Body::Listening(_) => {}
        _ => {
            return Err(ZpError::failed(
                "the vault process did not take the key agent",
            ));
        }
    }
    let up = Arc::clone(&uplink);
    thread::spawn(move || {
        while let Ok(response::Body::KeyAgentRequest(question)) = downlink.receive() {
            let Some(ask) = question.ask else { continue };
            let reply = proto::KeyAgentReply {
                id: question.id,
                outcome: Some(answer(store.as_ref(), ask)),
            };
            if !send_up(&up, request::Body::KeyAgentReply(reply)) {
                break;
            }
        }
    });
    Ok(uplink)
}

/// The vault, from the app process.
#[derive(uniffi::Object)]
pub struct VaultClient {
    pub(crate) connect: Connect,
    host: SharedUplink,
    agent: Option<SharedUplink>,
}

impl core::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultClient").finish_non_exhaustive()
    }
}

impl Drop for VaultClient {
    /// Closes the relays: the vault process closes the vault and wipes its keys.
    fn drop(&mut self) {
        close_up(&self.host);
        if let Some(agent) = &self.agent {
            close_up(agent);
        }
    }
}

fn domain_value(domain: Domain) -> i32 {
    domain.to_proto() as i32
}

fn item_id(id: &str) -> Result<Vec<u8>, ZpError> {
    parse_hex::<16>(id)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| ZpError::new(Problem::InvalidInput, "malformed item identifier"))
}

fn unexpected() -> ZpError {
    ZpError::failed("the vault process gave an unexpected answer")
}

impl VaultClient {
    /// The client of the vault process that `connect` reaches, with the vault
    /// file at `vault_file`, and `key_store` for the TOTP and passkey domains
    /// (without one, they cannot be made or opened on this device).
    pub(crate) fn with(
        connect: Connect,
        vault_file: PathBuf,
        key_store: Option<Arc<dyn PlatformKeyStore>>,
    ) -> Result<Self, ZpError> {
        let host = attach_image_host(&connect, &vault_file)?;
        let agent = match key_store {
            Some(store) => match attach_key_agent(&connect, store) {
                Ok(agent) => Some(agent),
                Err(error) => {
                    close_up(&host);
                    return Err(error);
                }
            },
            None => None,
        };
        Ok(Self {
            connect,
            host,
            agent,
        })
    }

    pub(crate) fn call(&self, body: request::Body) -> Result<response::Body, ZpError> {
        Ok((self.connect)()?.call(body)?)
    }

    fn done(&self, body: request::Body) -> Result<(), ZpError> {
        self.call(body).map(drop)
    }

    fn add(&self, content: new_item::Content) -> Result<String, ZpError> {
        match self.call(request::Body::AddItem(proto::AddItem {
            item: Some(proto::NewItem {
                content: Some(content),
            }),
        }))? {
            response::Body::ItemAdded(added) => Ok(hex(&added.item_id)),
            _ => Err(unexpected()),
        }
    }

    fn update(&self, id: &str, content: new_item::Content) -> Result<(), ZpError> {
        self.done(request::Body::UpdateItem(proto::UpdateItem {
            item_id: item_id(id)?,
            item: Some(proto::NewItem {
                content: Some(content),
            }),
        }))
    }

    fn status_of(reply: response::Body) -> Result<VaultStatus, ZpError> {
        match reply {
            response::Body::Status(status) => Ok(VaultStatus::from_proto(status)),
            _ => Err(unexpected()),
        }
    }
}

#[uniffi::export]
impl VaultClient {
    /// Connects to the vault process through `connector`, gives it the vault
    /// file at `vault_file` (if there is one) and stores what changes there.
    /// `key_store` answers for the TOTP and passkey domains; without one, this
    /// device has neither.
    #[uniffi::constructor]
    pub fn open(
        connector: Arc<dyn VaultConnector>,
        vault_file: String,
        key_store: Option<Arc<dyn PlatformKeyStore>>,
    ) -> Result<Arc<Self>, ZpError> {
        let connect: Connect = Arc::new(move || crate::engine::connect_with(connector.as_ref()));
        Ok(Arc::new(Self::with(
            connect,
            PathBuf::from(vault_file),
            key_store,
        )?))
    }

    /// The state of the vault.
    pub fn status(&self) -> Result<VaultStatus, ZpError> {
        Self::status_of(self.call(request::Body::Status(proto::Status {}))?)
    }

    /// Creates the vault, protected by `master_password`. Unless
    /// `without_hardware`, it fails with `HardwareUnavailable` if the key
    /// store cannot be used, rather than making a vault without the TOTP and
    /// passkey domains (ADR-0011).
    pub fn create(
        &self,
        master_password: String,
        without_hardware: bool,
    ) -> Result<VaultStatus, ZpError> {
        Self::status_of(self.call(request::Body::CreateVault(proto::CreateVault {
            master_password,
            without_hardware,
        }))?)
    }

    /// Unlocks the password domain.
    pub fn unlock_password(&self, master_password: String) -> Result<(), ZpError> {
        self.done(request::Body::Unlock(proto::Unlock {
            domain: domain_value(Domain::Password),
            master_password,
        }))
    }

    /// Unlocks the TOTP or passkey domain: the key store verifies the user.
    pub fn unlock(&self, domain: Domain) -> Result<(), ZpError> {
        self.done(request::Body::Unlock(proto::Unlock {
            domain: domain_value(domain),
            master_password: String::new(),
        }))
    }

    /// Locks one domain, or all of them.
    pub fn lock(&self, domain: Option<Domain>) -> Result<(), ZpError> {
        self.done(request::Body::Lock(proto::Lock {
            domain: domain.map(domain_value),
        }))
    }

    /// The items of `domain` that match `query` (all if it is empty), without
    /// secrets.
    pub fn list(&self, domain: Domain, query: String) -> Result<ItemList, ZpError> {
        let response::Body::Items(items) =
            self.call(request::Body::ListItems(proto::ListItems {
                domain: domain_value(domain),
                query,
            }))?
        else {
            return Err(unexpected());
        };
        Ok(ItemList {
            items: items
                .items
                .into_iter()
                .map(|item| ItemSummary {
                    id: hex(&item.item_id),
                    kind: match proto::ItemKind::try_from(item.kind) {
                        Ok(proto::ItemKind::Note) => ItemKind::Note,
                        Ok(proto::ItemKind::Totp) => ItemKind::Totp,
                        Ok(proto::ItemKind::Passkey) => ItemKind::Passkey,
                        _ => ItemKind::Login,
                    },
                    title: item.title,
                    username: item.username,
                    urls: item.urls,
                })
                .collect(),
            unreadable: items.unreadable,
        })
    }

    /// One item.
    pub fn get(&self, id: String) -> Result<ItemContent, ZpError> {
        let response::Body::Item(item) = self.call(request::Body::GetItem(proto::GetItem {
            item_id: item_id(&id)?,
        }))?
        else {
            return Err(unexpected());
        };
        use proto::item::Content;
        Ok(match item.content.ok_or_else(unexpected)? {
            Content::Login(login) => ItemContent::Login {
                title: login.title.clone(),
                username: login.username.clone(),
                password: login.password.clone(),
                urls: login.urls.clone(),
                notes: login.notes.clone(),
            },
            Content::Note(note) => ItemContent::Note {
                title: note.title.clone(),
                body: note.body.clone(),
            },
            Content::Totp(totp) => ItemContent::Totp {
                issuer: totp.issuer,
                account: totp.account,
                digits: totp.digits,
                period: totp.period,
                login_id: totp.login_id.as_deref().map(hex),
            },
            Content::Passkey(passkey) => ItemContent::Passkey {
                rp_id: passkey.rp_id,
                user_name: passkey.user_name,
            },
        })
    }

    /// Stores a new login and returns its identifier.
    pub fn add_login(
        &self,
        title: String,
        username: String,
        password: String,
        urls: Vec<String>,
        notes: String,
    ) -> Result<String, ZpError> {
        self.add(new_item::Content::Login(proto::Login {
            title,
            username,
            password,
            urls,
            notes,
        }))
    }

    /// Replaces a login.
    pub fn update_login(
        &self,
        id: String,
        title: String,
        username: String,
        password: String,
        urls: Vec<String>,
        notes: String,
    ) -> Result<(), ZpError> {
        self.update(
            &id,
            new_item::Content::Login(proto::Login {
                title,
                username,
                password,
                urls,
                notes,
            }),
        )
    }

    /// Stores a new secure note and returns its identifier.
    pub fn add_note(&self, title: String, body: String) -> Result<String, ZpError> {
        self.add(new_item::Content::Note(proto::Note { title, body }))
    }

    /// Replaces a secure note.
    pub fn update_note(&self, id: String, title: String, body: String) -> Result<(), ZpError> {
        self.update(&id, new_item::Content::Note(proto::Note { title, body }))
    }

    /// Stores a TOTP entry from an `otpauth://` URI or a Base32 secret, tied to
    /// the login `login_id` if given. The TOTP domain must be unlocked.
    pub fn add_totp(
        &self,
        otpauth_uri: String,
        login_id: Option<String>,
    ) -> Result<String, ZpError> {
        let login_id = login_id.as_deref().map(item_id).transpose()?;
        self.add(new_item::Content::Totp(proto::NewTotp {
            otpauth_uri,
            login_id,
        }))
    }

    /// Deletes an item.
    pub fn delete(&self, id: String) -> Result<(), ZpError> {
        self.done(request::Body::DeleteItem(proto::DeleteItem {
            item_id: item_id(&id)?,
        }))
    }

    /// The current code of a TOTP entry. The TOTP domain must be unlocked.
    pub fn totp_code(&self, id: String) -> Result<TotpCode, ZpError> {
        match self.call(request::Body::TotpCode(proto::TotpCode {
            item_id: item_id(&id)?,
        }))? {
            response::Body::TotpCode(code) => Ok(TotpCode {
                code: code.code.clone(),
                seconds_remaining: code.seconds_remaining,
            }),
            _ => Err(unexpected()),
        }
    }

    /// The devices of the vault.
    pub fn devices(&self) -> Result<Vec<DeviceInfo>, ZpError> {
        let response::Body::Devices(devices) =
            self.call(request::Body::ListDevices(proto::ListDevices {}))?
        else {
            return Err(unexpected());
        };
        Ok(devices
            .devices
            .into_iter()
            .map(|device| DeviceInfo {
                id: hex(&device.device_id),
                name: device.name,
                state: match proto::DeviceState::try_from(device.state) {
                    Ok(proto::DeviceState::ThisDevice) => DeviceState::ThisDevice,
                    Ok(proto::DeviceState::Revoked) => DeviceState::Revoked,
                    _ => DeviceState::Active,
                },
                changes_held: device.changes_held,
            })
            .collect())
    }

    /// Revokes a device and replaces the vault keys. Every domain must be
    /// unlocked. Refuses with `KeysAtRisk` unless `even_without_keys` when this
    /// device lacks a domain another device has (ADR-0011).
    pub fn revoke(&self, device_id: String, even_without_keys: bool) -> Result<(), ZpError> {
        let device_id = parse_hex::<16>(&device_id)
            .ok_or_else(|| ZpError::new(Problem::InvalidInput, "malformed device identifier"))?;
        self.done(request::Body::RevokeDevice(proto::RevokeDevice {
            device_id: device_id.to_vec(),
            even_without_keys,
        }))
    }

    /// Makes a recovery kit and returns its recovery key, once. Every domain
    /// must be unlocked.
    pub fn create_recovery_kit(&self, replace: bool) -> Result<String, ZpError> {
        match self.call(request::Body::CreateRecoveryKit(proto::CreateRecoveryKit {
            replace,
        }))? {
            response::Body::RecoveryKit(kit) => Ok(kit.recovery_key.clone()),
            _ => Err(unexpected()),
        }
    }

    /// Changes the master password. The password domain is locked afterwards.
    pub fn change_master_password(&self, current: String, new: String) -> Result<(), ZpError> {
        self.done(request::Body::ChangeMasterPassword(
            proto::ChangeMasterPassword { current, new },
        ))
    }

    /// Makes the TOTP or passkey domain on this device, for a vault that has it
    /// nowhere (ADR-0011). The password domain must be unlocked.
    pub fn set_up_domain(&self, domain: Domain) -> Result<VaultStatus, ZpError> {
        Self::status_of(self.call(request::Body::SetUpDomain(proto::SetUpDomain {
            domain: domain_value(domain),
        }))?)
    }
}
