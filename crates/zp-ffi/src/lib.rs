//! UniFFI bindings exposing the ZeroPass core to mobile apps.
//!
//! The app owns the radio: it scans, connects and moves bytes (Bluetooth LE on
//! Android and iOS). Everything else stays here, in the same code the desktop
//! runs: pairing, the Noise channel, sync and the vault. The seam between the
//! two is [`ByteLink`], a byte stream the app implements.
//!
//! Every function blocks until it is done; call them off the UI thread.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zp_crypto::{DeviceId, ItemId, Password};
use zp_pairing::{Joiner, OfferRole, PairingOffer};
use zp_sync::SessionReport;
use zp_transport::ble::{self, parse_tag_value};
use zp_transport::discovery::identify;
use zp_transport::{
    DriveConfig, LanTransport, Link, NewVault, PairingLink, Transport, pair_as_new,
    sync_as_initiator,
};
use zp_vault::model::{Content, Login};
use zp_vault::{CreateOptions, Store, Vault};

uniffi::setup_scaffolding!();

/// How often a blocked reader gives the driver a chance to notice that the
/// connection was dropped.
const READ_POLL_MS: u32 = 200;
/// How long the other side may stay silent while pairing: its user has to read
/// the name of this device and confirm.
const PAIRING_IDLE: Duration = Duration::from_secs(90);

/// Why a call failed. The message is meant for the user.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    /// The master password is wrong.
    #[error("wrong master password")]
    WrongPassword,
    /// The vault (or the domain) is locked.
    #[error("the vault is locked")]
    Locked,
    /// The pairing code is malformed, expired or of the wrong kind.
    #[error("the pairing code cannot be used: {0}")]
    BadCode(String),
    /// Anything else.
    #[error("{0}")]
    Failed(String),
}

impl From<zp_vault::VaultError> for FfiError {
    fn from(error: zp_vault::VaultError) -> Self {
        match error {
            zp_vault::VaultError::WrongPassword => Self::WrongPassword,
            zp_vault::VaultError::Locked(_) => Self::Locked,
            other => Self::Failed(other.to_string()),
        }
    }
}

fn failed(error: impl core::fmt::Display) -> FfiError {
    FfiError::Failed(error.to_string())
}

/// Why a [`ByteLink`] call failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum LinkError {
    /// The connection is gone.
    #[error("the link is closed")]
    Closed,
    /// The app's implementation threw something unexpected.
    #[error("the link failed: {0}")]
    Unexpected(String),
}

impl From<uniffi::UnexpectedUniFFICallbackError> for LinkError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unexpected(error.reason)
    }
}

/// A reliable, ordered byte stream to one nearby device, implemented by the app
/// on top of its radio (`docs/spec/ble.md` §5). Only ciphertext passes through.
#[uniffi::export(with_foreign)]
pub trait ByteLink: Send + Sync {
    /// The next bytes from the other device, in order. Returns an empty array if
    /// nothing arrived within `timeout_ms`, and fails once the link is closed.
    fn read(&self, timeout_ms: u32) -> Result<Vec<u8>, LinkError>;

    /// Sends `bytes`, returning when the radio has taken them.
    fn write(&self, bytes: Vec<u8>) -> Result<(), LinkError>;
}

struct AppLink(Arc<dyn ByteLink>);

struct AppReader {
    link: Arc<dyn ByteLink>,
    pending: Vec<u8>,
}

struct AppWriter(Arc<dyn ByteLink>);

impl Read for AppReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            match self.link.read(READ_POLL_MS) {
                Ok(bytes) if bytes.is_empty() => return Err(io::ErrorKind::TimedOut.into()),
                Ok(bytes) => self.pending = bytes,
                // End of stream.
                Err(_) => return Ok(0),
            }
        }
        let count = buffer.len().min(self.pending.len());
        buffer[..count].copy_from_slice(&self.pending[..count]);
        self.pending.drain(..count);
        Ok(count)
    }
}

impl Write for AppWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .write(bytes.to_vec())
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Link for AppLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let reader = AppReader {
            link: Arc::clone(&self.0),
            pending: Vec::new(),
        };
        Ok((Box::new(reader), Box::new(AppWriter(self.0))))
    }

    fn peer(&self) -> String {
        "app link".to_owned()
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The identifiers of the Bluetooth LE service (`docs/spec/ble.md` §3), as
/// UUID strings.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BleUuids {
    /// The service to scan for.
    pub service: String,
    /// The `Tag` characteristic (read).
    pub tag: String,
    /// The `Rx` characteristic (write, phone to desktop).
    pub rx: String,
    /// The `Tx` characteristic (notify, desktop to phone).
    pub tx: String,
}

fn uuid(value: u128) -> String {
    let text = format!("{value:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    )
}

/// The Bluetooth LE identifiers the app needs.
#[uniffi::export]
pub fn ble_uuids() -> BleUuids {
    BleUuids {
        service: uuid(ble::SERVICE_UUID),
        tag: uuid(ble::TAG_UUID),
        rx: uuid(ble::RX_UUID),
        tx: uuid(ble::TX_UUID),
    }
}

/// What a scanned pairing code says, as far as the app needs to know.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferInfo {
    /// The device showing the code announces this tag in the second half of its
    /// `Tag` characteristic: connect to the one that does.
    pub pairing_tag: Vec<u8>,
    /// When the code stops working, in seconds since the Unix epoch.
    pub expires_at_secs: u64,
}

fn parse_offer(code: &str) -> Result<PairingOffer, FfiError> {
    let offer = PairingOffer::parse(code.trim(), unix_secs())
        .map_err(|error| FfiError::BadCode(error.to_string()))?;
    if offer.role != OfferRole::Existing {
        return Err(FfiError::BadCode(
            "it was not created by a device that is already in a vault".to_owned(),
        ));
    }
    Ok(offer)
}

/// Checks a scanned pairing code and tells the app which device to connect to.
#[uniffi::export]
pub fn offer_info(code: String) -> Result<OfferInfo, FfiError> {
    let offer = parse_offer(&code)?;
    Ok(OfferInfo {
        pairing_tag: ble::pairing_tag(&offer.psk).to_vec(),
        expires_at_secs: offer.expires_at,
    })
}

/// Whether the value of a `Tag` characteristic announces the pairing offer
/// with `pairing_tag` (from [`offer_info`]).
#[uniffi::export]
pub fn announces_pairing(tag_value: Vec<u8>, pairing_tag: Vec<u8>) -> bool {
    matches!(parse_tag_value(&tag_value), Some((_, Some(tag))) if tag[..] == pairing_tag[..])
}

/// What a sync session moved.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncOutcome {
    /// Changes sent to the other device.
    pub sent: u64,
    /// Changes received and stored.
    pub received: u64,
}

impl From<&SessionReport> for SyncOutcome {
    fn from(report: &SessionReport) -> Self {
        Self {
            sent: report.sent as u64,
            received: report.received.applied as u64,
        }
    }
}

/// What joining a vault achieved.
#[derive(Debug, Clone, uniffi::Record)]
pub struct JoinOutcome {
    /// The vault that was joined.
    pub vault_id: String,
    /// The identifier of this device in it.
    pub device_id: String,
    /// The first sync, if it completed.
    pub first_sync: Option<SyncOutcome>,
    /// Why the first sync did not complete, if it did not. The vault file is
    /// valid either way and catches up at the next sync.
    pub first_sync_error: Option<String>,
}

/// Joins the vault of the device that shows `code`, over `link` to that device,
/// and creates this device's vault file at `path`, protected by
/// `master_password` (this device's own).
///
/// The other device asks its user to confirm `device_name` before it hands
/// anything over. This device has no hardware key store yet (PoC), so the TOTP
/// and passkey domains sync as ciphertext it cannot open.
#[uniffi::export]
pub fn join_vault(
    path: String,
    master_password: String,
    device_name: String,
    code: String,
    link: Arc<dyn ByteLink>,
) -> Result<JoinOutcome, FfiError> {
    let offer = parse_offer(&code)?;
    let pairing = PairingLink {
        scanned: true,
        psk: &offer.psk,
        offered_key: Some(offer.noise_pk),
    };
    let new_vault = NewVault {
        path: Path::new(&path),
        master_password: &master_password,
        hardware: None,
        options: CreateOptions {
            device_name: Some(device_name.clone()),
            ..CreateOptions::default()
        },
    };
    let config = DriveConfig {
        idle_timeout: PAIRING_IDLE,
    };
    let joined = pair_as_new(
        Box::new(AppLink(link)),
        Joiner::new(&device_name).map_err(failed)?,
        &pairing,
        new_vault,
        &config,
    )
    .map_err(failed)?;
    Ok(JoinOutcome {
        vault_id: joined.vault.vault_id().to_string(),
        device_id: joined.vault.device_id().to_string(),
        first_sync: joined.sync.as_ref().ok().map(Into::into),
        first_sync_error: joined.sync.err(),
    })
}

/// A device of this vault that was recognised nearby.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Peer {
    /// Its identifier.
    pub device_id: String,
    /// Its name.
    pub name: String,
}

/// Tells whether the value of a `Tag` characteristic belongs to another device
/// of the vault at `path`, and to which. Needs no password.
#[uniffi::export]
pub fn recognise_peer(path: String, tag_value: Vec<u8>) -> Result<Option<Peer>, FfiError> {
    let Some((Some(tag), _)) = parse_tag_value(&tag_value) else {
        return Ok(None);
    };
    let store = Store::open(Path::new(&path))?;
    let registry = store.registry()?;
    Ok(identify(&registry, &tag, unix_secs())
        .filter(|record| record.device_id != store.device_id())
        .map(|record| Peer {
            device_id: record.device_id.to_string(),
            name: record.name.clone(),
        }))
}

fn parse_id<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.trim();
    if text.len() != 2 * N || !text.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).ok()?;
    }
    Some(bytes)
}

/// Syncs the vault file at `path` with the device `peer_device_id` (from
/// [`recognise_peer`]) over `link` to it. Works on the locked file: no password
/// is needed, and only ciphertext and signatures are handled.
#[uniffi::export]
pub fn sync_with(
    path: String,
    peer_device_id: String,
    link: Arc<dyn ByteLink>,
) -> Result<SyncOutcome, FfiError> {
    let peer = parse_id(&peer_device_id)
        .map(DeviceId::from_bytes)
        .ok_or_else(|| failed("malformed device identifier"))?;
    let mut store = Store::open(Path::new(&path))?;
    let registry = store.registry()?;
    let remote = registry
        .get(&peer)
        .filter(|_| registry.is_active(&peer))
        .ok_or_else(|| failed("that device is not an active member of this vault"))?
        .noise_pk;
    let key = store.channel_key()?;
    let report = sync_as_initiator(
        Box::new(AppLink(link)),
        &mut store,
        &key,
        &remote,
        &DriveConfig::default(),
    )
    .map_err(failed)?;
    Ok((&report).into())
}

/// A login as shown in a list: no secret.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LoginSummary {
    /// The item identifier.
    pub id: String,
    /// The display name.
    pub title: String,
    /// The user name.
    pub username: String,
}

/// A device of the vault.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceSummary {
    /// Its identifier.
    pub id: String,
    /// Its name.
    pub name: String,
    /// Whether it is this device.
    pub is_this_device: bool,
    /// Whether it has been revoked.
    pub revoked: bool,
}

/// The vault file of this device, opened for reading and writing logins.
#[derive(uniffi::Object)]
pub struct MobileVault {
    vault: Mutex<Vault>,
}

impl MobileVault {
    fn vault(&self) -> MutexGuard<'_, Vault> {
        self.vault.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn item_id(text: &str) -> Result<ItemId, FfiError> {
    parse_id(text)
        .map(ItemId::from_bytes)
        .ok_or_else(|| failed("malformed item identifier"))
}

#[uniffi::export]
impl MobileVault {
    /// Opens the vault file at `path`. It starts locked.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Self {
            vault: Mutex::new(Vault::open(Path::new(&path))?),
        }))
    }

    /// Unlocks the password domain.
    pub fn unlock(&self, master_password: String) -> Result<(), FfiError> {
        Ok(self.vault().unlock_password(&master_password)?)
    }

    /// Locks everything, wiping the keys from memory.
    pub fn lock(&self) {
        self.vault().lock_all();
    }

    /// The logins in the vault, without their passwords.
    pub fn logins(&self) -> Result<Vec<LoginSummary>, FfiError> {
        let items = self.vault().list::<Password>()?;
        Ok(items
            .into_iter()
            .filter_map(|(id, content)| match content {
                Content::Login(login) => Some(LoginSummary {
                    id: id.to_string(),
                    title: login.title.clone(),
                    username: login.username.clone(),
                }),
                _ => None,
            })
            .collect())
    }

    /// The password of a login.
    pub fn login_password(&self, id: String) -> Result<String, FfiError> {
        let login: Login = self.vault().get(item_id(&id)?)?;
        Ok(login.password.clone())
    }

    /// Stores a new login and returns its identifier.
    pub fn add_login(
        &self,
        title: String,
        username: String,
        password: String,
    ) -> Result<String, FfiError> {
        let id = self.vault().insert(Login::new(title, username, password))?;
        Ok(id.to_string())
    }

    /// Deletes a login.
    pub fn delete_login(&self, id: String) -> Result<(), FfiError> {
        Ok(self.vault().delete::<Password>(item_id(&id)?)?)
    }

    /// The devices of the vault. Readable while locked.
    pub fn devices(&self) -> Result<Vec<DeviceSummary>, FfiError> {
        let vault = self.vault();
        let registry = vault.registry()?;
        let own = vault.device_id();
        Ok(registry
            .records()
            .map(|record| DeviceSummary {
                id: record.device_id.to_string(),
                name: record.name.clone(),
                is_this_device: record.device_id == own,
                revoked: registry.is_revoked(&record.device_id),
            })
            .collect())
    }
}

/// Lower-case hexadecimal, for showing tags in the app's log.
#[uniffi::export]
pub fn to_hex(bytes: Vec<u8>) -> String {
    hex(&bytes)
}

/// The other devices of the vault at `path` that have not been revoked. Needs
/// no password.
#[uniffi::export]
pub fn other_devices(path: String) -> Result<Vec<Peer>, FfiError> {
    let store = Store::open(Path::new(&path))?;
    let registry = store.registry()?;
    Ok(registry
        .active()
        .filter(|record| record.device_id != store.device_id())
        .map(|record| Peer {
            device_id: record.device_id.to_string(),
            name: record.name.clone(),
        })
        .collect())
}

/// What happened with one device found on the local network.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LanSync {
    /// The device.
    pub peer: Peer,
    /// The session, if it completed.
    pub outcome: Option<SyncOutcome>,
    /// Why it did not complete, if it did not.
    pub error: Option<String>,
}

/// Looks for the other devices of the vault at `path` on the local network
/// (mDNS, `docs/spec/lan.md`) for `discover_ms` and syncs with each one found.
/// Returns an empty list if this device is not on a local network or nobody is
/// there. Works on the locked file.
///
/// The app decides what to do about the devices that are missing from the
/// result: they may still be in reach of Bluetooth.
#[uniffi::export]
pub fn sync_on_lan(path: String, discover_ms: u32) -> Result<Vec<LanSync>, FfiError> {
    let mut store = Store::open(Path::new(&path))?;
    let key = store.channel_key()?;
    let registry = store.registry()?;
    let own = store.device_id();
    let Ok(mut transport) = LanTransport::new() else {
        // Not on a local network.
        return Ok(Vec::new());
    };

    // Listen for the whole time: answers trickle in.
    let deadline = Instant::now() + Duration::from_millis(u64::from(discover_ms));
    let mut found = Vec::new();
    loop {
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        for discovered in transport.discover(wait).map_err(failed)? {
            let Some(record) = identify(&registry, &discovered.tag, unix_secs()) else {
                continue;
            };
            let known = found
                .iter()
                .any(|(device, _, _, _): &(DeviceId, _, _, _)| *device == record.device_id);
            if record.device_id != own && !known {
                found.push((
                    record.device_id,
                    record.name.clone(),
                    record.noise_pk,
                    discovered.address,
                ));
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    let mut results = Vec::new();
    for (device, name, noise_pk, address) in found {
        let session = transport
            .connect(&address)
            .map_err(|error| error.to_string())
            .and_then(|link| {
                sync_as_initiator(link, &mut store, &key, &noise_pk, &DriveConfig::default())
                    .map_err(|error| error.to_string())
            });
        results.push(LanSync {
            peer: Peer {
                device_id: device.to_string(),
                name,
            },
            outcome: session.as_ref().ok().map(Into::into),
            error: session.err(),
        });
    }
    Ok(results)
}
