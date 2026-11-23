//! The other devices: pairing and sync over the app's radio (BLE) and the
//! local network (`docs/spec/android.md` §5). The app process plays the sync
//! daemon: it holds the connections, and the vault process handles what goes
//! through them (sync requests and pairing relays, `docs/spec/ipc.md` §10–§11).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zp_crypto::{ChannelKey, DeviceId};
use zp_ipc::RemoteOpLog;
use zp_ipc::proto::{self, request, response};
use zp_pairing::{OfferRole, PairingOffer};
use zp_sync::{OpLog, SessionReport};
use zp_transport::ble::{self, parse_tag_value};
use zp_transport::discovery::identify;
use zp_transport::{DriveConfig, LanTransport, Transport, sync_as_initiator};

use crate::client::{VaultClient, close_up, relay, send_up};
use crate::error::{Problem, ZpError};
use crate::link::{AppLink, ByteLink};
use crate::{Domain, hex, parse_hex};

/// How long to wait for the other device's bytes while reading the link.
const READ_POLL_MS: u32 = 200;

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
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

fn parse_offer(code: &str) -> Result<PairingOffer, ZpError> {
    let offer = PairingOffer::parse(code.trim(), unix_secs())
        .map_err(|error| ZpError::new(Problem::BadCode, error.to_string()))?;
    if offer.role != OfferRole::Existing {
        return Err(ZpError::new(
            Problem::BadCode,
            "the code was not made by a device that has the vault",
        ));
    }
    Ok(offer)
}

/// Checks a scanned pairing code and tells the app which device to connect to.
/// The code itself only goes to the vault process.
#[uniffi::export]
pub fn offer_info(code: String) -> Result<OfferInfo, ZpError> {
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

/// Lower-case hexadecimal, for showing tags in the app's log.
#[uniffi::export]
pub fn to_hex(bytes: Vec<u8>) -> String {
    hex(&bytes)
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

/// What pairing achieved.
#[derive(Debug, Clone, uniffi::Record)]
pub struct JoinOutcome {
    /// The vault.
    pub vault_id: String,
    /// The identifier of this device in it.
    pub device_id: String,
    /// The first sync, if it completed.
    pub first_sync: Option<SyncOutcome>,
    /// Why the first sync did not complete, if it did not. The vault is valid
    /// either way and catches up at the next sync.
    pub first_sync_error: Option<String>,
    /// The domains whose keys this device received.
    pub domains: Vec<Domain>,
}

impl From<proto::PairDone> for JoinOutcome {
    fn from(done: proto::PairDone) -> Self {
        let synced = done.first_sync_error.is_empty();
        Self {
            vault_id: hex(&done.vault_id),
            device_id: hex(&done.device_id),
            first_sync: synced.then_some(SyncOutcome {
                sent: done.sent,
                received: done.received,
            }),
            first_sync_error: (!synced).then(|| done.first_sync_error.clone()),
            domains: done
                .domains
                .iter()
                .filter_map(|domain| Domain::from_proto(*domain))
                .collect(),
        }
    }
}

/// A device of this vault.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Peer {
    /// Its identifier (hexadecimal).
    pub device_id: String,
    /// Its name.
    pub name: String,
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

fn sync_error(error: impl core::fmt::Display) -> ZpError {
    ZpError::failed(format!("sync: {error}"))
}

impl VaultClient {
    /// The vault process's operation log, for one sync session.
    fn op_log(&self) -> Result<RemoteOpLog, ZpError> {
        RemoteOpLog::new((self.connect)()?).map_err(sync_error)
    }

    /// Carries a pairing between `link` and the vault process, which runs it
    /// (`docs/spec/ipc.md` §11). This device never admits anyone, so it turns
    /// down whatever the vault process would ask its user.
    fn relay_pairing(
        &self,
        request: request::Body,
        link: Arc<dyn ByteLink>,
    ) -> Result<proto::PairDone, ZpError> {
        let (mut downlink, uplink) = relay(&self.connect, request)?;
        let finished = Arc::new(AtomicBool::new(false));
        let reader = {
            let (link, uplink, finished) = (
                Arc::clone(&link),
                Arc::clone(&uplink),
                Arc::clone(&finished),
            );
            thread::spawn(move || {
                while !finished.load(Ordering::Relaxed) {
                    match link.read(READ_POLL_MS) {
                        Ok(bytes) if bytes.is_empty() => {}
                        Ok(data) => {
                            if !send_up(&uplink, request::Body::LinkData(proto::LinkData { data }))
                            {
                                break;
                            }
                        }
                        // The other device is gone.
                        Err(_) => break,
                    }
                }
                close_up(&uplink);
            })
        };
        let outcome = loop {
            match downlink.receive() {
                Ok(response::Body::LinkData(chunk)) => {
                    if let Err(error) = link.write(chunk.data) {
                        break Err(ZpError::failed(format!("the link failed: {error}")));
                    }
                }
                Ok(response::Body::PairConfirmRequest(_)) => {
                    send_up(
                        &uplink,
                        request::Body::PairConfirm(proto::PairConfirm { approved: false }),
                    );
                }
                Ok(response::Body::PairDone(done)) => break Ok(done),
                Ok(_) => {}
                Err(error) => break Err(error.into()),
            }
        };
        finished.store(true, Ordering::Relaxed);
        close_up(&uplink);
        let _ = reader.join();
        outcome
    }
}

#[uniffi::export]
impl VaultClient {
    /// Joins the vault of the device that shows `code`, over `link` to that
    /// device. The vault process creates this device's vault from what the
    /// other device grants, protected by `master_password` (this device's
    /// own); the other device's user confirms `device_name` first. Unless
    /// `without_hardware`, fails with `HardwareUnavailable` when the key store
    /// cannot be used (ADR-0011).
    pub fn join(
        &self,
        code: String,
        device_name: String,
        master_password: String,
        without_hardware: bool,
        link: Arc<dyn ByteLink>,
    ) -> Result<JoinOutcome, ZpError> {
        parse_offer(&code)?;
        let join = request::Body::PairJoin(proto::PairJoin {
            offer: code,
            device_name,
            master_password,
            without_hardware,
        });
        self.relay_pairing(join, link).map(Into::into)
    }

    /// On a device that is already in the vault: receives the TOTP and passkey
    /// keys from the device that shows `code`, over `link` to it (ADR-0011).
    pub fn receive_keys(
        &self,
        code: String,
        link: Arc<dyn ByteLink>,
    ) -> Result<JoinOutcome, ZpError> {
        parse_offer(&code)?;
        let receive = request::Body::PairReceiveKeys(proto::PairReceiveKeys { offer: code });
        self.relay_pairing(receive, link).map(Into::into)
    }

    /// The other devices of the vault that have not been revoked. Needs no
    /// password.
    pub fn other_devices(&self) -> Result<Vec<Peer>, ZpError> {
        let log = self.op_log()?;
        let registry = log.registry().map_err(sync_error)?;
        let own = log.device_id();
        Ok(registry
            .active()
            .filter(|record| record.device_id != own)
            .map(|record| Peer {
                device_id: record.device_id.to_string(),
                name: record.name.clone(),
            })
            .collect())
    }

    /// Whether the value of a `Tag` characteristic belongs to another device of
    /// the vault, and to which. Needs no password.
    pub fn recognise_peer(&self, tag_value: Vec<u8>) -> Result<Option<Peer>, ZpError> {
        let Some((Some(tag), _)) = parse_tag_value(&tag_value) else {
            return Ok(None);
        };
        let log = self.op_log()?;
        let registry = log.registry().map_err(sync_error)?;
        let own = log.device_id();
        Ok(identify(&registry, &tag, unix_secs())
            .filter(|record| record.device_id != own)
            .map(|record| Peer {
                device_id: record.device_id.to_string(),
                name: record.name.clone(),
            }))
    }

    /// Syncs with the device `peer_device_id` over `link` to it. Works while
    /// the vault is locked: only ciphertext and signatures pass.
    pub fn sync_with(
        &self,
        peer_device_id: String,
        link: Arc<dyn ByteLink>,
    ) -> Result<SyncOutcome, ZpError> {
        let peer = parse_hex::<16>(&peer_device_id)
            .map(DeviceId::from_bytes)
            .ok_or_else(|| ZpError::new(Problem::InvalidInput, "malformed device identifier"))?;
        let mut log = self.op_log()?;
        let registry = log.registry().map_err(sync_error)?;
        let remote = registry
            .get(&peer)
            .filter(|_| registry.is_active(&peer))
            .ok_or_else(|| {
                ZpError::new(
                    Problem::ItemNotFound,
                    "that device is not an active member of this vault",
                )
            })?
            .noise_pk;
        let key = ChannelKey::from_secret_bytes(log.channel_key().secret_bytes());
        let report = sync_as_initiator(
            Box::new(AppLink(link)),
            &mut log,
            &key,
            &remote,
            &DriveConfig::default(),
        )
        .map_err(sync_error)?;
        Ok((&report).into())
    }

    /// Looks for the other devices of the vault on the local network (mDNS,
    /// `docs/spec/lan.md`) for `discover_ms` and syncs with each one found.
    /// Returns an empty list if this device is not on a local network or nobody
    /// is there. Works while the vault is locked.
    ///
    /// The app decides what to do about the devices missing from the result:
    /// they may still be in reach of Bluetooth.
    pub fn sync_on_lan(&self, discover_ms: u32) -> Result<Vec<LanSync>, ZpError> {
        let mut log = self.op_log()?;
        let key = ChannelKey::from_secret_bytes(log.channel_key().secret_bytes());
        let registry = log.registry().map_err(sync_error)?;
        let own = log.device_id();
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
            for discovered in transport.discover(wait).map_err(sync_error)? {
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
                    sync_as_initiator(link, &mut log, &key, &noise_pk, &DriveConfig::default())
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
}
