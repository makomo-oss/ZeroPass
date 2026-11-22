//! Pairing, as a client carries it (`docs/spec/ipc.md` §11, §12).
//!
//! The vault daemon runs the pairing protocol; the sync daemon holds the
//! connection to the other device. The client carries the bytes between the
//! two — the pairing channel's ciphertext — and asks its user to confirm.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use zp_drive::Link;
use zp_ipc::proto::{self, request, response};
use zp_ipc::{Client, IpcError, Uplink};
use zp_pairing::qr::pairing_tag;
use zp_pairing::{Hint, OfferRole, PairingOffer};
use zp_vault::VaultError;

use crate::syncd::{self, DeviceLink};
use crate::vaultd::{self, Start};
use crate::{Error, KeyAgent, KeyStoreChoice, Result};

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The outcome of the first sync after pairing, as the daemon tells it: what
/// was sent and received, or why it did not complete.
pub fn first_sync(done: &proto::PairDone) -> core::result::Result<(u64, u64), &str> {
    if done.first_sync_error.is_empty() {
        Ok((done.sent, done.received))
    } else {
        Err(&done.first_sync_error)
    }
}

/// The uplink of a relay, shared by the thread that forwards what the other
/// device sends and the thread that answers the daemon's questions. Taking
/// it out closes it, which tells the daemon that nothing more comes.
type SharedUplink = Arc<Mutex<Option<Uplink>>>;

fn send_up(uplink: &SharedUplink, body: request::Body) -> bool {
    let mut guard = uplink.lock().unwrap_or_else(|poison| poison.into_inner());
    guard
        .as_mut()
        .is_some_and(|uplink| uplink.send(body).is_ok())
}

fn close_up(uplink: &SharedUplink) {
    uplink
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .take();
}

/// Opens the link to the other device once the vault daemon is ready.
type OpenLink = Box<dyn FnOnce() -> Result<Box<dyn Link>>>;

/// The link to the other device, for [`relay`].
pub enum DeviceSide {
    /// Already open: the other device starts the handshake.
    Open(Box<dyn Link>),
    /// To be opened once the vault daemon has its first message ready: this
    /// device starts the handshake, and the other one does not wait long for
    /// it (the vault daemon may first have to set up its key store).
    WhenReady(OpenLink),
}

/// Starts carrying what the other device sends to the vault daemon. Returns
/// where to write what the vault daemon sends, and the forwarding thread.
fn forward_from_device(
    link: Box<dyn Link>,
    uplink: &SharedUplink,
    finished: &Arc<AtomicBool>,
) -> Result<(Box<dyn Write + Send>, thread::JoinHandle<()>)> {
    let (mut from_device, to_device) = link.split()?;
    let uplink = Arc::clone(uplink);
    let finished = Arc::clone(finished);
    let forwarding = thread::spawn(move || {
        let mut buffer = vec![0u8; 32 * 1024];
        while !finished.load(Ordering::Relaxed) {
            match from_device.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    if !send_up(&uplink, request::Body::LinkData(proto::LinkData { data })) {
                        break;
                    }
                }
                // Nothing arrived for a moment (links wake their reader up
                // regularly so that it can notice the end).
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
        }
        // The other device is gone, or the pairing is over.
        close_up(&uplink);
    });
    Ok((to_device, forwarding))
}

/// Carries a pairing between the other device and the vault daemon, which
/// runs it. `request` starts the pairing in the daemon; `confirm` is asked
/// when the daemon wants the user's consent.
pub fn relay(
    vault: &Path,
    choice: KeyStoreChoice,
    start: Start,
    request: request::Body,
    device: DeviceSide,
    mut confirm: impl FnMut(&proto::PairConfirmRequest) -> bool,
) -> Result<proto::PairDone> {
    let connect = || -> Result<Client> { vaultd::open(vault, choice, start) };
    let (id, mut downlink) = connect()?.start_relay(request)?;
    let uplink = match connect()?.attach_relay(id) {
        Ok(uplink) => uplink,
        // The daemon ended the relay at once; its reason is on the downlink.
        Err(attach_error) => {
            return match downlink.receive() {
                Err(reason) => Err(reason.into()),
                Ok(_) => Err(attach_error.into()),
            };
        }
    };
    let uplink: SharedUplink = Arc::new(Mutex::new(Some(uplink)));
    let finished = Arc::new(AtomicBool::new(false));
    let (mut to_device, mut forwarding, mut pending) = match device {
        DeviceSide::Open(link) => {
            let (to_device, forwarding) = forward_from_device(link, &uplink, &finished)?;
            (Some(to_device), Some(forwarding), None)
        }
        DeviceSide::WhenReady(open) => (None, None, Some(open)),
    };

    // Daemon → other device, and the daemon's questions.
    let outcome: Result<proto::PairDone> = loop {
        match downlink.receive() {
            Ok(response::Body::LinkData(chunk)) => {
                if let Some(open) = pending.take() {
                    let opened =
                        open().and_then(|link| forward_from_device(link, &uplink, &finished));
                    match opened {
                        Ok((writer, thread)) => {
                            to_device = Some(writer);
                            forwarding = Some(thread);
                        }
                        Err(error) => break Err(error),
                    }
                }
                let Some(writer) = to_device.as_mut() else {
                    break Err(Error::message(
                        "the vault daemon sent data before there was a link",
                    ));
                };
                if let Err(error) = writer.write_all(&chunk.data).and_then(|()| writer.flush()) {
                    break Err(IpcError::Io(error).into());
                }
            }
            Ok(response::Body::PairConfirmRequest(question)) => {
                let approved = confirm(&question);
                send_up(
                    &uplink,
                    request::Body::PairConfirm(proto::PairConfirm { approved }),
                );
            }
            Ok(response::Body::PairDone(done)) => break Ok(done),
            Ok(_) => {}
            Err(error) => break Err(error.into()),
        }
    };
    finished.store(true, Ordering::Relaxed);
    close_up(&uplink);
    drop(to_device);
    if let Some(forwarding) = forwarding {
        let _ = forwarding.join();
    }
    outcome
}

/// A pairing code, ready to be shown to the user.
#[derive(Debug, Clone)]
pub struct ShownOffer {
    /// The code: the text to type, and what the QR code encodes.
    pub code: String,
    /// How many seconds it stays valid.
    pub lifetime_secs: u32,
    /// What the sync daemon waits on (LAN, Bluetooth).
    pub transports: Vec<String>,
    /// Transports that are not available, and why.
    pub problems: Vec<String>,
}

/// On a device that has the vault: creates a pairing code, has `show` show it
/// once the sync daemon waits for the other device, and admits that device if
/// `confirm` agrees. Every domain of the vault must be unlocked (the daemon
/// answers `LOCKED` otherwise); the daemon keeps them unlocked until the code
/// is used or expires.
pub fn admit(
    vault: &Path,
    choice: KeyStoreChoice,
    mut show: impl FnMut(&ShownOffer) -> Result<()>,
    confirm: impl FnMut(&proto::PairConfirmRequest) -> bool,
) -> Result<proto::PairDone> {
    // The sync daemon tells where other devices reach this one; those
    // addresses go into the code.
    let status = syncd::status_when_syncing(&mut syncd::open(vault)?)?;
    let offer = proto::PairOffer {
        hints: status.lan_endpoints.clone(),
    };
    let offered = match vaultd::open(vault, choice, Start::IfVaultExists)?
        .call(request::Body::PairOffer(offer))?
    {
        response::Body::PairOffered(offered) => offered,
        _ => return Err(Error::message("the vault daemon gave an unexpected answer")),
    };
    let parsed = PairingOffer::parse(&offered.offer, unix_secs())?;
    let shown = ShownOffer {
        code: offered.offer.clone(),
        lifetime_secs: offered.lifetime_secs,
        transports: status.transports,
        problems: status.problems,
    };

    // The sync daemon waits for the device. It is given the tag a joining
    // device looks for over Bluetooth, derived from the code's secret, but
    // never the code: it must not be able to take part in the pairing. The
    // code is shown only once the sync daemon waits, so that a device that
    // enters it at once finds someone waiting.
    let listen = request::Body::PairListen(proto::PairListen {
        tag: pairing_tag(&parsed.psk).to_vec(),
        seconds: offered.lifetime_secs,
    });
    let link = DeviceLink::open(vault, listen, || show(&shown))?;
    relay(
        vault,
        choice,
        Start::IfVaultExists,
        request::Body::PairAdmit(proto::PairAdmit {}),
        DeviceSide::Open(Box::new(link)),
        confirm,
    )
}

/// On a new device: creates the vault file at `vault` by joining the vault of
/// the device that shows `code`. The vault daemon creates the file from what
/// the other device grants, protected by `master_password`; this process only
/// carries the bytes. The user of the other device confirms.
///
/// If the hardware key store cannot be used, the daemon refuses with
/// `HARDWARE_UNAVAILABLE` unless `without_hardware`: then this device joins
/// without the TOTP and passkey domains (ADR-0011).
pub fn join(
    vault: &Path,
    choice: KeyStoreChoice,
    code: &str,
    device_name: &str,
    master_password: &str,
    without_hardware: bool,
) -> Result<proto::PairDone> {
    if vault.exists() {
        return Err(VaultError::AlreadyExists.into());
    }
    // The daemon checks the code again; here it is read for the addresses.
    let offer = PairingOffer::parse(code, unix_secs())?;
    if offer.role != OfferRole::Existing {
        return Err(Error::message(
            "this code was not created by a device that has the vault",
        ));
    }

    // The sync daemon connects to the other device. It is given the addresses
    // from the code, never the code.
    let addresses = offer
        .hints
        .iter()
        .filter_map(|hint| match hint {
            Hint::Socket(address) => Some(address.to_string()),
            Hint::Ble => None,
        })
        .collect();
    let connect = request::Body::PairConnect(proto::PairConnect { addresses });
    let device = DeviceSide::WhenReady(Box::new({
        let vault = vault.to_path_buf();
        move || -> Result<Box<dyn Link>> {
            Ok(Box::new(DeviceLink::open(&vault, connect, || Ok(()))?))
        }
    }));

    let join = request::Body::PairJoin(proto::PairJoin {
        offer: code.to_owned(),
        device_name: device_name.to_owned(),
        master_password: master_password.to_owned(),
        without_hardware,
    });
    // The daemon wraps the keys it is granted with the hardware key store,
    // which the key agent reaches for it.
    vaultd::connect(vault, choice, Start::Always)?;
    let _key_agent = KeyAgent::start(vault, choice)?;
    // Nobody is asked on this side: the user of the other device confirms.
    relay(vault, choice, Start::Always, join, device, |_| false)
}
