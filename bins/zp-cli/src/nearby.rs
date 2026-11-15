//! Commands that involve other devices nearby: pairing and sync.
//!
//! This process has no connection to another device and no vault data. The
//! sync daemon holds the connections and syncs (`docs/spec/ipc.md` §12); the
//! vault daemon runs the pairing protocol (§11). For pairing, this process
//! carries the bytes between the two: the pairing channel's ciphertext.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use qrcode::QrCode;
use qrcode::render::unicode;
use zp_crypto::DomainId;
use zp_drive::Link;
use zp_ipc::proto::{self, request, response};
use zp_ipc::{Client, IpcError, Uplink};
use zp_pairing::qr::pairing_tag;
use zp_pairing::{Hint, OfferRole, PairingOffer};
use zp_vault::{VaultError, default_device_name};

use super::keyagent::KeyAgent;
use super::remote::{self, Remote, Start};
use super::syncd::{self, DeviceLink};
use super::{CliResult, Input, KeyStoreChoice, domain_name};

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The outcome of the first sync after pairing, as the daemon tells it.
fn first_sync(done: &proto::PairDone) -> Result<String, &str> {
    if done.first_sync_error.is_empty() {
        Ok(format!(
            "sent {} change(s), received {}",
            done.sent, done.received
        ))
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

/// The link to the other device, for [`relay_pairing`].
enum DeviceSide {
    /// Already open: the other device starts the handshake.
    Open(Box<dyn Link>),
    /// To be opened once the vault daemon has its first message ready: this
    /// device starts the handshake, and the other one does not wait long for
    /// it (the vault daemon may first have to set up its key store).
    WhenReady(Box<dyn FnOnce() -> CliResult<Box<dyn Link>>>),
}

/// Starts carrying what the other device sends to the vault daemon. Returns
/// where to write what the vault daemon sends, and the forwarding thread.
fn forward_from_device(
    link: Box<dyn Link>,
    uplink: &SharedUplink,
    finished: &Arc<AtomicBool>,
) -> CliResult<(Box<dyn Write + Send>, thread::JoinHandle<()>)> {
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
fn relay_pairing(
    vault_path: &Path,
    choice: KeyStoreChoice,
    start: Start,
    request: request::Body,
    device: DeviceSide,
    mut confirm: impl FnMut(&proto::PairConfirmRequest) -> bool,
) -> CliResult<proto::PairDone> {
    let connect = || -> CliResult<Client> {
        Ok(remote::connect(vault_path, choice, start)?.ok_or("the vault daemon is not running")?)
    };
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
    let outcome: CliResult<proto::PairDone> = loop {
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
                    break Err("the vault daemon sent data before there was a link".into());
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

/// Shows the pairing code, as text and as a QR code, and what to do with it.
fn show_code(
    out: &mut impl Write,
    code: &str,
    lifetime: u32,
    status: &proto::SyncdStatusReply,
) -> CliResult<()> {
    writeln!(
        out,
        "Pairing code (valid for {lifetime} seconds, usable once):"
    )?;
    writeln!(out)?;
    writeln!(out, "{code}")?;
    writeln!(out)?;
    if let Ok(picture) = QrCode::new(code.as_bytes()) {
        let picture = picture
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();
        writeln!(out, "{picture}")?;
        writeln!(out)?;
    }
    writeln!(
        out,
        "On a phone, scan the picture. On a computer, run `zp-cli --vault <new file> join` and enter the code."
    )?;
    writeln!(out, "Waiting on: {}", status.transports.join(", "))?;
    for problem in &status.problems {
        writeln!(out, "  not available: {problem}")?;
    }
    writeln!(
        out,
        "Anyone who sees the code within its lifetime can ask to join; check the name before you confirm."
    )?;
    out.flush()?;
    Ok(())
}

/// `pair`: shows a pairing code and admits the device that enters it.
pub(super) fn pair(
    choice: KeyStoreChoice,
    vault_path: &Path,
    out: &mut impl Write,
) -> CliResult<()> {
    let mut remote = Remote::open(vault_path, choice)?;
    // Admitting a device hands over every vault key, so every domain of the
    // vault must be unlocked. The daemon keeps them unlocked from the moment it
    // hands out the code until the device is admitted or the code expires.
    remote.unlock_every_domain()?;
    // The sync daemon tells where other devices reach this one; those
    // addresses go into the code.
    let status = syncd::status_when_syncing(&mut syncd::open(vault_path)?)?;
    let (code, lifetime) = remote.pair_offer(status.lan_endpoints.clone())?;
    let offer = PairingOffer::parse(&code, unix_secs())?;

    // The sync daemon waits for the device. It is given the tag a joining
    // device looks for over Bluetooth, derived from the code's secret, but
    // never the code: it must not be able to take part in the pairing. The
    // code is shown only once the sync daemon waits, so that a device that
    // enters it at once finds someone waiting.
    let listen = request::Body::PairListen(proto::PairListen {
        tag: pairing_tag(&offer.psk).to_vec(),
        seconds: lifetime,
    });
    let link = DeviceLink::open(vault_path, listen, || {
        show_code(&mut *out, &code, lifetime, &status)
    })?;
    let input = &remote.input;
    let admitted = relay_pairing(
        vault_path,
        choice,
        Start::IfVaultExists,
        request::Body::PairAdmit(proto::PairAdmit {}),
        DeviceSide::Open(Box::new(link)),
        |question| {
            let text = format!(
                "Add the device \"{}\" ({}) to this vault? [y/N] ",
                question.name,
                hex(&question.device_id)
            );
            matches!(input.line(&text), Ok(Some(answer)) if answer.trim().eq_ignore_ascii_case("y"))
        },
    )?;

    writeln!(
        out,
        "added device \"{}\" ({})",
        admitted.name,
        hex(&admitted.device_id)
    )?;
    match first_sync(&admitted) {
        Ok(report) => writeln!(out, "first sync: {report}")?,
        Err(error) => writeln!(
            out,
            "first sync did not complete ({error}); it will be retried at the next sync"
        )?,
    }
    Ok(())
}

/// `sync`: has the sync daemon sync with the other devices of the vault now,
/// for at most `seconds`, and reports what it did.
pub(super) fn sync(vault_path: &Path, seconds: u64, out: &mut impl Write) -> CliResult<()> {
    if !vault_path.exists() {
        return Err(VaultError::NotFound.into());
    }
    let mut client = syncd::open(vault_path)?;
    let request = request::Body::SyncNow(proto::SyncNow {
        seconds: u32::try_from(seconds).unwrap_or(u32::MAX),
    });
    let response::Body::SyncResults(results) = client.call(request)? else {
        return Err("the sync daemon gave an unexpected answer".into());
    };
    if results.other_devices == 0 {
        writeln!(
            out,
            "this vault has no other devices yet; use `pair` to add one"
        )?;
        return Ok(());
    }
    let mut synced = 0;
    for result in &results.results {
        if result.error.is_empty() {
            synced += 1;
            writeln!(
                out,
                "synced with \"{}\": sent {} change(s), received {}",
                result.name, result.sent, result.received
            )?;
        } else {
            writeln!(out, "a sync attempt failed: {}", result.error)?;
        }
    }
    if synced == 0 {
        writeln!(out, "no other device of this vault was found nearby")?;
    }
    Ok(())
}

/// `join`: creates this device's vault file by joining an existing vault with a
/// pairing code. The vault daemon creates the file from what the other device
/// grants; this process only carries the bytes.
pub(super) fn join(
    choice: KeyStoreChoice,
    vault_path: &Path,
    name: Option<String>,
    out: &mut impl Write,
) -> CliResult<()> {
    if vault_path.exists() {
        return Err(VaultError::AlreadyExists.into());
    }
    let input = Input::new();
    // The password first: the code is short-lived.
    let password = input.new_master_password()?;
    let code = input.secret("Pairing code shown on the other device: ")?;
    // The daemon checks the code again; here it is read for the addresses.
    let offer = PairingOffer::parse(&code, unix_secs())?;
    if offer.role != OfferRole::Existing {
        return Err("this code was not created by `zp-cli pair`".into());
    }
    let name = name.unwrap_or_else(default_device_name);

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
        let vault_path = vault_path.to_path_buf();
        move || -> CliResult<Box<dyn Link>> {
            Ok(Box::new(DeviceLink::open(&vault_path, connect, || Ok(()))?))
        }
    }));

    let join = request::Body::PairJoin(proto::PairJoin {
        offer: code.as_str().to_owned(),
        device_name: name.clone(),
        master_password: password.as_str().to_owned(),
    });
    // The daemon wraps the keys it is granted with the hardware key store,
    // which the key agent reaches for it.
    remote::connect(vault_path, choice, Start::Always)?;
    let _key_agent = KeyAgent::start(vault_path, choice)?;
    // Nobody is asked on this side: the user of the other device confirms.
    let joined = relay_pairing(vault_path, choice, Start::Always, join, device, |_| false)?;

    writeln!(out, "joined vault {} as \"{name}\"", hex(&joined.vault_id))?;
    let mut remote = Remote::open(vault_path, choice)?;
    let status = remote.status()?;
    // Joining a vault is not unlocking it: what follows asks again.
    remote.lock_all()?;
    for state in &status.domains {
        let domain = match proto::Domain::try_from(state.domain) {
            Ok(proto::Domain::Password) => DomainId::Password,
            Ok(proto::Domain::Totp) => DomainId::Totp,
            Ok(proto::Domain::Passkey) => DomainId::Passkey,
            _ => continue,
        };
        // The new device holds the keys of the domains it could wrap: all of
        // them with a hardware key store, the password domain without one.
        let availability = if state.unlocked {
            "available"
        } else {
            "not available on this device (no hardware key store)"
        };
        writeln!(
            out,
            "  {:<8} {availability}",
            format!("{}:", domain_name(domain))
        )?;
    }
    match first_sync(&joined) {
        Ok(report) => writeln!(out, "first sync: {report}")?,
        Err(error) => writeln!(
            out,
            "first sync did not complete ({error}); run `sync` to retry"
        )?,
    }
    Ok(())
}
