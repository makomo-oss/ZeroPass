//! Commands that talk to other devices nearby: pairing and sync.
//!
//! This process opens the connection to the other device, but it never works
//! on vault data itself. For sync it asks the vault daemon for ciphertext and
//! hands it ciphertext (`docs/spec/ipc.md` §10); for pairing it only carries
//! bytes between the other device and the vault daemon, which runs the
//! protocol, and those bytes are the pairing channel's ciphertext (§11).

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qrcode::QrCode;
use qrcode::render::unicode;
use zp_crypto::DomainId;
use zp_ipc::proto::{self, request, response};
use zp_ipc::{Client, IpcError, RemoteOpLog, Uplink};
use zp_pairing::{Hint, OfferRole, PairingOffer};
use zp_sync::{OpLog, SessionReport};
use zp_transport::ble::pairing_tag;
use zp_transport::daemon::{DaemonConfig, Event, SyncDaemon};
use zp_transport::{Address, LanTransport, Link, Nearby, Transport, open_nearby};
use zp_vault::{VaultError, default_device_name};

use super::remote::{self, Remote, Start};
use super::{CliResult, Input, KeyStoreChoice, domain_name};

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The local network and, where this machine has it, Bluetooth LE.
fn nearby() -> CliResult<Nearby> {
    open_nearby().map_err(|error| format!("cannot reach other devices: {error}").into())
}

fn lan() -> CliResult<LanTransport> {
    LanTransport::new().map_err(|error| format!("cannot use the local network: {error}").into())
}

fn describe(report: &SessionReport) -> String {
    format!(
        "sent {} change(s), received {}",
        report.sent, report.received.applied
    )
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

/// Carries a pairing between `link`, which leads to the other device, and the
/// vault daemon, which runs it. `request` starts the pairing in the daemon;
/// `confirm` is asked when the daemon wants the user's consent.
fn relay_pairing(
    vault_path: &Path,
    choice: KeyStoreChoice,
    start: Start,
    request: request::Body,
    link: Box<dyn Link>,
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
    let (mut from_device, mut to_device) = link.split()?;
    let finished = Arc::new(AtomicBool::new(false));

    // Other device → daemon.
    let forwarding = {
        let uplink = Arc::clone(&uplink);
        let finished = Arc::clone(&finished);
        thread::spawn(move || {
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
                    // Nothing arrived for a moment (links wake their reader
                    // up regularly so that it can notice the end).
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
        })
    };

    // Daemon → other device, and the daemon's questions.
    let outcome = loop {
        match downlink.receive() {
            Ok(response::Body::LinkData(chunk)) => {
                let written = to_device
                    .write_all(&chunk.data)
                    .and_then(|()| to_device.flush());
                if let Err(error) = written {
                    break Err(IpcError::Io(error));
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
            Err(error) => break Err(error),
        }
    };
    finished.store(true, Ordering::Relaxed);
    close_up(&uplink);
    let _ = forwarding.join();
    Ok(outcome?)
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
    let mut nearby = nearby()?;
    let hints = nearby
        .lan_endpoints
        .iter()
        .map(ToString::to_string)
        .collect();
    let (code, lifetime) = remote.pair_offer(hints)?;
    let offer = PairingOffer::parse(&code, unix_secs())?;
    // Over Bluetooth the code carries no address: the other device finds this
    // one by a tag derived from the code's secret.
    nearby
        .transport
        .announce_pairing(Some(pairing_tag(&offer.psk)))?;

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
    writeln!(out, "Waiting on: {}", nearby.transport.names().join(", "))?;
    for problem in &nearby.problems {
        writeln!(out, "  not available: {problem}")?;
    }
    writeln!(
        out,
        "Anyone who sees the code within its lifetime can ask to join; check the name before you confirm."
    )?;
    out.flush()?;

    let deadline = Instant::now() + Duration::from_secs(u64::from(lifetime));
    let link = loop {
        if let Some(link) = nearby.transport.accept(Duration::from_millis(500))? {
            break link;
        }
        if Instant::now() >= deadline {
            return Err("no device connected before the code expired".into());
        }
    };
    let input = &remote.input;
    let admitted = relay_pairing(
        vault_path,
        choice,
        Start::IfVaultExists,
        request::Body::PairAdmit(proto::PairAdmit {}),
        link,
        |question| {
            let text = format!(
                "Add the device \"{}\" ({}) to this vault? [y/N] ",
                question.name,
                hex(&question.device_id)
            );
            matches!(input.line(&text), Ok(Some(answer)) if answer.trim().eq_ignore_ascii_case("y"))
        },
    );
    nearby.transport.announce_pairing(None)?;
    let admitted = admitted?;

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

/// `sync`: looks for the other devices of the vault on the local network for a
/// while and syncs with those it finds. The ops are read from and handed to
/// the vault daemon; this process does not open the vault file.
pub(super) fn sync(
    choice: KeyStoreChoice,
    vault_path: &Path,
    seconds: u64,
    out: &mut impl Write,
) -> CliResult<()> {
    let client = remote::connect(vault_path, choice, Start::IfVaultExists)?
        .ok_or("the vault daemon is not running")?;
    let store = RemoteOpLog::new(client)?;
    let others: usize = store
        .registry()?
        .active()
        .filter(|record| record.device_id != store.device_id())
        .count();
    if others == 0 {
        writeln!(
            out,
            "this vault has no other devices yet; use `pair` to add one"
        )?;
        return Ok(());
    }
    let mut daemon = SyncDaemon::new(store, nearby()?.transport, DaemonConfig::default());
    let deadline = Instant::now() + Duration::from_secs(seconds);
    // Done once a session with every other device has completed.
    let events = daemon.run_until(deadline, |events| {
        let mut peers: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Synced { peer, .. } => Some(*peer),
                Event::Failed { .. } => None,
            })
            .collect();
        peers.sort();
        peers.dedup();
        peers.len() >= others
    })?;
    daemon.stop();

    let mut synced = 0;
    for event in &events {
        match event {
            Event::Synced { name, report, .. } => {
                synced += 1;
                writeln!(out, "synced with \"{name}\": {}", describe(report))?;
            }
            Event::Failed { error, .. } => writeln!(out, "a sync attempt failed: {error}")?,
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
    let mut transport = lan()?;

    // Try the addresses from the code until one answers.
    let mut link = None;
    let mut last_error = None;
    for hint in &offer.hints {
        let Hint::Socket(address) = hint else {
            continue;
        };
        match transport.connect(&Address::Socket(*address)) {
            Ok(connected) => {
                link = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some(link) = link else {
        let reason = last_error.map_or_else(
            || "the code contains no address".to_owned(),
            |e| e.to_string(),
        );
        return Err(format!("cannot reach the other device on the local network: {reason}").into());
    };

    let join = request::Body::PairJoin(proto::PairJoin {
        offer: code.as_str().to_owned(),
        device_name: name.clone(),
        master_password: password.as_str().to_owned(),
    });
    // Nobody is asked on this side: the user of the other device confirms.
    let joined = relay_pairing(vault_path, choice, Start::Always, join, link, |_| false)?;

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
