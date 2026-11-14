//! Commands that talk to other devices on the local network: pairing and sync.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qrcode::QrCode;
use qrcode::render::unicode;
use zp_crypto::DomainId;
use zp_ipc::RemoteOpLog;
use zp_pairing::qr::OFFER_LIFETIME_SECS;
use zp_pairing::{Hint, Joiner, OfferRole, PairingOffer};
use zp_sync::OpLog;
use zp_sync::SessionReport;
use zp_transport::ble::pairing_tag;
use zp_transport::daemon::{DaemonConfig, Event, SyncDaemon};
use zp_transport::{
    Address, DriveConfig, LanTransport, Nearby, NewVault, PairingLink, Transport, open_nearby,
    pair_as_existing, pair_as_new,
};
use zp_vault::{CreateOptions, VaultError, default_device_name};

use super::remote::{self, Start};
use super::{
    CliResult, Input, KeyStoreChoice, Session, dev_key_path, domain_name, hardware_key_store,
};

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

impl Session {
    /// `pair`: shows a pairing code and admits the device that enters it.
    pub(super) fn pair(&mut self, out: &mut impl Write) -> CliResult<()> {
        // Admitting a device hands over every vault key, so every domain of the
        // vault must be unlocked, and still be when the other device has connected
        // and the user has confirmed it.
        self.unlock_every_domain()?;
        let mut nearby = nearby()?;
        let key = self.vault.channel_key()?;
        let hints = nearby
            .lan_endpoints
            .iter()
            .map(|endpoint| Hint::Socket(*endpoint))
            .collect();
        let offer =
            PairingOffer::new(OfferRole::Existing, *key.public_bytes(), hints, unix_secs())?;
        // Over Bluetooth the code carries no address: the other device finds this
        // one by a tag derived from the code's secret.
        nearby
            .transport
            .announce_pairing(Some(pairing_tag(&offer.psk)))?;

        writeln!(
            out,
            "Pairing code (valid for {OFFER_LIFETIME_SECS} seconds, usable once):"
        )?;
        writeln!(out)?;
        writeln!(out, "{}", offer.to_text().as_str())?;
        writeln!(out)?;
        if let Ok(code) = QrCode::new(offer.to_text().as_bytes()) {
            let picture = code
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

        let deadline = Instant::now() + Duration::from_secs(OFFER_LIFETIME_SECS);
        let link = loop {
            if let Some(link) = nearby.transport.accept(Duration::from_millis(500))? {
                break link;
            }
            if Instant::now() >= deadline {
                return Err("no device connected before the code expired".into());
            }
        };
        let pairing = PairingLink {
            scanned: false,
            psk: &offer.psk,
            offered_key: None,
        };
        let input = &self.input;
        let admitted = pair_as_existing(
            link,
            &mut self.vault,
            &pairing,
            |request| {
                let question = format!(
                    "Add the device \"{}\" ({}) to this vault? [y/N] ",
                    request.name, request.device_id
                );
                matches!(input.line(&question), Ok(Some(answer)) if answer.trim().eq_ignore_ascii_case("y"))
            },
            &DriveConfig::default(),
        )?;
        nearby.transport.announce_pairing(None)?;

        writeln!(
            out,
            "added device \"{}\" ({})",
            admitted.name, admitted.device
        )?;
        match &admitted.sync {
            Ok(report) => writeln!(out, "first sync: {}", describe(report))?,
            Err(error) => writeln!(
                out,
                "first sync did not complete ({error}); it will be retried at the next sync"
            )?,
        }
        Ok(())
    }
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
/// pairing code.
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
    let offer = PairingOffer::parse(&code, unix_secs())?;
    if offer.role != OfferRole::Existing {
        return Err("this code was not created by `zp-cli pair`".into());
    }
    let name = name.unwrap_or_else(default_device_name);
    let hardware = hardware_key_store(choice, vault_path, true)?;
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

    let pairing = PairingLink {
        scanned: true,
        psk: &offer.psk,
        offered_key: Some(offer.noise_pk),
    };
    let new_vault = NewVault {
        path: vault_path,
        master_password: &password,
        hardware: hardware.as_deref(),
        options: CreateOptions {
            device_name: Some(name.clone()),
            ..CreateOptions::default()
        },
    };
    let joined = match pair_as_new(
        link,
        Joiner::new(&name)?,
        &pairing,
        new_vault,
        &DriveConfig::default(),
    ) {
        Ok(joined) => joined,
        Err(error) => {
            if choice == KeyStoreChoice::InsecureSoftware {
                let _ = std::fs::remove_file(dev_key_path(vault_path));
            }
            return Err(error.into());
        }
    };

    let mut vault = joined.vault;
    writeln!(out, "joined vault {} as \"{name}\"", vault.vault_id())?;
    for domain in DomainId::ALL {
        let state = if vault.is_unlocked(domain) {
            "available"
        } else {
            "not available on this device (no hardware key store)"
        };
        writeln!(out, "  {:<8} {state}", format!("{}:", domain_name(domain)))?;
    }
    match &joined.sync {
        Ok(report) => writeln!(out, "first sync: {}", describe(report))?,
        Err(error) => writeln!(
            out,
            "first sync did not complete ({error}); run `sync` to retry"
        )?,
    }
    Ok(())
}
