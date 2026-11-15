//! Commands that involve other devices nearby: pairing and sync.
//!
//! This process has no connection to another device and no vault data. The
//! sync daemon holds the connections and syncs (`docs/spec/ipc.md` §12); the
//! vault daemon runs the pairing protocol (§11). For pairing, this process
//! carries the bytes between the two (`zp_client::pairing`).

use std::io::Write;
use std::path::Path;

use qrcode::QrCode;
use qrcode::render::unicode;
use zp_client::pairing::{self, ShownOffer};
use zp_client::vaultd::Start;
use zp_client::{KeyStoreChoice, syncd};
use zp_crypto::DomainId;
use zp_ipc::proto;
use zp_vault::{VaultError, default_device_name};

use super::remote::Remote;
use super::{CliResult, Input, domain_name};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The outcome of the first sync after pairing, in words.
fn first_sync(done: &proto::PairDone) -> Result<String, &str> {
    pairing::first_sync(done)
        .map(|(sent, received)| format!("sent {sent} change(s), received {received}"))
}

/// Shows the pairing code, as text and as a QR code, and what to do with it.
fn show_code(out: &mut impl Write, offer: &ShownOffer) -> CliResult<()> {
    let code = &offer.code;
    writeln!(
        out,
        "Pairing code (valid for {} seconds, usable once):",
        offer.lifetime_secs
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
    writeln!(out, "Waiting on: {}", offer.transports.join(", "))?;
    for problem in &offer.problems {
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
    let input = &remote.input;
    let admitted = pairing::admit(
        vault_path,
        choice,
        |offer| {
            show_code(&mut *out, offer)
                .map_err(|error| zp_client::Error::message(error.to_string()))
        },
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
    let results = syncd::sync_now(vault_path, u32::try_from(seconds).unwrap_or(u32::MAX))?;
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
    let name = name.unwrap_or_else(default_device_name);
    let joined = pairing::join(vault_path, choice, &code, &name, &password)?;

    writeln!(out, "joined vault {} as \"{name}\"", hex(&joined.vault_id))?;
    let mut remote = Remote::open_with(vault_path, choice, Start::IfVaultExists)?;
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
