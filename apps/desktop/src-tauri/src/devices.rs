//! The vault's devices, pairing, and sync (P4-03).
//!
//! This program has no connection to other devices. The sync daemon holds
//! them; the vault daemon runs the pairing protocol; this program carries the
//! pairing's ciphertext between the two (`zp_client::pairing`) and asks the
//! user. A pairing runs on a thread of its own, and the page follows it by
//! asking for its progress ([`pair_progress`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;
use zp_client::pairing::{self, ShownOffer};
use zp_client::syncd;
use zp_ipc::proto::{self, request, response};

use crate::AppState;
use crate::commands::{blocking, hex};
use crate::error::{CommandError, CommandResult};

/// How long the user has to answer whether a device may join. The vault
/// daemon gives up after two minutes (`docs/spec/ipc.md` §11.2).
const ANSWER_TIMEOUT: Duration = Duration::from_secs(115);

fn unexpected() -> CommandError {
    CommandError::client("the vault daemon gave an unexpected answer")
}

impl AppState {
    /// Makes sure the sync daemon of the vault runs while this application
    /// shows the vault, as the logon start does (ADR-0008): otherwise a vault
    /// made in this session would not sync until the next logon. Once per
    /// run, on a thread of its own; tried again if it failed.
    pub(crate) fn ensure_sync_daemon(&self) {
        if self.sync_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let vault = self.daemon.vault().to_path_buf();
        let started = Arc::clone(&self.sync_started);
        std::thread::spawn(move || {
            if syncd::connect(&vault, true).is_err() {
                started.store(false, Ordering::SeqCst);
            }
        });
    }
}

/// One device of the vault.
#[derive(Serialize)]
pub(crate) struct Device {
    id: String,
    name: String,
    /// `this`, `active` or `revoked`.
    state: &'static str,
    changes_held: u64,
}

#[tauri::command]
pub(crate) async fn list_devices(app: AppHandle) -> CommandResult<Vec<Device>> {
    blocking(app, |state| {
        let response::Body::Devices(devices) = state
            .daemon
            .call(request::Body::ListDevices(proto::ListDevices {}))?
        else {
            return Err(unexpected());
        };
        Ok(devices
            .devices
            .into_iter()
            .map(|device| Device {
                id: hex(&device.device_id),
                name: device.name,
                state: match proto::DeviceState::try_from(device.state) {
                    Ok(proto::DeviceState::ThisDevice) => "this",
                    Ok(proto::DeviceState::Revoked) => "revoked",
                    _ => "active",
                },
                changes_held: device.changes_held,
            })
            .collect())
    })
    .await
}

/// Revokes a device and replaces the vault keys. Every domain must be open:
/// the hardware-bound ones are opened with Windows Hello if necessary.
#[tauri::command]
pub(crate) async fn revoke_device(app: AppHandle, id: String) -> CommandResult<()> {
    let device_id = (0..id.len() / 2)
        .map(|index| u8::from_str_radix(id.get(index * 2..index * 2 + 2).unwrap_or(""), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| CommandError::client("a device identifier is hexadecimal"))?;
    blocking(app, move |state| {
        state.call_unlocking(request::Body::RevokeDevice(proto::RevokeDevice {
            device_id,
        }))?;
        Ok(())
    })
    .await
}

/// What the sync daemon tells about itself.
#[derive(Serialize)]
pub(crate) struct SyncStatus {
    running: bool,
    syncing: bool,
    not_syncing_because: String,
    transports: Vec<String>,
    problems: Vec<String>,
    lan_endpoints: Vec<String>,
}

/// The state of the sync daemon. With `start`, starts it if it is not
/// running (it normally starts at logon).
#[tauri::command]
pub(crate) async fn sync_status(app: AppHandle, start: bool) -> CommandResult<SyncStatus> {
    blocking(app, move |state| {
        let Some(mut client) = syncd::connect(state.daemon.vault(), start)? else {
            return Ok(SyncStatus {
                running: false,
                syncing: false,
                not_syncing_because: "the sync daemon is not running".to_owned(),
                transports: Vec::new(),
                problems: Vec::new(),
                lan_endpoints: Vec::new(),
            });
        };
        let status = syncd::status(&mut client)?;
        Ok(SyncStatus {
            running: true,
            syncing: status.syncing,
            not_syncing_because: status.not_syncing_because,
            transports: status.transports,
            problems: status.problems,
            lan_endpoints: status.lan_endpoints,
        })
    })
    .await
}

/// The outcome of syncing with one device.
#[derive(Serialize)]
pub(crate) struct SyncOutcome {
    name: String,
    sent: u64,
    received: u64,
    error: String,
}

/// What [`sync_now`] did.
#[derive(Serialize)]
pub(crate) struct SyncReport {
    other_devices: u32,
    results: Vec<SyncOutcome>,
}

/// Has the sync daemon sync with the other devices now, for at most
/// `seconds`.
#[tauri::command]
pub(crate) async fn sync_now(app: AppHandle, seconds: u32) -> CommandResult<SyncReport> {
    blocking(app, move |state| {
        let results = syncd::sync_now(state.daemon.vault(), seconds.clamp(1, 120))?;
        Ok(SyncReport {
            other_devices: results.other_devices,
            results: results
                .results
                .into_iter()
                .map(|result| SyncOutcome {
                    name: result.name,
                    sent: result.sent,
                    received: result.received,
                    error: result.error,
                })
                .collect(),
        })
    })
    .await
}

/// Where a pairing started on this device stands, as the page shows it.
#[derive(Serialize, Clone, Default)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub(crate) enum PairProgress {
    /// No pairing.
    #[default]
    Idle,
    /// Unlocking, asking the daemons for a code.
    Starting,
    /// The code is shown; the sync daemon waits for the other device.
    Waiting {
        code: String,
        /// The code as a QR code: an SVG image, as a data URL.
        qr: String,
        lifetime_secs: u32,
        transports: Vec<String>,
        problems: Vec<String>,
    },
    /// The other device connected: may it join?
    Confirm {
        device_id: String,
        name: String,
    },
    /// The device was added.
    Done {
        device_id: String,
        name: String,
        /// Why the first sync did not complete, if it did not.
        first_sync_error: String,
        sent: u64,
        received: u64,
    },
    Failed {
        message: String,
    },
    /// The user gave up; the code runs out by itself.
    Cancelled,
}

/// The pairing this device offers, if any.
#[derive(Default)]
pub(crate) struct Pairing {
    progress: Mutex<PairProgress>,
    /// Where the user's answer to [`PairProgress::Confirm`] goes.
    answer: Mutex<Option<mpsc::Sender<bool>>>,
    /// A pairing thread is running (a cancelled one runs until its code
    /// expires).
    running: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}

impl Pairing {
    fn set(&self, progress: PairProgress) {
        // A cancelled pairing stays cancelled, whatever its thread reports.
        if self.cancelled.load(Ordering::Relaxed) && !matches!(progress, PairProgress::Cancelled) {
            return;
        }
        *self
            .progress
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = progress;
    }

    fn get(&self) -> PairProgress {
        self.progress
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn answer_slot(&self) -> std::sync::MutexGuard<'_, Option<mpsc::Sender<bool>>> {
        self.answer
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// A QR code of `text` as an SVG data URL, for an `<img>`.
fn qr_data_url(text: &str) -> String {
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else {
        return String::new();
    };
    let svg = code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build();
    let mut url = String::from("data:image/svg+xml;utf8,");
    for byte in svg.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b' '
            | b'-'
            | b'.'
            | b'_'
            | b'/'
            | b'='
            | b':'
            | b',' => url.push(char::from(byte)),
            other => url.push_str(&format!("%{other:02X}")),
        }
    }
    url
}

/// Starts offering a pairing: every domain is unlocked (Windows Hello may
/// ask), a code is made and shown once the sync daemon waits. Returns at
/// once; the page follows with [`pair_progress`].
#[tauri::command]
pub(crate) fn pair_start(app: AppHandle, state: tauri::State<'_, AppState>) -> CommandResult<()> {
    let pairing = &state.pairing;
    if pairing.running.swap(true, Ordering::SeqCst) {
        return Err(CommandError::client(
            "the previous pairing code is still valid; wait until it expires (at most a minute)",
        ));
    }
    pairing.cancelled.store(false, Ordering::Relaxed);
    pairing.set(PairProgress::Starting);
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let pairing = &state.pairing;
        let outcome = admit(&state);
        match outcome {
            Ok(done) => pairing.set(PairProgress::Done {
                device_id: hex(&done.device_id),
                name: done.name.clone(),
                first_sync_error: done.first_sync_error.clone(),
                sent: done.sent,
                received: done.received,
            }),
            Err(error) => pairing.set(PairProgress::Failed {
                message: error.to_string(),
            }),
        }
        pairing.answer_slot().take();
        pairing.running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

fn admit(state: &AppState) -> CommandResult<proto::PairDone> {
    let pairing = &state.pairing;
    // Admitting a device hands over every vault key: every domain must be
    // unlocked. The password domain is (the vault screen is open); the
    // others are opened here.
    for domain in [proto::Domain::Totp, proto::Domain::Passkey] {
        let status = state.status()?;
        let needs = status
            .domains
            .iter()
            .any(|entry| entry.domain == domain as i32 && entry.available && !entry.unlocked);
        if needs {
            state.unlock_hardware(domain)?;
        }
    }
    let done = pairing::admit(
        state.daemon.vault(),
        state.daemon.choice(),
        |offer: &ShownOffer| {
            pairing.set(PairProgress::Waiting {
                code: offer.code.clone(),
                qr: qr_data_url(&offer.code),
                lifetime_secs: offer.lifetime_secs,
                transports: offer.transports.clone(),
                problems: offer.problems.clone(),
            });
            Ok(())
        },
        |question| {
            if pairing.cancelled.load(Ordering::Relaxed) {
                return false;
            }
            let (sender, receiver) = mpsc::channel();
            *pairing.answer_slot() = Some(sender);
            pairing.set(PairProgress::Confirm {
                device_id: hex(&question.device_id),
                name: question.name.clone(),
            });
            receiver.recv_timeout(ANSWER_TIMEOUT).unwrap_or(false)
        },
    )?;
    Ok(done)
}

#[tauri::command]
pub(crate) fn pair_progress(state: tauri::State<'_, AppState>) -> PairProgress {
    state.pairing.get()
}

/// The user's answer: may the device join?
#[tauri::command]
pub(crate) fn pair_answer(state: tauri::State<'_, AppState>, approved: bool) {
    if let Some(sender) = state.pairing.answer_slot().take() {
        let _ = sender.send(approved);
    }
}

/// Stops showing the pairing. A device that already connected is refused;
/// the code itself runs out by itself.
#[tauri::command]
pub(crate) fn pair_cancel(state: tauri::State<'_, AppState>) {
    let pairing = &state.pairing;
    pairing.cancelled.store(true, Ordering::Relaxed);
    if let Some(sender) = pairing.answer_slot().take() {
        let _ = sender.send(false);
    }
    if pairing.running.load(Ordering::SeqCst) {
        pairing.set(PairProgress::Cancelled);
    } else {
        *pairing
            .progress
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = PairProgress::Idle;
    }
}

/// What joining a vault did.
#[derive(Serialize)]
pub(crate) struct Joined {
    vault_id: String,
    first_sync_error: String,
    sent: u64,
    received: u64,
}

/// On a device without a vault: joins the vault of the device that shows
/// `code`. Returns once the other device's user has confirmed (or refused).
#[tauri::command]
pub(crate) async fn join_vault(
    app: AppHandle,
    code: String,
    name: String,
    password: String,
) -> CommandResult<Joined> {
    let code = Zeroizing::new(code);
    let password = Zeroizing::new(password);
    blocking(app, move |state| {
        let name = name.trim();
        let name = if name.is_empty() {
            zp_client::default_device_name()
        } else {
            name.to_owned()
        };
        let joined = pairing::join(
            state.daemon.vault(),
            state.daemon.choice(),
            code.trim(),
            &name,
            &password,
        )?;
        Ok(Joined {
            vault_id: hex(&joined.vault_id),
            first_sync_error: joined.first_sync_error.clone(),
            sent: joined.sent,
            received: joined.received,
        })
    })
    .await
}

/// The name this device gives itself by default.
#[tauri::command]
pub(crate) fn default_device_name() -> String {
    zp_client::default_device_name()
}

/// Stops the local daemons and removes this device's local vault file so that
/// it can join a vault again with a fresh device identifier and new keys
/// (for example after this device was revoked from another device).
#[tauri::command]
pub(crate) async fn reset_local_vault(app: AppHandle) -> CommandResult<()> {
    blocking(app, |state| {
        let pairing = &state.pairing;
        pairing.cancelled.store(true, Ordering::Relaxed);
        if let Some(sender) = pairing.answer_slot().take() {
            let _ = sender.send(false);
        }
        if pairing.running.load(Ordering::SeqCst) {
            return Err(CommandError::client(
                "a pairing offer is still running; cancel it and wait until it finishes before resetting",
            ));
        }
        *pairing
            .progress
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = PairProgress::Idle;
        state.daemon.disconnect();
        state.sync_started.store(false, Ordering::SeqCst);
        zp_client::reset_local_vault(state.daemon.vault())?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_qr_code_is_an_svg_data_url_without_markup_characters() {
        let url = qr_data_url("ZP1:EXAMPLE-CODE");
        assert!(url.starts_with("data:image/svg+xml;utf8,"));
        assert!(url.contains("%3Csvg"));
        assert!(!url.contains(['<', '>', '"', '#']));
    }
}
