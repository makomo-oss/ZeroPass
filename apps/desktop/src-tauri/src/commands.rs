//! The commands the page may call (`invoke`). Each runs on a worker thread.
//!
//! Secrets cross from the page to here only as the user types them (master
//! password, a new item's password), and from here to the page only when the
//! user asks to see one.

use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;
use zp_client::vaultd::Start;
use zp_ipc::proto::{self, request, response};

use crate::AppState;
use crate::error::{CommandError, CommandResult, domain_name};

/// Runs `job` on a worker thread with the application's state.
pub(crate) async fn blocking<T: Send + 'static>(
    app: AppHandle,
    job: impl FnOnce(&AppState) -> CommandResult<T> + Send + 'static,
) -> CommandResult<T> {
    tauri::async_runtime::spawn_blocking(move || job(&app.state::<AppState>()))
        .await
        .map_err(|error| CommandError::client(format!("internal error: {error}")))?
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unexpected() -> CommandError {
    CommandError::client("the vault daemon gave an unexpected answer")
}

/// A domain named by the page.
pub(crate) fn parse_domain(name: &str) -> CommandResult<proto::Domain> {
    match name {
        "password" => Ok(proto::Domain::Password),
        "totp" => Ok(proto::Domain::Totp),
        "passkey" => Ok(proto::Domain::Passkey),
        _ => Err(CommandError::client(format!("unknown domain {name:?}"))),
    }
}

/// What the page shows about the application itself.
#[derive(Serialize)]
pub(crate) struct AppInfo {
    version: &'static str,
    vault_path: String,
}

#[tauri::command]
pub(crate) fn app_info(state: tauri::State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        vault_path: state.daemon.vault().display().to_string(),
    }
}

/// The state of one key domain.
#[derive(Serialize)]
pub(crate) struct DomainState {
    name: &'static str,
    available: bool,
    unlocked: bool,
    /// For a domain this device does not have: other devices seem to have it.
    elsewhere: bool,
}

/// The state of the vault.
#[derive(Serialize)]
pub(crate) struct Status {
    exists: bool,
    vault_id: String,
    device_id: String,
    domains: Vec<DomainState>,
    has_recovery_kit: bool,
    sandboxed: bool,
}

impl From<proto::StatusReply> for Status {
    fn from(status: proto::StatusReply) -> Self {
        Self {
            exists: status.vault_exists,
            vault_id: hex(&status.vault_id),
            device_id: hex(&status.device_id),
            domains: status
                .domains
                .iter()
                .filter_map(|state| {
                    let domain = proto::Domain::try_from(state.domain).ok()?;
                    Some(DomainState {
                        name: domain_name(domain)?,
                        available: state.available,
                        unlocked: state.unlocked,
                        elsewhere: state.elsewhere,
                    })
                })
                .collect(),
            has_recovery_kit: status.has_recovery_kit,
            sandboxed: status.sandboxed,
        }
    }
}

fn status_of(reply: response::Body) -> CommandResult<Status> {
    match reply {
        response::Body::Status(status) => Ok(status.into()),
        _ => Err(unexpected()),
    }
}

/// The state of the vault. Without a vault file nothing is started.
#[tauri::command]
pub(crate) async fn status(app: AppHandle) -> CommandResult<Status> {
    blocking(app, |state| {
        if !state.daemon.vault().exists() {
            return Ok(Status {
                exists: false,
                vault_id: String::new(),
                device_id: String::new(),
                domains: Vec::new(),
                has_recovery_kit: false,
                sandboxed: false,
            });
        }
        let status = status_of(state.daemon.call(request::Body::Status(proto::Status {}))?)?;
        state.ensure_sync_daemon();
        Ok(status)
    })
    .await
}

/// Creates the vault, protected by `password`. With a hardware key store the
/// TOTP and passkey domains are bound to it (Windows Hello asks twice). The
/// vault stays unlocked: the next step is the recovery kit.
///
/// Without Windows Hello the daemon refuses (`HardwareUnavailable`) unless
/// `without_hardware`: the user chose a vault without one-time codes and
/// passkeys on this device for now (ADR-0011).
#[tauri::command]
pub(crate) async fn create_vault(
    app: AppHandle,
    password: String,
    without_hardware: bool,
) -> CommandResult<Status> {
    let password = Zeroizing::new(password);
    blocking(app, move |state| {
        if state.daemon.vault().exists() {
            return Err(CommandError::client("a vault already exists"));
        }
        let create = request::Body::CreateVault(proto::CreateVault {
            master_password: password.as_str().to_owned(),
            without_hardware,
        });
        status_of(state.daemon.call_with_key_agent(Start::Always, create)?)
    })
    .await
}

/// Unlocks a domain: the password domain with the master password, the
/// others with Windows Hello.
#[tauri::command]
pub(crate) async fn unlock(
    app: AppHandle,
    domain: String,
    password: Option<String>,
) -> CommandResult<()> {
    let password = Zeroizing::new(password.unwrap_or_default());
    let domain = parse_domain(&domain)?;
    blocking(app, move |state| {
        let unlock = request::Body::Unlock(proto::Unlock {
            domain: domain as i32,
            master_password: password.as_str().to_owned(),
        });
        if domain == proto::Domain::Password {
            state.daemon.call(unlock)?;
        } else {
            state
                .daemon
                .call_with_key_agent(Start::IfVaultExists, unlock)?;
        }
        Ok(())
    })
    .await
}

/// Locks one domain, or all of them.
#[tauri::command]
pub(crate) async fn lock(app: AppHandle, domain: Option<String>) -> CommandResult<()> {
    let domain = domain.as_deref().map(parse_domain).transpose()?;
    blocking(app, move |state| {
        state.daemon.call(request::Body::Lock(proto::Lock {
            domain: domain.map(|domain| domain as i32),
        }))?;
        Ok(())
    })
    .await
}

/// The page has drawn its first screen. Measures the start-up time; with
/// `--startup-time <FILE>` writes it there and ends the application.
#[tauri::command]
pub(crate) fn ui_ready(app: AppHandle, state: tauri::State<'_, AppState>) -> CommandResult<()> {
    let elapsed = state.started.elapsed();
    if let Some(report) = &state.startup_report {
        std::fs::write(report, format!("{}\n", elapsed.as_millis()))
            .map_err(|error| CommandError::client(error.to_string()))?;
        app.exit(0);
    }
    Ok(())
}
