//! Import and encrypted export (P4-07, `docs/spec/export.md`).
//!
//! Files are chosen with the system's file dialogs and read and written here:
//! what another password manager exported (every password in the clear)
//! never reaches the page, which sees counts only. An encrypted export is
//! made and read by the vault daemon; this process only carries the sealed
//! file.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;
use zp_import::Imported;
use zp_ipc::proto::{self, request, response};

use crate::AppState;
use crate::commands::blocking;
use crate::error::{CommandError, CommandResult};

/// A file read and waiting for the user to confirm the import.
enum Pending {
    /// An encrypted ZeroPass export; its passphrase comes with the
    /// confirmation.
    ZeroPass(Zeroizing<Vec<u8>>),
    /// What another password manager exported.
    Other(Imported),
}

/// The file waiting to be imported, if any.
#[derive(Default)]
pub(crate) struct PendingImport(Mutex<Option<Pending>>);

impl PendingImport {
    fn slot(&self) -> MutexGuard<'_, Option<Pending>> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

fn dialog(app: &AppHandle) -> rfd::FileDialog {
    let dialog = rfd::FileDialog::new();
    match app.get_webview_window("main") {
        Some(window) => dialog.set_parent(&window),
        None => dialog,
    }
}

/// What a chosen file holds, before anything is added.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Preview {
    /// The user closed the dialog.
    Cancelled,
    /// An encrypted ZeroPass export: its passphrase is needed.
    Zeropass { file: String },
    /// Another password manager's export.
    Other {
        file: String,
        format: &'static str,
        logins: usize,
        notes: usize,
        totp: usize,
        skipped: usize,
    },
}

/// Lets the user choose a file to import and reads it.
#[tauri::command]
pub(crate) async fn import_choose(app: AppHandle) -> CommandResult<Preview> {
    let handle = app.clone();
    blocking(app, move |state| {
        let Some(path) = dialog(&handle)
            .set_title("Import into ZeroPass")
            .add_filter(
                "Exports (CSV, JSON, ZeroPass)",
                &["csv", "json", "zpexport"],
            )
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return Ok(Preview::Cancelled);
        };
        let file = file_name(&path);
        let data = Zeroizing::new(
            std::fs::read(&path)
                .map_err(|error| CommandError::client(format!("cannot read {file}: {error}")))?,
        );
        if data.starts_with(zp_vault::export::MAGIC) {
            *state.pending_import.slot() = Some(Pending::ZeroPass(data));
            return Ok(Preview::Zeropass { file });
        }
        let imported =
            zp_import::read(&data).map_err(|error| CommandError::client(error.to_string()))?;
        let preview = Preview::Other {
            file,
            format: imported.format.name(),
            logins: imported.logins.len(),
            notes: imported.notes.len(),
            totp: imported
                .logins
                .iter()
                .filter(|login| login.totp.is_some())
                .count(),
            skipped: imported.skipped,
        };
        *state.pending_import.slot() = Some(Pending::Other(imported));
        Ok(preview)
    })
    .await
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// What an import added.
#[derive(Serialize)]
pub(crate) struct ImportResult {
    logins: usize,
    notes: usize,
    totp: usize,
    passkeys: usize,
    failures: Vec<String>,
}

/// Adds the items of the file read by [`import_choose`]. `passphrase` opens
/// an encrypted ZeroPass export.
#[tauri::command]
pub(crate) async fn import_confirm(
    app: AppHandle,
    passphrase: Option<String>,
) -> CommandResult<ImportResult> {
    let passphrase = Zeroizing::new(passphrase.unwrap_or_default());
    blocking(app, move |state| {
        let pending = state
            .pending_import
            .slot()
            .take()
            .ok_or_else(|| CommandError::client("choose a file first"))?;
        match pending {
            Pending::ZeroPass(data) => {
                let request = request::Body::ImportExport(proto::ImportExport {
                    data: data.to_vec(),
                    passphrase: passphrase.as_str().to_owned(),
                });
                let outcome = state.call_unlocking(request);
                if outcome.is_err() {
                    // Let the user try another passphrase.
                    *state.pending_import.slot() = Some(Pending::ZeroPass(data));
                }
                let response::Body::ImportedItems(imported) = outcome? else {
                    return Err(CommandError::client(
                        "the vault daemon gave an unexpected answer",
                    ));
                };
                let counts = imported.counts.unwrap_or_default();
                Ok(ImportResult {
                    logins: counts.logins as usize,
                    notes: counts.notes as usize,
                    totp: counts.totp as usize,
                    passkeys: counts.passkeys as usize,
                    failures: Vec::new(),
                })
            }
            Pending::Other(imported) => {
                let added = zp_client::import::add_imported(&imported, |body| {
                    state
                        .call_unlocking(body)
                        .map_err(|error| zp_client::Error::message(error.to_string()))
                })?;
                Ok(ImportResult {
                    logins: added.logins,
                    notes: added.notes,
                    totp: added.totp,
                    passkeys: 0,
                    failures: added.failures,
                })
            }
        }
    })
    .await
}

/// Forgets the file read by [`import_choose`].
#[tauri::command]
pub(crate) fn import_cancel(state: tauri::State<'_, AppState>) {
    state.pending_import.slot().take();
}

/// What an export wrote.
#[derive(Serialize)]
pub(crate) struct ExportResult {
    /// Where; `None` if the user closed the dialog.
    path: Option<String>,
    logins: u32,
    notes: u32,
    totp: u32,
    passkeys: u32,
}

/// Writes an encrypted export of the whole vault where the user chooses.
/// Every domain is unlocked first (Windows Hello may ask).
#[tauri::command]
pub(crate) async fn export_vault(
    app: AppHandle,
    passphrase: String,
) -> CommandResult<ExportResult> {
    let passphrase = Zeroizing::new(passphrase);
    let handle = app.clone();
    blocking(app, move |state| {
        let today = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() / 86_400);
        let Some(path): Option<PathBuf> = dialog(&handle)
            .set_title("Export the vault")
            .set_file_name(format!("zeropass-{today}.zpexport"))
            .add_filter("ZeroPass export", &["zpexport"])
            .save_file()
        else {
            return Ok(ExportResult {
                path: None,
                logins: 0,
                notes: 0,
                totp: 0,
                passkeys: 0,
            });
        };
        let request = request::Body::ExportVault(proto::ExportVault {
            passphrase: passphrase.as_str().to_owned(),
        });
        let response::Body::Exported(exported) = state.call_unlocking(request)? else {
            return Err(CommandError::client(
                "the vault daemon gave an unexpected answer",
            ));
        };
        std::fs::write(&path, &exported.data).map_err(|error| {
            CommandError::client(format!("cannot write {}: {error}", path.display()))
        })?;
        let counts = exported.counts.unwrap_or_default();
        Ok(ExportResult {
            path: Some(path.display().to_string()),
            logins: counts.logins,
            notes: counts.notes,
            totp: counts.totp,
            passkeys: counts.passkeys,
        })
    })
    .await
}
