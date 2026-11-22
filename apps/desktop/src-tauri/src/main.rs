//! ZeroPass desktop application.
//!
//! A window onto the vault, which the vault daemon holds: this program asks the
//! daemon over the local IPC (`docs/spec/ipc.md`) as the command-line client
//! does, with the same role (UI), and has no network connection of its own.
//! The page in the window is the application's own, embedded at compile time;
//! it may not load anything else, navigate away, or open windows
//! (`docs/adr/0009-desktop-application.md`).

#![cfg_attr(windows, windows_subsystem = "windows")]

mod clipboard;
mod commands;
mod daemon;
mod devices;
mod error;
mod generator;
mod items;
mod transfer;

use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use tauri::webview::NewWindowResponse;
use tauri::{Url, WebviewWindowBuilder};
use zp_client::KeyStoreChoice;

use daemon::Daemon;

#[derive(Parser)]
#[command(name = "zeropass", version, about = "ZeroPass desktop application")]
struct Args {
    /// Path of the vault file. Without it, the vault in this user's ZeroPass
    /// directory (on Windows `%LOCALAPPDATA%\ZeroPass\Vault\vault.zpvault`).
    #[arg(long, env = "ZEROPASS_VAULT")]
    vault: Option<PathBuf>,

    /// DEVELOPMENT ONLY: protect the TOTP and passkey domains with a key stored
    /// in a file next to the vault instead of a hardware key store.
    #[arg(long)]
    insecure_software_keystore: bool,

    /// Do not use the platform's hardware key store. A vault created this way
    /// has no TOTP and passkey domains.
    #[arg(long, conflicts_with = "insecure_software_keystore")]
    no_hardware_keystore: bool,

    /// DEVELOPMENT ONLY: start the vault daemon as an ordinary process instead
    /// of in a sandbox without network access.
    #[arg(long)]
    no_sandbox: bool,

    /// Measure the start-up time: write the milliseconds from the start of the
    /// process until the first screen is drawn to FILE, then exit.
    #[arg(long, value_name = "FILE")]
    startup_time: Option<PathBuf>,
}

/// What every command can reach.
pub(crate) struct AppState {
    pub(crate) daemon: Daemon,
    /// When this process started.
    pub(crate) started: Instant,
    /// Where to report the start-up time, if it is being measured.
    pub(crate) startup_report: Option<PathBuf>,
    /// Whether this application has made sure the sync daemon runs.
    pub(crate) sync_started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A file read for import, waiting for the user to confirm.
    pub(crate) pending_import: transfer::PendingImport,
    /// The pairing this device offers, if any.
    pub(crate) pairing: devices::Pairing,
}

/// Whether the page may navigate to `url`: only to the application's own
/// pages. Everything else stays where it is, and nothing is opened outside.
fn own_page(url: &Url) -> bool {
    match url.scheme() {
        // macOS and Linux serve the embedded files on this scheme.
        "tauri" => url.host_str() == Some("localhost"),
        // Windows serves them on this host.
        "http" | "https" => url.host_str() == Some("tauri.localhost"),
        _ => false,
    }
}

/// DEVELOPMENT BUILDS ONLY: with `ZEROPASS_E2E_CDP_PORT`, opens the webview's
/// debugging port for the end-to-end tests (`apps/desktop/e2e`). Some
/// versions of WebView2 do not take the port from their own environment
/// variable; this passes it as the application's argument to the webview.
/// Not compiled into release builds.
#[cfg(all(debug_assertions, windows))]
fn end_to_end_port<R: tauri::Runtime, M: tauri::Manager<R>>(
    builder: WebviewWindowBuilder<'_, R, M>,
) -> WebviewWindowBuilder<'_, R, M> {
    match std::env::var("ZEROPASS_E2E_CDP_PORT")
        .ok()
        .and_then(|port| port.parse::<u16>().ok())
    {
        // wry's own arguments are replaced: they are repeated here.
        Some(port) => builder.additional_browser_args(&format!(
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --remote-debugging-port={port}"
        )),
        None => builder,
    }
}

fn main() {
    let started = Instant::now();
    let args = Args::parse();
    // This program has no console; what it starts must not open one.
    zp_client::set_windowed();
    if args.no_sandbox {
        zp_client::vaultd::disable_sandbox();
    }
    let choice = if args.insecure_software_keystore {
        KeyStoreChoice::InsecureSoftware
    } else if args.no_hardware_keystore {
        KeyStoreChoice::None
    } else {
        KeyStoreChoice::Platform
    };
    let vault = match args.vault {
        Some(path) => Ok(path),
        None => zp_client::default_vault_path(),
    };
    let vault = match vault {
        Ok(vault) => vault,
        Err(error) => {
            // Without a console there is nowhere else to say it.
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                format!("zeropass: {error}\n").as_bytes(),
            );
            std::process::exit(1);
        }
    };
    let state = AppState {
        daemon: Daemon::new(vault, choice),
        started,
        startup_report: args.startup_time,
        sync_started: std::sync::Arc::default(),
        pairing: devices::Pairing::default(),
        pending_import: transfer::PendingImport::default(),
    };

    let built = tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::status,
            commands::create_vault,
            commands::set_up_domain,
            commands::unlock,
            commands::lock,
            commands::ui_ready,
            items::list_items,
            items::get_item,
            items::reveal_password,
            items::copy,
            items::copy_text,
            items::add_login,
            items::update_login,
            items::add_note,
            items::update_note,
            items::add_totp,
            items::delete_item,
            items::totp_code,
            items::generate_password,
            items::create_recovery_kit,
            items::change_master_password,
            devices::list_devices,
            devices::revoke_device,
            devices::sync_status,
            devices::sync_now,
            devices::pair_start,
            devices::pair_progress,
            devices::pair_answer,
            devices::pair_cancel,
            devices::join_vault,
            devices::receive_keys,
            devices::default_device_name,
            transfer::import_choose,
            transfer::import_confirm,
            transfer::import_cancel,
            transfer::export_vault,
        ])
        .setup(|app| {
            let config = app
                .config()
                .app
                .windows
                .first()
                .ok_or("the configuration has no window")?
                .clone();
            let builder = WebviewWindowBuilder::from_config(app.handle(), &config)?
                .on_navigation(own_page)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .on_download(|_, _| false)
                // Nothing the page does is kept on disk by the webview.
                .incognito(true)
                .devtools(cfg!(debug_assertions));
            #[cfg(all(debug_assertions, windows))]
            let builder = end_to_end_port(builder);
            builder.build()?;
            Ok(())
        })
        .build(tauri::generate_context!());
    match built {
        Ok(app) => app.run(|_, event| {
            if let tauri::RunEvent::Exit = event {
                // A secret copied a moment ago must not outlive the
                // application on the clipboard.
                clipboard::clear_now();
            }
        }),
        Err(error) => {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                format!("zeropass: {error}\n").as_bytes(),
            );
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_applications_own_pages_are_reachable() {
        for allowed in [
            "tauri://localhost/",
            "tauri://localhost/index.html",
            "http://tauri.localhost/",
            "https://tauri.localhost/index.html",
        ] {
            assert!(own_page(&Url::parse(allowed).unwrap()), "{allowed}");
        }
        for denied in [
            "https://example.com/",
            "http://localhost:5173/",
            "http://tauri.localhost.example.com/",
            "tauri://evil/",
            "file:///C:/Windows/",
            "javascript:alert(1)",
            "data:text/html,hi",
        ] {
            assert!(!own_page(&Url::parse(denied).unwrap()), "{denied}");
        }
    }

    #[test]
    fn command_line_is_well_formed() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }
}
