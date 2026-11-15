//! What every ZeroPass client does to reach the daemons of a vault.
//!
//! The vault daemon (`zp-vaultd`) holds the vault; the sync daemon
//! (`zp-syncd`) holds every connection to other devices. A client — the
//! command-line client, the desktop application, the browser bridge — has
//! neither the vault file nor a network connection. It asks the daemons over
//! the local IPC (`docs/spec/ipc.md`), and this crate is the part of that
//! which does not depend on how the client talks to its user:
//!
//! - [`vaultd`]: connecting to the vault daemon, and starting it (in its
//!   sandbox) when it is not running;
//! - [`syncd`]: the same for the sync daemon, and links to other devices
//!   through it;
//! - [`KeyAgent`]: the helper that reaches the platform's hardware key store
//!   for the vault daemon;
//! - [`pairing`]: carrying a pairing between the two daemons.
//!
//! This crate is part of the offline dependency set (ADR-0004): it must never
//! gain a networking dependency.

mod error;
pub mod import;
mod keyagent;
pub mod pairing;
pub mod syncd;
pub mod vaultd;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

pub use error::{Error, Result};
pub use keyagent::KeyAgent;
pub use zp_vault::default_device_name;

/// Which key store protects the TOTP and passkey domains of a vault the
/// daemon creates or opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyStoreChoice {
    /// The platform's hardware key store, if this device has one.
    #[default]
    Platform,
    /// None: password domain only.
    None,
    /// The development-only software key store, kept in a file beside the
    /// vault. No biometrics.
    InsecureSoftware,
}

/// Set by [`set_windowed`].
static WINDOWED: AtomicBool = AtomicBool::new(false);

/// Tells this crate that this process has no console (a windowed
/// application): the console programs it starts must not open console
/// windows, and what they report is collected instead of shown.
pub fn set_windowed() {
    WINDOWED.store(true, Ordering::Relaxed);
}

pub(crate) fn is_windowed() -> bool {
    WINDOWED.load(Ordering::Relaxed)
}

/// The development-only key file of the software key store, beside `vault`.
pub fn dev_key_path(vault: &std::path::Path) -> PathBuf {
    vault.with_extension("devkey")
}

/// Where this user's vault is kept when no other is named (ADR-0008): a
/// directory of its own, because the vault daemon's sandbox is given access to
/// the whole directory (`docs/spec/ipc.md` §9.1). The directory is created.
///
/// Every client must find the vault at the same path, spelled the same way:
/// the daemons' endpoints are derived from it.
pub fn default_vault_path() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(|dir| PathBuf::from(dir).join("ZeroPass"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support/ZeroPass"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
            })
            .map(|data| data.join("zeropass"))
    };
    let directory = base
        .ok_or_else(|| {
            Error::message(
                "cannot tell where this user's files go: pass --vault <PATH> or set ZEROPASS_VAULT",
            )
        })?
        .join("Vault");
    std::fs::create_dir_all(&directory).map_err(|error| {
        Error::message(format!("cannot create {}: {error}", directory.display()))
    })?;
    Ok(directory.join("vault.zpvault"))
}

/// The vault this client works with: `ZEROPASS_VAULT` if it is set, otherwise
/// [`default_vault_path`]. For clients without a command line of their own.
pub fn vault_path_from_environment() -> Result<PathBuf> {
    match std::env::var_os("ZEROPASS_VAULT") {
        Some(path) if !path.is_empty() => Ok(PathBuf::from(path)),
        _ => default_vault_path(),
    }
}

/// The executable `name` in the directory of this process's executable,
/// which is where every ZeroPass program is installed.
pub(crate) fn sibling(name: &str) -> Result<PathBuf> {
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    Ok(std::env::current_exe()?.with_file_name(file))
}
