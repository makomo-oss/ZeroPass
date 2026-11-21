//! The vault daemon (`docs/spec/ipc.md` §8): connecting to it, and starting it
//! in its sandbox when it is not running.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use zp_ipc::proto::{self, request};
use zp_ipc::{Client, DAEMON_NAME, DAEMON_SANDBOX, DaemonPolicy, Endpoint, IpcError};
use zp_sandbox::Access;
use zp_vault::VaultError;

use crate::{Error, KeyStoreChoice, Result, dev_key_path, sibling};

/// How long a daemon that was just started may take to listen.
const START_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`stop`] waits for a daemon to let go of its endpoint.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether to start the daemon when it is not running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// Start it only if the vault file exists: nothing else needs a daemon.
    IfVaultExists,
    /// Start it; the vault is about to be created.
    Always,
    /// Do not start it.
    Never,
}

/// Set by [`disable_sandbox`]: start the daemon as an ordinary process.
static NO_SANDBOX: AtomicBool = AtomicBool::new(false);

/// DEVELOPMENT ONLY: makes this process start the daemon as an ordinary
/// process from now on, instead of in a sandbox without network access.
pub fn disable_sandbox() {
    NO_SANDBOX.store(true, Ordering::Relaxed);
}

/// The name this process gives itself in the daemons' logs.
pub(crate) fn client_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "zeropass".to_owned())
}

/// Gives the daemon's sandbox access to what the daemon works with, and to
/// nothing else: its executable, the vault file, and the files it creates
/// beside the vault (the database's journal).
fn grant_to_sandbox(executable: &Path, vault: &Path) -> io::Result<()> {
    // Installed under Program Files, the user may not change the executable's
    // access rights, and need not: that directory lets every app container
    // read and run what it holds (ADR-0008). If the container really cannot
    // run it, starting the daemon says so.
    match zp_sandbox::allow(DAEMON_SANDBOX, executable, Access::ReadExecute) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        other => other?,
    }
    if let Some(directory) = vault.parent() {
        zp_sandbox::allow(DAEMON_SANDBOX, directory, Access::CreateFiles)?;
    }
    // Files that are already there are not covered by the grant on the
    // directory.
    let mut journal = vault.as_os_str().to_owned();
    journal.push("-journal");
    for existing in [
        vault.to_path_buf(),
        PathBuf::from(journal),
        dev_key_path(vault),
    ] {
        if existing.exists() {
            zp_sandbox::allow(DAEMON_SANDBOX, &existing, Access::Modify)?;
        }
    }
    Ok(())
}

/// Starts the daemon for `vault` as a background process: in a sandbox without
/// network access where the platform has one.
fn start_daemon(vault: &Path, choice: KeyStoreChoice) -> Result<()> {
    let executable = sibling(DAEMON_NAME)?;
    let vault = std::path::absolute(vault)?;
    let mut args: Vec<OsString> = vec!["--vault".into(), vault.clone().into()];
    match choice {
        KeyStoreChoice::Platform => {}
        KeyStoreChoice::None => args.push("--no-hardware-keystore".into()),
        KeyStoreChoice::InsecureSoftware => args.push("--insecure-software-keystore".into()),
    }
    let started = if zp_sandbox::SUPPORTED && !NO_SANDBOX.load(Ordering::Relaxed) {
        grant_to_sandbox(&executable, &vault)
            .and_then(|()| zp_sandbox::spawn(DAEMON_SANDBOX, &executable, &args))
            .map(drop)
    } else {
        zp_ipc::spawn_detached(Process::new(&executable).args(&args))
    };
    started.map_err(|error| {
        Error::message(format!(
            "cannot start the vault daemon ({}): {error}",
            executable.display()
        ))
    })
}

/// Connects to the daemon of `vault`, starting it if `start` says so.
/// `Ok(None)` means it is not running and was not to be started.
pub fn connect(vault: &Path, choice: KeyStoreChoice, start: Start) -> Result<Option<Client>> {
    let endpoint = Endpoint::for_vault(vault)?;
    let policy = DaemonPolicy::beside_current_exe()?;
    let name = client_name();
    let attempt = || Client::connect(&endpoint, &policy, &name);
    match attempt() {
        Ok(client) => return Ok(Some(client)),
        Err(IpcError::NotRunning) => {}
        Err(error) => return Err(error.into()),
    }
    match start {
        Start::Never => return Ok(None),
        Start::IfVaultExists if !vault.exists() => return Err(VaultError::NotFound.into()),
        Start::IfVaultExists => {}
        // The vault is about to be created: its folder must be there, for
        // the daemon's sandbox is given access to it.
        Start::Always => {
            if let Some(folder) = std::path::absolute(vault)?.parent() {
                std::fs::create_dir_all(folder).map_err(|error| {
                    Error::message(format!("cannot create {}: {error}", folder.display()))
                })?;
            }
        }
    }
    start_daemon(vault, choice)?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        thread::sleep(Duration::from_millis(20));
        match attempt() {
            Ok(client) => return Ok(Some(client)),
            Err(IpcError::NotRunning) if Instant::now() < deadline => {}
            Err(IpcError::NotRunning) => {
                return Err(Error::message("the vault daemon did not start"));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Connects to the daemon of `vault`, starting it if `start` says so; fails
/// if it is not running and was not to be started.
pub fn open(vault: &Path, choice: KeyStoreChoice, start: Start) -> Result<Client> {
    connect(vault, choice, start)?.ok_or_else(|| Error::message("the vault daemon is not running"))
}

/// Waits until the vault daemon of `vault`, just asked to shut down, has let go
/// of its endpoint: it answers before it does, and the next command must not
/// meet it on its way out.
pub fn wait_until_stopped(vault: &Path) -> Result<()> {
    zp_ipc::wait_until_closed(&Endpoint::for_vault(vault)?, STOP_TIMEOUT);
    Ok(())
}

/// Stops the vault daemon of `vault` if it is running. Returns whether it was.
pub fn stop(vault: &Path) -> Result<bool> {
    let Some(mut client) = connect(vault, KeyStoreChoice::None, Start::Never)? else {
        return Ok(false);
    };
    client.call(request::Body::Shutdown(proto::Shutdown {}))?;
    drop(client);
    wait_until_stopped(vault)?;
    Ok(true)
}
