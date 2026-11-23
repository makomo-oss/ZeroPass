//! ZeroPass Vault Core Daemon (layer 1).
//!
//! The only process that opens the vault file with its keys. It has no network
//! access: it serves the other ZeroPass processes of the same user over a named
//! pipe or a Unix domain socket (`docs/spec/ipc.md`), and its dependency tree
//! must not contain a networking crate (ADR-0004).
//!
//! One daemon serves one vault file. Unlocked domains stay unlocked across
//! client connections until they are locked, time out, or the daemon stops.
//!
//! The daemon is this library's [`daemon_main`]. The same handling of the
//! requests also runs embedded in the vault process of the Android app
//! ([`embedded`], ADR-0012).

mod agent;
mod back;
mod bridge;
mod convert;
pub mod embedded;
mod front;
mod image;
mod pairing;
mod passkey;
mod port;
mod service;
mod sync;
mod wire;
mod worker;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;
use zp_crypto::DomainId;
use zp_ipc::{ClientPolicy, Endpoint, IpcError, Server};

use front::Front;
use service::{KeyStoreChoice, Scope, log};

#[derive(Parser)]
#[command(name = "zp-vaultd", version, about = "ZeroPass vault daemon")]
struct Args {
    /// Path of the vault file to serve. It does not need to exist yet.
    #[arg(long, env = "ZEROPASS_VAULT")]
    vault: PathBuf,

    /// DEVELOPMENT ONLY: protect the TOTP and passkey domains with a key stored in
    /// a file next to the vault instead of a hardware key store. No biometrics.
    #[arg(long)]
    insecure_software_keystore: bool,

    /// Do not use the platform's hardware key store (Windows Hello, ...). A vault
    /// created this way has no TOTP and passkey domains.
    #[arg(long, conflicts_with = "insecure_software_keystore")]
    no_hardware_keystore: bool,

    /// Used by the daemon itself: run as one of its other processes (ADR-0007),
    /// taking orders from standard input.
    #[arg(long, hide = true, value_parser = ["totp", "passkey", "whole"])]
    worker: Option<String>,
}

/// How often idle domains are checked for their timeout.
const TICK: Duration = Duration::from_secs(1);

/// Exit code after an internal error (a panic).
const EXIT_PANIC: i32 = 101;

/// Exit code when another daemon already serves the vault.
const EXIT_ALREADY_RUNNING: u8 = 2;

/// Dies with the process.
fn every_tick(tick: impl Fn() + Send + 'static) {
    thread::spawn(move || {
        loop {
            thread::sleep(TICK);
            tick();
        }
    });
}

/// One of the processes behind the one the clients talk to.
fn run_worker(vault: PathBuf, key_store: KeyStoreChoice, scope: Scope) -> Result<(), IpcError> {
    worker::run(vault, key_store, scope, std::io::stdin(), std::io::stdout())
        .map_err(|error| IpcError::Io(std::io::Error::other(error.message)))
}

fn run(args: Args) -> Result<(), IpcError> {
    let vault = std::path::absolute(&args.vault)?;
    let key_store = if args.insecure_software_keystore {
        KeyStoreChoice::InsecureSoftware
    } else if args.no_hardware_keystore {
        KeyStoreChoice::None
    } else {
        KeyStoreChoice::Platform
    };
    match args.worker.as_deref() {
        None => {}
        Some("totp") => return run_worker(vault, key_store, Scope::Domain(DomainId::Totp)),
        Some("passkey") => return run_worker(vault, key_store, Scope::Domain(DomainId::Passkey)),
        Some(_) => return run_worker(vault, key_store, Scope::Whole),
    }
    let endpoint = Endpoint::for_vault(&vault)?;
    // Started in the Linux sandbox: restrict this process now, before it reads
    // anything from a client (ipc.md §9.2). Its workers inherit it. Inside,
    // it cannot read which program a client runs: a helper started before
    // does that for it.
    #[cfg(target_os = "linux")]
    if zp_sandbox::is_requested() {
        zp_ipc::look_up_executables_through(&std::env::current_exe()?, &[EXECUTABLE_LOOKUPS])?;
    }
    let directory = endpoint.directory()?;
    let extra: Vec<(&std::path::Path, zp_sandbox::Access)> = directory
        .iter()
        .map(|directory| (directory.as_path(), zp_sandbox::Access::CreateFiles))
        .collect();
    match zp_sandbox::enter_requested(&extra) {
        Ok(Some(true)) | Ok(None) => {}
        Ok(Some(false)) => {
            log("warning: the kernel has no Landlock: files are not limited (the network is)")
        }
        // Asked to run sandboxed and cannot: do not run at all.
        Err(error) => return Err(IpcError::Io(error)),
    }
    let policy = ClientPolicy::beside_current_exe()?;
    let server = Server::bind(&endpoint, policy, env!("CARGO_PKG_VERSION"))?;

    if key_store == KeyStoreChoice::InsecureSoftware {
        log(
            "warning: using the INSECURE software key store; TOTP and passkey data are NOT protected by biometrics",
        );
    }
    log(&format!(
        "serving {} (domains: {}; sandbox: {})",
        vault.display(),
        service::domain_names(),
        if zp_sandbox::is_sandboxed() {
            "yes"
        } else {
            "no"
        }
    ));

    let front = Front::new(vault, key_store, std::env::current_exe()?)
        .map_err(|error| IpcError::Io(std::io::Error::other(error.message)))?;
    let front = Arc::new(front);
    {
        let front = Arc::clone(&front);
        every_tick(move || front.tick());
    }
    server.serve(Arc::clone(&front));
    // Ends the other processes, with their keys, before this one ends.
    front.stop();
    log("stopped");
    Ok(())
}

/// The command line of the helper that tells the sandboxed daemon which
/// programs its clients run (`zp_ipc::look_up_executables_through`).
#[cfg(target_os = "linux")]
const EXECUTABLE_LOOKUPS: &str = "--executable-lookups";

/// Runs the daemon with the command line of this process: what the
/// `zp-vaultd` executable does.
pub fn daemon_main() -> ExitCode {
    // Before anything else, and before any secret is in memory. The other
    // processes of the daemon (ADR-0007) hold keys too, and no client checks
    // them: they can hide from other programs further.
    let worker = std::env::args().any(|arg| arg == "--worker");
    let hardening = if worker {
        zp_sandbox::harden_worker_process()
    } else {
        zp_sandbox::harden_process()
    };
    // A panic must not end in a crash report with the process's memory in it:
    // say what happened and leave.
    std::panic::set_hook(Box::new(|info| {
        log(&format!("internal error: {info}"));
        std::process::exit(EXIT_PANIC);
    }));
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some(EXECUTABLE_LOOKUPS) {
        return match zp_ipc::serve_executable_lookups() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                log(&format!("executable lookups: {error}"));
                ExitCode::FAILURE
            }
        };
    }
    let args = Args::parse();
    for failure in hardening.failed() {
        log(&format!("warning: could not apply: {failure}"));
    }
    log(&format!("hardening: {}", hardening.applied().join("; ")));
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(IpcError::AlreadyRunning) => {
            log("a daemon is already running for this vault");
            ExitCode::from(EXIT_ALREADY_RUNNING)
        }
        Err(error) => {
            log(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_is_well_formed() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }
}
