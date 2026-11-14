//! ZeroPass Vault Core Daemon (layer 1).
//!
//! The only process that opens the vault file with its keys. It has no network
//! access: it serves the other ZeroPass processes of the same user over a named
//! pipe or a Unix domain socket (`docs/spec/ipc.md`), and its dependency tree
//! must not contain a networking crate (ADR-0004).
//!
//! One daemon serves one vault file. Unlocked domains stay unlocked across
//! client connections until they are locked, time out, or the daemon stops.

mod convert;
mod pairing;
mod service;
mod sync;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;
use zp_ipc::{ClientPolicy, Endpoint, IpcError, Server};

use service::{KeyStoreChoice, Service, log};

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
}

/// How often idle domains are checked for their timeout.
const TICK: Duration = Duration::from_secs(1);

/// Exit code after an internal error (a panic).
const EXIT_PANIC: i32 = 101;

/// Exit code when another daemon already serves the vault.
const EXIT_ALREADY_RUNNING: u8 = 2;

fn run(args: Args) -> Result<(), IpcError> {
    let vault = std::path::absolute(&args.vault)?;
    let key_store = if args.insecure_software_keystore {
        KeyStoreChoice::InsecureSoftware
    } else if args.no_hardware_keystore {
        KeyStoreChoice::None
    } else {
        KeyStoreChoice::Platform
    };
    let endpoint = Endpoint::for_vault(&vault)?;
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

    let service = Arc::new(Service::new(vault, key_store));
    {
        // Dies with the process.
        let service = Arc::clone(&service);
        thread::spawn(move || {
            loop {
                thread::sleep(TICK);
                service.tick();
            }
        });
    }
    server.serve(Arc::clone(&service));
    service.lock_all();
    log("stopped");
    Ok(())
}

fn main() -> ExitCode {
    // Before anything else, and before any secret is in memory.
    let hardening = zp_sandbox::harden_process();
    // A panic must not end in a crash report with the process's memory in it:
    // say what happened and leave.
    std::panic::set_hook(Box::new(|info| {
        log(&format!("internal error: {info}"));
        std::process::exit(EXIT_PANIC);
    }));
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
