//! ZeroPass proximity sync daemon (layer 4).
//!
//! Keeps one vault file in sync with the other devices of the vault that are on
//! the same local network. It works on the locked file: it is never given a
//! master password or a vault key, and handles only ciphertext and signatures.
//!
//! This is the minimal version of Phase 2. It opens the vault file itself; in
//! Phase 3 it will instead exchange ops with the vault daemon over local IPC.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::Parser;
use zp_transport::daemon::{DaemonConfig, Event, SyncDaemon};
use zp_transport::{DriveError, LanTransport};
use zp_vault::Store;

#[derive(Parser)]
#[command(name = "zp-syncd", version, about = "ZeroPass proximity sync daemon")]
struct Args {
    /// Path of the vault file to keep in sync.
    #[arg(long, env = "ZEROPASS_VAULT")]
    vault: PathBuf,

    /// How often to ask a nearby device for changes, in seconds.
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,
}

/// How long to wait before trying again after the network went away.
const RETRY: Duration = Duration::from_secs(5);

fn log(message: &str) {
    let _ = writeln!(io::stderr(), "zp-syncd: {message}");
}

fn report(event: &Event) {
    match event {
        Event::Synced {
            name,
            initiated,
            report,
            ..
        } => {
            // Only sessions that moved something are worth a line.
            if report.sent > 0 || report.received.applied > 0 || report.registry_changed {
                let direction = if *initiated {
                    "connected to"
                } else {
                    "answered"
                };
                log(&format!(
                    "{direction} \"{name}\": sent {} change(s), received {}",
                    report.sent, report.received.applied
                ));
            }
        }
        Event::Failed { error, .. } => log(&format!("sync attempt failed: {error}")),
    }
}

/// Runs the loop on one transport instance until the transport fails.
fn run(args: &Args) -> Result<(), DriveError> {
    let sync_error = |error: zp_vault::VaultError| DriveError::Sync(error.to_string());
    let store = Store::open(&args.vault).map_err(sync_error)?;
    // Fails early with a clear message if the vault has no device identity yet.
    store.channel_key().map_err(sync_error)?;
    let transport = LanTransport::new()?;
    log(&format!(
        "syncing {} on {:?}, port {}",
        args.vault.display(),
        transport.addresses(),
        transport.port()
    ));
    let config = DaemonConfig {
        poll_interval: Duration::from_secs(args.poll_secs.max(1)),
        ..DaemonConfig::default()
    };
    let mut daemon = SyncDaemon::new(store, transport, config);
    loop {
        for event in daemon.step()? {
            report(&event);
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    if !args.vault.exists() {
        log(&format!("no vault file at {}", args.vault.display()));
        return ExitCode::FAILURE;
    }
    loop {
        match run(&args) {
            // The network went away or changed (Wi-Fi off, new address): start
            // over with a fresh transport once it is back.
            Err(DriveError::Io(error)) => {
                log(&format!("local network unavailable ({error}); retrying"));
                thread::sleep(RETRY);
            }
            Err(error) => {
                log(&format!("{error}"));
                return ExitCode::FAILURE;
            }
            Ok(()) => return ExitCode::SUCCESS,
        }
    }
}
