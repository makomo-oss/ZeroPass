//! ZeroPass proximity sync daemon (layer 4).
//!
//! Keeps one vault in sync with the other devices of the vault that are nearby,
//! on the local network or over Bluetooth LE. It is the process that talks to
//! the network, so it is given as little as possible: it does not open the
//! vault file, and it is never given a master password or a vault key. It asks
//! the vault daemon for the ciphertext to send and hands it the ciphertext it
//! receives (`docs/spec/ipc.md` §10); the vault daemon verifies every op
//! against the signatures of the vault's devices before storing it.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::Parser;
use zp_ipc::{Client, DaemonPolicy, Endpoint, RemoteOpLog};
use zp_transport::daemon::{DaemonConfig, Event, SyncDaemon};
use zp_transport::open_nearby;

#[derive(Parser)]
#[command(name = "zp-syncd", version, about = "ZeroPass proximity sync daemon")]
struct Args {
    /// Path of the vault file to keep in sync. The vault daemon of that file
    /// must be running; this program waits for it.
    #[arg(long, env = "ZEROPASS_VAULT")]
    vault: PathBuf,

    /// How often to ask a nearby device for changes, in seconds.
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,
}

/// How long to wait before trying again after the vault daemon or the network
/// went away.
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

/// Connects to the vault daemon and runs the sync loop until either the vault
/// daemon or the transport fails.
fn run(args: &Args) -> Result<(), String> {
    let endpoint = Endpoint::for_vault(&args.vault).map_err(|error| error.to_string())?;
    let policy = DaemonPolicy::beside_current_exe().map_err(|error| error.to_string())?;
    let client = Client::connect(&endpoint, &policy, "zp-syncd")
        .map_err(|error| format!("vault daemon: {error}"))?;
    // Fails with a clear message if there is no vault yet.
    let store = RemoteOpLog::new(client).map_err(|error| format!("vault daemon: {error}"))?;

    let nearby = open_nearby().map_err(|error| format!("no transport available: {error}"))?;
    log(&format!(
        "syncing {} over {} (local network endpoints: {:?})",
        args.vault.display(),
        nearby.transport.names().join(" and "),
        nearby.lan_endpoints
    ));
    for problem in &nearby.problems {
        log(&format!("not available: {problem}"));
    }
    let config = DaemonConfig {
        poll_interval: Duration::from_secs(args.poll_secs.max(1)),
        ..DaemonConfig::default()
    };
    let mut daemon = SyncDaemon::new(store, nearby.transport, config);
    loop {
        for event in daemon.step().map_err(|error| error.to_string())? {
            report(&event);
        }
    }
}

fn main() -> ExitCode {
    // This process holds the channel key and talks to the network: make it
    // hard to read and to tamper with (docs/spec/hardening.md).
    for failure in zp_sandbox::harden_process().failed() {
        log(&format!("warning: could not apply: {failure}"));
    }
    let args = Args::parse();
    // The vault daemon may start later or restart, and the network comes and
    // goes (Wi-Fi off, new address): start over whenever either is back.
    let mut last = String::new();
    loop {
        if let Err(error) = run(&args) {
            // Say it once, not every few seconds.
            if error != last {
                log(&format!("{error}; retrying every {}s", RETRY.as_secs()));
                last = error;
            }
        }
        thread::sleep(RETRY);
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
