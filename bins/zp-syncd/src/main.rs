//! ZeroPass proximity sync daemon (layer 4).
//!
//! The one ZeroPass process that talks to other devices: it keeps one vault in
//! sync with the devices of the vault nearby, on the local network or over
//! Bluetooth LE, and it holds the connections the user interface needs for
//! pairing. It is given as little as possible:
//!
//! - It does not open the vault file and is never given a vault key. It asks
//!   the vault daemon for the ciphertext to send and hands it the ciphertext
//!   it receives (`docs/spec/ipc.md` §10); the vault daemon verifies every op.
//! - For pairing it only relays bytes between the other device and the user
//!   interface, which passes them on to the vault daemon. It is given the tag
//!   of a pairing code, never the code: it could not take part in the pairing
//!   handshake even though it holds this device's channel key (§12).

mod relay;
mod service;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use zp_ipc::{Client, ClientPolicy, DaemonPolicy, Endpoint, IpcError, RemoteOpLog, Server};
use zp_transport::daemon::{DaemonConfig, Event, SyncDaemon};
use zp_transport::open_nearby;

use service::{Command, Service, Status};

#[derive(Parser)]
#[command(name = "zp-syncd", version, about = "ZeroPass proximity sync daemon")]
struct Args {
    /// Path of the vault file to keep in sync. Its vault daemon must be
    /// running; this program waits for it.
    #[arg(long, env = "ZEROPASS_VAULT")]
    vault: PathBuf,

    /// How often to ask a nearby device for changes, in seconds.
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,
}

/// How long to wait before trying again after the vault daemon or the network
/// went away.
const RETRY: Duration = Duration::from_secs(5);

/// Exit code when another sync daemon already serves the vault.
const EXIT_ALREADY_RUNNING: u8 = 2;

/// Exit code after an internal error (a panic).
const EXIT_PANIC: i32 = 101;

pub(crate) fn log(message: &str) {
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

/// Connects to the vault daemon, opens the transports and runs the sync loop
/// until either fails. Commands from the user interface are taken in between
/// steps.
fn run(args: &Args, service: &Service, commands: &Receiver<Command>) -> Result<(), String> {
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
    service.set_status(Status {
        syncing: true,
        not_syncing_because: String::new(),
        lan_endpoints: nearby
            .lan_endpoints
            .iter()
            .map(ToString::to_string)
            .collect(),
        transports: nearby
            .transport
            .names()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        problems: nearby.problems.clone(),
    });
    let config = DaemonConfig {
        poll_interval: Duration::from_secs(args.poll_secs.max(1)),
        ..DaemonConfig::default()
    };
    let mut daemon = SyncDaemon::new(store, nearby.transport, config);
    let mut requests = service::Requests::default();
    loop {
        requests.take(&mut daemon, commands);
        let events = daemon.step().map_err(|error| error.to_string())?;
        for event in &events {
            report(event);
        }
        requests.progress(&mut daemon, &events, Instant::now());
    }
}

/// Runs the sync loop for as long as the process lives, starting over when the
/// vault daemon or the network comes back.
fn sync_forever(args: &Args, service: &Service, commands: &Receiver<Command>) {
    let mut last = String::new();
    loop {
        if let Err(error) = run(args, service, commands) {
            // Say it once, not every few seconds.
            if error != last {
                log(&format!("{error}; retrying every {}s", RETRY.as_secs()));
                last.clone_from(&error);
            }
            service.set_status(Status {
                syncing: false,
                not_syncing_because: error,
                ..Status::default()
            });
        }
        // Meanwhile, tell whoever asks that nothing can be done.
        let until = Instant::now() + RETRY;
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match commands.recv_timeout(left) {
                Ok(command) => service.refuse(command),
                Err(_) => break,
            }
        }
    }
}

fn main() -> ExitCode {
    // This process holds the channel key and talks to the network: make it
    // hard to read and to tamper with (docs/spec/hardening.md).
    for failure in zp_sandbox::harden_network_process().failed() {
        log(&format!("warning: could not apply: {failure}"));
    }
    // A panic must not end in a crash report with the process's memory in it.
    std::panic::set_hook(Box::new(|info| {
        log(&format!("internal error: {info}"));
        std::process::exit(EXIT_PANIC);
    }));
    let args = Args::parse();

    let endpoint = match Endpoint::for_sync_daemon(&args.vault) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            log(&format!("error: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let policy = match ClientPolicy::beside_current_exe() {
        Ok(policy) => policy,
        Err(error) => {
            log(&format!("error: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let server = match Server::bind(&endpoint, policy, env!("CARGO_PKG_VERSION")) {
        Ok(server) => server,
        Err(IpcError::AlreadyRunning) => {
            log("a sync daemon is already running for this vault");
            return ExitCode::from(EXIT_ALREADY_RUNNING);
        }
        Err(error) => {
            log(&format!("error: {error}"));
            return ExitCode::FAILURE;
        }
    };

    let (commands_in, commands) = mpsc::channel();
    let service = Arc::new(Service::new(commands_in));
    {
        let service = Arc::clone(&service);
        // Dies with the process.
        thread::spawn(move || sync_forever(&args, &service, &commands));
    }
    server.serve(service);
    log("stopped");
    ExitCode::SUCCESS
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
