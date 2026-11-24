//! Local IPC protocol between ZeroPass processes.
//!
//! The vault daemon (`zp-vaultd`) is the only process that holds vault keys.
//! Everything else on the device — the command-line client, the desktop
//! application, the browser bridge, the agent broker, the sync daemon — asks it
//! over this protocol, which is specified in `docs/spec/ipc.md`:
//!
//! - the transport is a Windows named pipe or a Unix domain socket that only the
//!   same user can open; there is no network socket anywhere in this crate;
//! - the daemon checks which executable connects before it reads anything
//!   ([`ClientPolicy`]), and a client checks that it reached the daemon before it
//!   sends anything ([`DaemonPolicy`]);
//! - messages are Protocol Buffers ([`proto`]) in length-prefixed frames.
//!
//! This crate is part of the offline dependency set (ADR-0004): it must never
//! gain a networking dependency.

mod client;
mod codec;
mod endpoint;
mod error;
mod memory;
mod peer;
pub mod proto;
mod server;
mod sync;
mod sys;

pub use client::{Client, Downlink, Duplex, Uplink};
pub use codec::{MAX_FRAME, read_frame, write_frame};
pub use endpoint::{DAEMON_SANDBOX, Endpoint};
pub use error::IpcError;
pub use memory::{MemoryStream, memory_pair};
pub use peer::{
    ClientPolicy, DAEMON_NAME, DaemonPolicy, KEY_AGENT_NAME, Peer, PeerProcess, SYNC_DAEMON_NAME,
};
pub use server::{Handler, RelayEnd, Server, ShutdownHandle, StreamServer};
pub use sync::{RemoteOpLog, RemoteSyncError};

/// The executable of this process, in the form in which the executables of
/// connecting processes are reported and compared. On Windows this is not the
/// familiar path with a drive letter; use it for policies and messages, not
/// to start programs.
pub fn current_executable() -> std::io::Result<std::path::PathBuf> {
    sys::current_exe()
}

/// Waits until nothing listens on `endpoint` any more, for at most `timeout`.
/// Returns whether that happened.
///
/// A daemon answers `Shutdown` before it closes its endpoint; a client that
/// connects in between is cut off without an answer. Whoever stopped the
/// daemon waits here, so that what it does next finds the daemon gone.
pub fn wait_until_closed(endpoint: &Endpoint, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match sys::connect(endpoint) {
            Err(IpcError::NotRunning) => return true,
            // Still there, or going: connecting and closing at once is
            // harmless to a daemon (the conversation ends before Hello).
            _ if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => return false,
        }
    }
}

/// Starts `command` as a background process that outlives this one: no console,
/// no standard streams, and none of this process's open handles.
///
/// This is how a client starts the daemon when it is not running.
///
/// On Windows the program is an absolute path, and the command sets neither
/// environment variables nor a directory: the process gets this process's.
pub fn spawn_detached(command: &mut std::process::Command) -> std::io::Result<()> {
    sys::spawn_detached(command)
}

/// [`spawn_detached`], out of the job object this process is in if the job
/// allows it: a process started by a browser must outlive the browser's job.
#[cfg(windows)]
pub fn spawn_detached_out_of_job(command: &mut std::process::Command) -> std::io::Result<()> {
    sys::spawn_detached_out_of_job(command)
}

/// On Linux: from now on, has the executables of connecting processes
/// (`ipc.md` §3.1) looked up by a helper: `program` started with `args`,
/// which answers with [`serve_executable_lookups`]. A daemon that restricts
/// itself with Landlock starts it first: inside, it may not read the
/// `/proc/<pid>/exe` of the processes outside its sandbox (`ipc.md` §9.2).
#[cfg(target_os = "linux")]
pub fn look_up_executables_through(
    program: &std::path::Path,
    args: &[&str],
) -> std::io::Result<()> {
    sys::executables::start_helper(program, args)
}

/// The helper of [`look_up_executables_through`]: answers on standard output
/// the requests read from standard input, until it ends (the process that
/// started this one is gone).
#[cfg(target_os = "linux")]
pub fn serve_executable_lookups() -> std::io::Result<()> {
    sys::executables::serve(std::io::stdin().lock(), std::io::stdout().lock())
}
