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
mod peer;
pub mod proto;
mod server;
mod sys;

pub use client::Client;
pub use codec::MAX_FRAME;
pub use endpoint::Endpoint;
pub use error::IpcError;
pub use peer::{ClientPolicy, DAEMON_NAME, DaemonPolicy, Peer, PeerProcess};
pub use server::{Handler, Server, ShutdownHandle};

/// Starts `command` as a background process that outlives this one: no console,
/// no standard streams, and none of this process's open handles.
///
/// This is how a client starts the daemon when it is not running.
pub fn spawn_detached(command: &mut std::process::Command) -> std::io::Result<()> {
    sys::spawn_detached(command)
}
