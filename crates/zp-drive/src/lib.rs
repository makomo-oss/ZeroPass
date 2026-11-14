//! Runs the sync and pairing protocols over a byte stream.
//!
//! The protocols are state machines without I/O (`zp-sync`, `zp-pairing`).
//! The drivers in this crate move bytes between them and a [`Link`], which is
//! any reliable, ordered byte stream to one peer: a TCP connection, a
//! Bluetooth LE link, a pair of in-memory queues, or the local IPC to the
//! process that holds the real connection.
//!
//! Nothing here opens a connection to another device. That is what
//! `zp-transport` does; the vault daemon, which must stay offline, uses this
//! crate without it.

pub mod driver;
mod error;
pub mod link;

pub use driver::{
    Admitted, DriveConfig, Joined, NewVault, PairingLink, pair_as_existing, pair_as_new,
    sync_as_initiator, sync_as_responder,
};
pub use error::DriveError;
pub use link::{ChannelReader, Connection, Link, MemoryLink, READ_POLL};
