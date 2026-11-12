//! Local-only transports for ZeroPass sync, and the drivers that run the
//! protocols over them.
//!
//! This is the only library crate that performs I/O towards other devices. It
//! never sends anything beyond the local link: see the individual transports.

pub mod ble;
#[cfg(windows)]
pub mod ble_windows;
pub mod capture;
pub mod daemon;
pub mod discovery;
pub mod driver;
mod error;
pub mod lan;
mod link;
pub mod local_net;
pub mod multi;
mod resilient;
mod transport;

pub use driver::{
    Admitted, DriveConfig, Joined, NewVault, PairingLink, pair_as_existing, pair_as_new,
    sync_as_initiator, sync_as_responder,
};
pub use error::DriveError;
pub use lan::LanTransport;
pub use link::{Connection, Link, MemoryLink};
pub use multi::{MultiTransport, Nearby, open_nearby};
pub use resilient::ResilientLan;
pub use transport::{Address, Discovered, LoopbackNetwork, LoopbackTransport, Transport};
