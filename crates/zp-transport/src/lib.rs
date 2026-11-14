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
pub mod lan;
pub mod local_net;
pub mod multi;
mod resilient;
mod transport;

// The drivers and the link they run on live in `zp-drive`, which has no
// networking; they are re-exported here for the programs that use both.
pub use zp_drive::driver::{
    self, Admitted, DriveConfig, Joined, NewVault, PairingLink, pair_as_existing, pair_as_new,
    sync_as_initiator, sync_as_responder,
};
pub(crate) use zp_drive::link;
pub use zp_drive::{Connection, DriveError, Link, MemoryLink};

pub use lan::LanTransport;
pub use multi::{MultiTransport, Nearby, open_nearby};
pub use resilient::ResilientLan;
pub use transport::{Address, Discovered, LoopbackNetwork, LoopbackTransport, Transport};
