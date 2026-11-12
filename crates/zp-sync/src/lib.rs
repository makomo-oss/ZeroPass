//! Transport-agnostic encrypted oplog synchronisation for ZeroPass.
//!
//! The protocol is specified in `docs/spec/sync.md`. Everything in this crate is
//! pure logic without I/O (ADR-0005): clocks, version vectors, ops, the device
//! registry, the merge rule and the session state machine. It must never gain a
//! networking dependency, because the vault crates depend on it (ADR-0004).

mod error;
mod frame;
pub mod hlc;
mod memory;
mod merge;
mod op;
mod registry;
mod rotation;
mod session;
mod vector;
mod wire;

pub use error::SyncError;
pub use frame::{FrameDecoder, encode_frame};
pub use hlc::Hlc;
pub use memory::{MemoryLog, Snapshot};
pub use merge::{ApplyReport, Incoming, OpLog, Placement, check_incoming, place};
pub use op::{Op, OpBody, Payload, Stamp};
pub use registry::{ChannelPublicKey, DeviceRecord, MAX_DEVICE_NAME_LEN, Registry, Revocation};
pub use rotation::{KeyUpdate, MAX_KEY_UPDATES};
pub use session::{InMemoryError, PROTOCOL_VERSION, Session, SessionReport, sync_in_memory};
pub use vector::VersionVector;
pub use wire::{MAX_MESSAGE_LEN, decode_registry, encode_registry};
