//! Transport-agnostic encrypted oplog synchronisation for ZeroPass.
//!
//! The protocol is specified in `docs/spec/sync.md`. Everything in this crate is
//! pure logic without I/O (ADR-0005): clocks, version vectors, the merge rule and
//! the session state machine. It must never gain a networking dependency, because
//! the vault crates depend on it (ADR-0004).

pub mod hlc;
mod vector;

pub use hlc::Hlc;
pub use vector::VersionVector;
