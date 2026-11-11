//! Device pairing and Noise secure channels for ZeroPass.
//!
//! Specified in `docs/spec/pairing.md`. Like `zp-sync`, everything here is a
//! state machine without I/O (ADR-0005): callers move the bytes.

mod error;
pub mod noise;

pub use error::PairingError;
pub use noise::{ChannelPublicKey, Handshake, SecureChannel};
