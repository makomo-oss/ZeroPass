//! Device pairing and Noise secure channels for ZeroPass.
//!
//! Specified in `docs/spec/pairing.md`. Like `zp-sync`, everything here is a
//! state machine without I/O (ADR-0005): callers move the bytes.

mod error;
pub mod flow;
pub mod noise;
pub mod qr;

pub use error::PairingError;
pub use flow::{Asking, JoinRequest, Joiner, admit, answer, keys_request, take_keys};
pub use noise::{ChannelPublicKey, Handshake, Opening, SecureChannel};
pub use qr::{Hint, OfferRole, PairingOffer};
