//! Cryptographic primitives, secret types and key hierarchy for ZeroPass.
//!
//! The byte-level formats implemented here are specified in `docs/spec/crypto.md`.
//! This crate must never gain a networking dependency (see ADR-0004).

mod context;
mod domain;
mod envelope;
mod error;
mod mem;
pub mod rng;
mod secret;

pub use context::{DeviceId, ItemContext, ItemId, VaultId};
pub use domain::{Domain, DomainId, Passkey, Password, Totp};
pub use envelope::{ENVELOPE_OVERHEAD, ENVELOPE_VERSION, NONCE_LEN, TAG_LEN};
pub use error::CryptoError;
pub use secret::{Generate, ItemKey, KEY_LEN, Role, SecretKey, VaultKey, WrappingKey, role};
