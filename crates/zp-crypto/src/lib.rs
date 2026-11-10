//! Cryptographic primitives, secret types and key hierarchy for ZeroPass.
//!
//! The byte-level formats implemented here are specified in `docs/spec/crypto.md`.
//! This crate must never gain a networking dependency (see ADR-0004).

mod domain;
mod error;
mod mem;
pub mod rng;
mod secret;

pub use domain::{Domain, DomainId, Passkey, Password, Totp};
pub use error::CryptoError;
pub use secret::{Generate, ItemKey, KEY_LEN, Role, SecretKey, VaultKey, WrappingKey, role};
