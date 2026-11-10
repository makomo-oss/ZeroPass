//! Encrypted vault storage, item model and TOTP engine for ZeroPass.
//!
//! The on-disk formats are specified in `docs/spec/crypto.md`. This crate must
//! never gain a networking dependency (see ADR-0004).

mod error;
pub mod model;
mod schema;
mod store;

pub use error::VaultError;
pub use schema::SCHEMA_VERSION;
pub use store::Store;
