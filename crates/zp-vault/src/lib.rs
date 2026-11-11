//! Encrypted vault storage, item model and TOTP engine for ZeroPass.
//!
//! The on-disk formats are specified in `docs/spec/crypto.md`. This crate must
//! never gain a networking dependency (see ADR-0004).

mod clock;
mod device;
mod error;
mod items;
mod keyslots;
pub mod model;
mod recovery;
mod schema;
mod store;
pub mod totp;
mod vault;

pub use clock::Clock;
pub use device::default_device_name;
pub use error::VaultError;
pub use items::HistoryEntry;
pub use schema::SCHEMA_VERSION;
pub use store::Store;
pub use vault::{
    AutoLock, CreateOptions, KdfChoice, MIN_MASTER_PASSWORD_CHARS, Vault, is_user_cancelled,
};
