//! Cryptographic primitives, secret types and key hierarchy for ZeroPass.
//!
//! The byte-level formats implemented here are specified in `docs/spec/crypto.md`.
//! This crate must never gain a networking dependency (see ADR-0004).

mod context;
mod device;
mod domain;
mod envelope;
mod error;
mod hardware;
mod kdf;
mod keywrap;
mod mem;
mod recovery_code;
pub mod rng;
mod secret;
mod signature_store;

pub use context::{DeviceId, ItemContext, ItemId, VaultId};
pub use device::{
    ChannelKey, DeviceSigningKey, PUBLIC_KEY_LEN, SIGNATURE_LEN, SignPublicKey, SignatureBytes,
};
pub use domain::{Domain, DomainId, Passkey, Password, Totp};
pub use envelope::{ENVELOPE_OVERHEAD, ENVELOPE_VERSION, NONCE_LEN, TAG_LEN};
pub use error::CryptoError;
pub use hardware::{HardwareBound, HardwareKeyError, HardwareKeyStore, InsecureSoftwareKeyStore};
pub use kdf::{KDF_SALT_LEN, KdfParams, derive_password_kek};
pub use keywrap::{RecoveryKey, WRAPPED_KEY_LEN};
pub use secret::{
    Generate, ItemKey, KEY_LEN, PasswordKek, RecoveryKek, Role, SecretKey, VaultKey, Wrap, role,
};
pub use signature_store::{SignatureKeyStore, UserVerifyingSigner};
