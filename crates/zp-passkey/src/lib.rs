//! OS-independent WebAuthn passkey authenticator engine for ZeroPass
//! (ADR-0010, `docs/spec/passkey.md`).
//!
//! Passkeys are items of the vault's passkey domain: their private keys are
//! encrypted under VK-K and decrypted only by the process that holds that
//! domain, the vault daemon's passkey worker (ADR-0007). This crate makes the
//! credentials, keeps them in the vault and signs with them.

mod cbor;
pub mod credential;
pub mod key;

pub use credential::{Account, find, key_of, new_credential, save};
pub use key::{Algorithm, CredentialKey, PublicKey};

use zp_vault::VaultError;

/// What went wrong with a passkey.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    /// The operating system's random number generator failed.
    #[error("the operating system's random number generator failed")]
    Random,
    /// A key is malformed, or not of the algorithm it is said to be.
    #[error("a passkey's key is malformed or of another algorithm")]
    MalformedKey,
    /// None of the algorithms the relying party accepts is supported.
    #[error(
        "none of the relying party's algorithms is supported (ZeroPass makes ES256 and EdDSA keys)"
    )]
    UnsupportedAlgorithm,
    /// A request is malformed.
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    /// The vault failed, or the passkey domain is locked.
    #[error(transparent)]
    Vault(#[from] VaultError),
}
