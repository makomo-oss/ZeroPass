//! OS-independent WebAuthn passkey authenticator engine for ZeroPass
//! (ADR-0010, `docs/spec/passkey.md`).
//!
//! Passkeys are items of the vault's passkey domain: their private keys are
//! encrypted under VK-K and decrypted only by the process that holds that
//! domain, the vault daemon's passkey worker (ADR-0007). This crate makes the
//! credentials, keeps them in the vault and signs with them: the
//! authenticator of WebAuthn, and the part of its client that decides which
//! relying party a page may use and what the signature covers.

pub mod authenticator;
mod cbor;
pub mod client;
pub mod credential;
pub mod key;

pub use authenticator::{
    AAGUID, Assertion, Choice, CreateRequest, GetOutcome, GetRequest, Registration, get_assertion,
    make_credential,
};
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
    /// The page's origin is not a web origin.
    #[error("the page's origin is not of the form https://host[:port]")]
    BadOrigin,
    /// The request comes from a frame of another site than the tab's top frame.
    #[error("passkeys are not used in a frame of another site than the page")]
    CrossSite,
    /// The page may not use the relying party it names.
    #[error("this page may not use that relying party identifier")]
    BadRelyingParty,
    /// The vault already holds a credential the relying party excludes.
    #[error("this vault already holds a passkey of this account for the site")]
    Excluded,
    /// The vault holds no credential for the request.
    #[error("this vault holds no passkey for the site")]
    NoCredential,
    /// A request is malformed.
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    /// The vault failed, or the passkey domain is locked.
    #[error(transparent)]
    Vault(#[from] VaultError),
}
