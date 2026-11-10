//! Error type of the vault crate.

use zp_crypto::CryptoError;

/// Errors returned by vault operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// A file already exists where a new vault was to be created.
    #[error("a file already exists at the vault path")]
    AlreadyExists,
    /// There is no vault file at the given path.
    #[error("no vault file exists at the given path")]
    NotFound,
    /// The file is not a ZeroPass vault.
    #[error("the file is not a ZeroPass vault")]
    NotAVault,
    /// The vault was written by a newer version of ZeroPass.
    #[error("vault schema version {found} is newer than the supported version {supported}")]
    UnsupportedSchema {
        /// Schema version found in the file.
        found: u32,
        /// Newest schema version this build understands.
        supported: u32,
    },
    /// The vault file is internally inconsistent.
    #[error("the vault file is corrupt: {0}")]
    Corrupt(&'static str),
    /// The key domain is locked (or has locked itself after being idle).
    #[error("the {0:?} domain is locked")]
    Locked(zp_crypto::DomainId),
    /// This vault was created without the given domain (no hardware key store).
    #[error("the {0:?} domain is not available in this vault")]
    DomainUnavailable(zp_crypto::DomainId),
    /// The master password is wrong.
    #[error("wrong master password")]
    WrongPassword,
    /// The master password is too short.
    #[error("the master password must be at least 12 characters long")]
    WeakPassword,
    /// The key-derivation parameters are below the allowed minimum.
    #[error("the key-derivation parameters are weaker than the allowed minimum")]
    WeakKdf,
    /// No live item has the given identifier.
    #[error("the item does not exist")]
    ItemNotFound,
    /// The item exists but is of a different kind than requested.
    #[error("the item is of a different kind")]
    WrongItemKind,
    /// The item belongs to a different key domain than the one used.
    #[error("the item belongs to a different key domain")]
    DomainMismatch,
    /// No further version stamps can be issued.
    #[error("the version clock is exhausted")]
    ClockExhausted,
    /// A decrypted item could not be parsed.
    #[error("the item content is malformed")]
    MalformedItem,
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The underlying database reported an error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}
