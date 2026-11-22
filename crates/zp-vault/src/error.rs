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
    /// The vault has no recovery kit.
    #[error("no recovery kit has been created for this vault")]
    NoRecoveryKit,
    /// The recovery key does not belong to this vault.
    #[error("the recovery key does not match this vault")]
    WrongRecoveryKey,
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
    /// This device has no identity yet (a vault file from an earlier format that
    /// has not been unlocked since).
    #[error("this device has no identity yet; unlock the vault once")]
    NotProvisioned,
    /// The device signing key is not available to this domain yet.
    #[error(
        "the device signing key is not available to the {0:?} domain; unlock the password domain together with it once"
    )]
    DeviceKeyUnavailable(zp_crypto::DomainId),
    /// A version was written with a vault key this device does not hold (yet):
    /// a key update travels with sync; a key another device made on its own
    /// is received from that device (ADR-0011).
    #[error(
        "the {domain:?} vault key (generation {epoch}) that wrote this has not reached this device; sync, or get the keys from another device"
    )]
    KeyGenerationUnavailable {
        /// The domain of the key.
        domain: zp_crypto::DomainId,
        /// The missing generation.
        epoch: u32,
    },
    /// This device already has the domain.
    #[error("this device already has the {0:?} domain")]
    DomainPresent(zp_crypto::DomainId),
    /// Other devices of the vault seem to have the domain: its keys are to be
    /// received from one of them rather than made anew here (ADR-0011).
    #[error(
        "other devices of this vault seem to have the {0:?} domain; get its keys from one of them"
    )]
    DomainElsewhere(zp_crypto::DomainId),
    /// Some items of the domain cannot be opened with the keys held here.
    #[error(
        "{items} item(s) of the {domain:?} domain cannot be opened on this device; get the keys from another device first"
    )]
    KeysMissing {
        /// The domain.
        domain: zp_crypto::DomainId,
        /// How many items cannot be opened.
        items: usize,
    },
    /// A device cannot revoke itself.
    #[error("a device cannot revoke itself; revoke it from another device")]
    CannotRevokeSelf,
    /// A sync rule was violated.
    #[error(transparent)]
    Sync(#[from] zp_sync::SyncError),
    /// A grant received while joining a vault is unusable.
    #[error("the grant is not valid: {0}")]
    InvalidGrant(&'static str),
    /// A decrypted item could not be parsed.
    #[error("the item content is malformed")]
    MalformedItem,
    /// A TOTP entry is invalid.
    #[error(transparent)]
    Totp(#[from] crate::totp::TotpError),
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The underlying database reported an error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}
