//! Errors returned by the passkey engine.

use thiserror::Error;
use zp_origin::RpIdError;
use zp_vault::VaultError;

/// Why a passkey operation failed.
#[derive(Debug, Error)]
pub enum PasskeyError {
    /// None of the algorithms requested by the relying party are supported
    /// (ZeroPass supports ES256 and EdDSA).
    #[error("no requested passkey algorithm is supported (supported: ES256, EdDSA)")]
    UnsupportedAlgorithm,

    /// The page origin is malformed or not allowed for passkeys.
    #[error("invalid passkey origin: {0}")]
    InvalidOrigin(String),

    /// The relying party identifier is malformed or does not match the origin.
    #[error("invalid relying party identifier: {0}")]
    InvalidRpId(#[from] RpIdError),

    /// The user handle is empty or longer than WebAuthn's 64-byte limit.
    #[error("user handle must be between 1 and 64 bytes")]
    InvalidUserHandle,

    /// A credential listed in `excludeCredentials` already exists for this RP.
    #[error("a matching passkey already exists for this relying party")]
    CredentialExcluded,

    /// No stored passkey matched the relying party and credential identifier.
    #[error("no matching passkey found")]
    CredentialNotFound,

    /// Stored key material could not be decoded or did not match its algorithm.
    #[error("stored passkey key material is malformed")]
    MalformedKey,

    /// Signature verification failed.
    #[error("passkey signature verification failed")]
    InvalidSignature,

    /// CBOR encoding failed.
    #[error("could not encode WebAuthn CBOR payload")]
    Cbor,

    /// The OS random number generator failed.
    #[error("could not obtain random bytes from the operating system")]
    Rng,

    /// An underlying vault error (for example, the passkey domain is locked).
    #[error(transparent)]
    Vault(#[from] VaultError),
}
