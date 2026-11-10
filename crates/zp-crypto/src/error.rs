//! Error type shared by the crate.

/// Errors returned by cryptographic operations.
///
/// Variants deliberately carry no secret-dependent detail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The operating system's random number generator failed.
    #[error("the operating system random number generator failed")]
    Rng,
    /// Encryption failed. Only possible for inputs beyond the cipher's size limits.
    #[error("encryption failed")]
    Encrypt,
    /// Authentication failed: wrong key, wrong context, or modified ciphertext.
    #[error("decryption failed")]
    Decrypt,
    /// The envelope is too short to be valid.
    #[error("malformed envelope")]
    MalformedEnvelope,
    /// The envelope was written by an unknown format version.
    #[error("unsupported envelope version {0:#04x}")]
    UnsupportedEnvelopeVersion(u8),
    /// Argon2id parameters are out of the accepted range.
    #[error("key derivation parameters are out of range")]
    InvalidKdfParams,
    /// Key derivation failed (for example, the memory could not be allocated).
    #[error("key derivation failed")]
    Kdf,
}
