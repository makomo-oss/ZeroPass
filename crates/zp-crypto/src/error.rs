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
}
