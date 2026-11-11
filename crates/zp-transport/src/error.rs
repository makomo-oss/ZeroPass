//! Errors of the transports and drivers.

use zp_pairing::PairingError;

/// Why a driver run ended without completing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DriveError {
    /// The link failed.
    #[error("connection error: {0}")]
    Io(#[from] std::io::Error),
    /// The peer stayed silent for too long.
    #[error("the other device stopped responding")]
    Timeout,
    /// The peer closed the link.
    #[error("the other device closed the connection")]
    Closed,
    /// The secure channel or the pairing conversation failed.
    #[error(transparent)]
    Pairing(#[from] PairingError),
    /// The sync session or the vault file reported an error.
    #[error("sync failed: {0}")]
    Sync(String),
}
