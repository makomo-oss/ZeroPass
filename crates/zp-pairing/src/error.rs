//! Errors of pairing and the secure channels.

/// Why a handshake, a channel or a pairing step failed.
///
/// The variants are deliberately coarse: a peer learns nothing from them about
/// which check failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PairingError {
    /// The Noise handshake failed: wrong secret, wrong device, wrong vault, or a
    /// malformed message.
    #[error("the secure channel could not be established")]
    Handshake,
    /// The peer's channel key is not in the device registry, or belongs to a
    /// revoked device.
    #[error("the peer is not a member of this vault")]
    UnknownPeer,
    /// The channel was closed after a frame failed to authenticate.
    #[error("the secure channel is closed")]
    ChannelClosed,
}
