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
    /// The scanned text is not a pairing offer.
    #[error("this is not a valid pairing code")]
    InvalidOffer,
    /// The pairing offer has expired.
    #[error("the pairing code has expired; show a new one")]
    OfferExpired,
    /// The key in the request or offer is not the key of the channel peer.
    #[error("the device at the other end is not the one that was offered")]
    KeyMismatch,
    /// The user declined to add the device.
    #[error("the request was declined")]
    Declined,
    /// The peer sent something that is not part of the pairing conversation.
    #[error("unexpected pairing message")]
    Protocol,
    /// The vault refused the operation (for example, a domain is locked).
    #[error("{0}")]
    Vault(String),
    /// The channel was closed after a frame failed to authenticate.
    #[error("the secure channel is closed")]
    ChannelClosed,
}
