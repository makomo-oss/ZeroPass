//! Errors of the sync protocol.

use zp_crypto::DeviceId;

/// Why an op, a device record or a protocol message was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// A signature does not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// An op violates the format rules.
    #[error("malformed op: {0}")]
    MalformedOp(&'static str),
    /// A device record violates the format rules.
    #[error("malformed device record: {0}")]
    MalformedDevice(&'static str),
    /// Something refers to a device that is not in the registry.
    #[error("unknown device {0}")]
    UnknownDevice(DeviceId),
    /// The device has been revoked.
    #[error("device {0} has been revoked")]
    RevokedDevice(DeviceId),
    /// Two different records claim the same device identifier.
    #[error("conflicting records for device {0}")]
    ConflictingDevice(DeviceId),
    /// An op arrived ahead of its predecessors.
    #[error("op {got} of device {device} arrived out of order (expected {expected})")]
    OutOfOrder {
        /// The authoring device.
        device: DeviceId,
        /// The sequence number that must come next.
        expected: u64,
        /// The sequence number that arrived.
        got: u64,
    },
    /// An op carries the identifier of an op already held, with other content.
    #[error("op {seq} of device {device} conflicts with the op already held")]
    ConflictingOp {
        /// The authoring device.
        device: DeviceId,
        /// The sequence number.
        seq: u64,
    },
    /// An op's clock stamp lies too far in the future.
    #[error("an op's clock stamp is too far in the future; check the device clocks")]
    ClockSkew,
    /// A message could not be decoded.
    #[error("malformed message: {0}")]
    MalformedMessage(&'static str),
    /// A message exceeds the size limit.
    #[error("a message exceeds the size limit")]
    MessageTooLarge,
    /// The peer speaks a protocol version this build does not.
    #[error("unsupported sync protocol version {0}")]
    UnsupportedVersion(u32),
    /// The peer belongs to a different vault.
    #[error("the peer belongs to a different vault")]
    VaultMismatch,
    /// The peer is not the device the channel was established with.
    #[error("the peer is not the expected device")]
    UnexpectedPeer,
    /// The peer sent a message that is not allowed at this point.
    #[error("protocol violation: {0}")]
    ProtocolViolation(&'static str),
    /// A cryptographic primitive failed (for example the random number generator).
    #[error(transparent)]
    Crypto(#[from] zp_crypto::CryptoError),
    /// An op tries to move an item to another key domain.
    #[error("an op changes the key domain of an existing item")]
    DomainChanged,
}
