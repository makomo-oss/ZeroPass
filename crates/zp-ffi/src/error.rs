//! What the app is told when something fails.

use zp_ipc::IpcError;
use zp_ipc::proto::{self, ErrorCode};

use crate::Domain;

/// What went wrong, for the app to decide what to show or do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Problem {
    /// The master password is wrong.
    WrongPassword,
    /// The new master password or passphrase is too short.
    WeakPassword,
    /// The domain is locked: unlock it and try again.
    Locked,
    /// The user turned down or failed the biometric prompt.
    Cancelled,
    /// This device cannot protect the TOTP and passkey keys (no lock screen,
    /// no biometrics): set it up first, or go on without them.
    HardwareUnavailable,
    /// The vault has no such domain on this device.
    DomainUnavailable,
    /// Another device has the domain: receive its keys instead of making it.
    DomainElsewhere,
    /// Something was written with keys this device has not received.
    KeysMissing,
    /// Revoking that device from here could lose the TOTP or passkey keys.
    KeysAtRisk,
    /// There is no vault yet.
    NoVault,
    /// There is a vault already.
    VaultExists,
    /// No such item.
    ItemNotFound,
    /// The recovery key does not open this vault.
    WrongRecoveryKey,
    /// The vault has no recovery kit.
    NoRecoveryKit,
    /// A recovery kit exists; replacing it invalidates the old one.
    RecoveryKitExists,
    /// The pairing code is malformed, expired or of the wrong kind.
    BadCode,
    /// The input cannot be used.
    InvalidInput,
    /// Not allowed (for example, a page asking for another site's login).
    Denied,
    /// The site excluded a passkey that is in the vault.
    CredentialExcluded,
    /// None of the site's algorithms is supported.
    UnsupportedAlgorithm,
    /// Anything else.
    Failed,
}

/// Why a call failed. The message is meant for the user, in English.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ZpError {
    /// The call failed.
    #[error("{detail}")]
    Failure {
        /// What kind of failure.
        problem: Problem,
        /// The domain it is about, for `Locked` and the domain problems.
        domain: Option<Domain>,
        /// A sentence for people. Never contains a secret. (Not `message`:
        /// Kotlin's exceptions have one already.)
        detail: String,
    },
}

impl ZpError {
    pub(crate) fn new(problem: Problem, message: impl Into<String>) -> Self {
        Self::Failure {
            problem,
            domain: None,
            detail: message.into(),
        }
    }

    pub(crate) fn failed(error: impl core::fmt::Display) -> Self {
        Self::new(Problem::Failed, error.to_string())
    }

    /// What kind of failure this is.
    #[cfg(test)]
    pub(crate) fn problem(&self) -> Problem {
        match self {
            Self::Failure { problem, .. } => *problem,
        }
    }
}

fn problem_of(code: ErrorCode) -> Problem {
    match code {
        ErrorCode::WrongPassword => Problem::WrongPassword,
        ErrorCode::WeakPassword => Problem::WeakPassword,
        ErrorCode::Locked => Problem::Locked,
        ErrorCode::UserCancelled => Problem::Cancelled,
        ErrorCode::HardwareUnavailable => Problem::HardwareUnavailable,
        ErrorCode::DomainUnavailable => Problem::DomainUnavailable,
        ErrorCode::DomainElsewhere => Problem::DomainElsewhere,
        ErrorCode::KeysMissing => Problem::KeysMissing,
        ErrorCode::KeysAtRisk => Problem::KeysAtRisk,
        ErrorCode::NoVault => Problem::NoVault,
        ErrorCode::VaultExists => Problem::VaultExists,
        ErrorCode::ItemNotFound | ErrorCode::DeviceNotFound => Problem::ItemNotFound,
        ErrorCode::WrongRecoveryKey => Problem::WrongRecoveryKey,
        ErrorCode::NoRecoveryKit => Problem::NoRecoveryKit,
        ErrorCode::RecoveryKitExists => Problem::RecoveryKitExists,
        ErrorCode::InvalidInput | ErrorCode::WrongItemKind | ErrorCode::BadRequest => {
            Problem::InvalidInput
        }
        ErrorCode::Denied => Problem::Denied,
        ErrorCode::CredentialExcluded => Problem::CredentialExcluded,
        ErrorCode::UnsupportedAlgorithm => Problem::UnsupportedAlgorithm,
        _ => Problem::Failed,
    }
}

impl From<proto::Error> for ZpError {
    fn from(error: proto::Error) -> Self {
        let problem = ErrorCode::try_from(error.code).map_or(Problem::Failed, problem_of);
        Self::Failure {
            problem,
            domain: error.domain.and_then(Domain::from_proto),
            detail: error.message,
        }
    }
}

impl From<IpcError> for ZpError {
    fn from(error: IpcError) -> Self {
        match error {
            IpcError::Remote(error) => error.into(),
            other => Self::failed(format!("the vault process: {other}")),
        }
    }
}
