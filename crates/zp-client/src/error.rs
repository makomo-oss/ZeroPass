//! What can go wrong while reaching the daemons.

use zp_ipc::IpcError;
use zp_ipc::proto::{self, ErrorCode};

/// An error of a client operation. Its text is meant for the user.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The local IPC failed, or a daemon answered with an error.
    #[error(transparent)]
    Ipc(#[from] IpcError),
    /// The vault file is missing, already exists, and the like.
    #[error(transparent)]
    Vault(#[from] zp_vault::VaultError),
    /// A pairing code could not be read.
    #[error(transparent)]
    Pairing(#[from] zp_pairing::PairingError),
    /// Starting a program or reaching a file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Anything else, described in words.
    #[error("{0}")]
    Message(String),
}

/// The result of a client operation.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// An error described in words.
    pub fn message(text: impl Into<String>) -> Self {
        Error::Message(text.into())
    }

    /// The error a daemon answered with, if this is one.
    pub fn remote(&self) -> Option<&proto::Error> {
        match self {
            Error::Ipc(IpcError::Remote(error)) => Some(error),
            _ => None,
        }
    }

    /// The code of the error a daemon answered with, if this is one.
    pub fn code(&self) -> Option<ErrorCode> {
        self.remote()
            .and_then(|error| ErrorCode::try_from(error.code).ok())
    }
}
