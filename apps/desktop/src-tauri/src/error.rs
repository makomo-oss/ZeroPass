//! Errors as the page sees them.

use serde::Serialize;
use zp_ipc::proto::{self, ErrorCode};

/// The error of a command. The page decides by `code` and shows `message`.
#[derive(Debug, Serialize)]
pub(crate) struct CommandError {
    /// The daemon's error code (`Locked`, `WrongPassword`, ...), or `Client`
    /// for an error on this side.
    code: String,
    /// Text for the user, without secrets.
    message: String,
    /// The domain the error is about, if any: `password`, `totp`, `passkey`.
    domain: Option<&'static str>,
}

impl CommandError {
    pub(crate) fn client(message: impl Into<String>) -> Self {
        Self {
            code: "Client".to_owned(),
            message: message.into(),
            domain: None,
        }
    }
}

/// The name of a domain as the page knows it.
pub(crate) fn domain_name(domain: proto::Domain) -> Option<&'static str> {
    match domain {
        proto::Domain::Password => Some("password"),
        proto::Domain::Totp => Some("totp"),
        proto::Domain::Passkey => Some("passkey"),
        proto::Domain::Unspecified => None,
    }
}

impl From<zp_client::Error> for CommandError {
    fn from(error: zp_client::Error) -> Self {
        match error.remote() {
            Some(remote) => Self {
                code: ErrorCode::try_from(remote.code)
                    .map_or_else(|_| "Internal".to_owned(), |code| format!("{code:?}")),
                message: remote.message.clone(),
                domain: remote
                    .domain
                    .and_then(|domain| proto::Domain::try_from(domain).ok())
                    .and_then(domain_name),
            },
            None => Self::client(error.to_string()),
        }
    }
}

impl From<zp_ipc::IpcError> for CommandError {
    fn from(error: zp_ipc::IpcError) -> Self {
        zp_client::Error::from(error).into()
    }
}

/// The result of a command.
pub(crate) type CommandResult<T> = Result<T, CommandError>;
