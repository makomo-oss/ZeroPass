//! Error type of the IPC crate.

use std::io;

use crate::proto;

/// Errors of the local IPC.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    /// No daemon is listening on the endpoint.
    #[error("the vault daemon is not running")]
    NotRunning,
    /// Another daemon already serves the endpoint.
    #[error("a vault daemon is already running for this vault")]
    AlreadyRunning,
    /// The process at the other end is not one this process talks to.
    #[error("the process at the other end of the connection is not trusted: {0}")]
    UntrustedPeer(String),
    /// The daemon does not accept this executable as a client. The text is the
    /// daemon's reason, if it gave one.
    #[error("the vault daemon refused the connection{}", reason(.0))]
    Refused(String),
    /// A frame is longer than the protocol allows.
    #[error("a message of {0} bytes exceeds the frame limit")]
    FrameTooLarge(usize),
    /// A frame is not a valid message.
    #[error("a message could not be decoded")]
    Malformed,
    /// The other side broke the rules of the conversation.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// The daemon answered a request with an error.
    #[error("{}", .0.message)]
    Remote(proto::Error),
    /// The underlying pipe or socket failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Formats the reason of a refusal for the end of a sentence.
fn reason(text: &str) -> String {
    if text.is_empty() {
        String::new()
    } else {
        format!(": {text}")
    }
}

impl IpcError {
    /// The error code if the daemon answered with an error.
    pub fn code(&self) -> Option<proto::ErrorCode> {
        match self {
            IpcError::Remote(error) => proto::ErrorCode::try_from(error.code).ok(),
            _ => None,
        }
    }
}
