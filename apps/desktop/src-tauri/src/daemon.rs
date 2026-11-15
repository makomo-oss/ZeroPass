//! The application's conversation with the vault daemon.
//!
//! One connection, made when first needed and kept. Requests are made one at
//! a time, on worker threads (never on the thread that runs the window): the
//! daemon may take minutes to answer while the user answers Windows Hello.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use zp_client::vaultd::{self, Start};
use zp_client::{KeyAgent, KeyStoreChoice};
use zp_ipc::proto::{self, request, response};
use zp_ipc::{Client, IpcError};

/// The vault daemon of the vault this application shows.
pub(crate) struct Daemon {
    vault: PathBuf,
    choice: KeyStoreChoice,
    client: Mutex<Option<Client>>,
}

/// Whether making `request` twice has the same effect as making it once: only
/// those are made again on a new connection when the old one broke.
fn repeatable(request: &request::Body) -> bool {
    use request::Body;
    matches!(
        request,
        Body::Status(_)
            | Body::Unlock(_)
            | Body::Lock(_)
            | Body::ListItems(_)
            | Body::GetItem(_)
            | Body::TotpCode(_)
            | Body::ListDevices(_)
    )
}

/// Whether `error` means that the connection is gone, rather than that the
/// daemon refused the request.
fn connection_lost(error: &IpcError) -> bool {
    matches!(error, IpcError::Io(_) | IpcError::Protocol(_))
}

impl Daemon {
    pub(crate) fn new(vault: PathBuf, choice: KeyStoreChoice) -> Self {
        Self {
            vault,
            choice,
            client: Mutex::new(None),
        }
    }

    pub(crate) fn choice(&self) -> KeyStoreChoice {
        self.choice
    }

    pub(crate) fn vault(&self) -> &Path {
        &self.vault
    }

    fn client(&self) -> MutexGuard<'_, Option<Client>> {
        self.client
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Makes one request, connecting first if necessary; `start` says whether
    /// to start the daemon if it is not running.
    pub(crate) fn call_with(
        &self,
        start: Start,
        request: request::Body,
    ) -> zp_client::Result<response::Body> {
        let mut client = self.client();
        let again = repeatable(&request);
        for attempt in 0..2 {
            if client.is_none() {
                *client = Some(vaultd::open(&self.vault, self.choice, start)?);
            }
            let Some(connection) = client.as_mut() else {
                continue;
            };
            match connection.call(request.clone()) {
                Ok(reply) => return Ok(reply),
                Err(error) if connection_lost(&error) => {
                    // The daemon stopped or restarted: the next request
                    // connects anew.
                    *client = None;
                    if attempt == 0 && again {
                        continue;
                    }
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(zp_client::Error::message(
            "the vault daemon cannot be reached",
        ))
    }

    /// Makes one request of an existing vault's daemon, starting it if
    /// necessary.
    pub(crate) fn call(&self, request: request::Body) -> zp_client::Result<response::Body> {
        self.call_with(Start::IfVaultExists, request)
    }

    /// Makes a request for which the daemon may need the hardware key store
    /// (Windows Hello): the key agent runs while it is made.
    pub(crate) fn call_with_key_agent(
        &self,
        start: Start,
        request: request::Body,
    ) -> zp_client::Result<response::Body> {
        // The daemon must be running for the agent to attach to it.
        self.call_with(start, request::Body::Status(proto::Status {}))?;
        let _agent = KeyAgent::start(&self.vault, self.choice)?;
        self.call_with(start, request)
    }
}
