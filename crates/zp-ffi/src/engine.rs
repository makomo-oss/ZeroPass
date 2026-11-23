//! The vault process's side (ADR-0012): the vault daemon embedded in the
//! `isolatedProcess` service, and the socket pairs that reach it.

use std::sync::{Arc, OnceLock};
use std::thread;

use zp_ipc::Client;
use zp_vaultd::embedded::Engine;

use crate::client::VaultConnector;
use crate::error::ZpError;

/// The one engine of the vault process.
static ENGINE: OnceLock<Arc<Engine>> = OnceLock::new();

fn engine() -> Arc<Engine> {
    Arc::clone(ENGINE.get_or_init(|| {
        // Before the first key is in memory: no core dumps.
        let _ = zp_sandbox::harden_process();
        Arc::new(Engine::new())
    }))
}

/// Takes ownership of a socket the app handed over as a file descriptor.
#[cfg(unix)]
fn adopt(fd: i32) -> Result<std::os::unix::net::UnixStream, ZpError> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if fd < 0 {
        return Err(ZpError::failed("not a file descriptor"));
    }
    // SAFETY: the app detached `fd` from its `ParcelFileDescriptor`
    // (`detachFd`) and hands it over: it is open, it is one end of a socket
    // pair, and nothing else owns or closes it from here on.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(owned.into())
}

/// In the vault process: serves one connection of the app. `fd` is this
/// process's end of a socket pair the app handed over through Binder; Rust
/// owns it from here on. Returns at once; the conversation runs on a thread
/// of its own until the app closes it.
#[uniffi::export]
pub fn serve_vault_connection(fd: i32) -> Result<(), ZpError> {
    #[cfg(unix)]
    {
        let stream = adopt(fd)?;
        let engine = engine();
        thread::Builder::new()
            .name("vault connection".into())
            .spawn(move || engine.converse(stream))
            .map_err(ZpError::failed)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (fd, engine, thread::current);
        Err(ZpError::failed(
            "the vault process runs on Android only (socket pairs)",
        ))
    }
}

/// In the app process: a new connection to the vault process.
pub(crate) fn connect_with(connector: &dyn VaultConnector) -> Result<Client, ZpError> {
    let fd = connector.connect().map_err(|error| {
        ZpError::failed(format!("the vault process cannot be reached: {error}"))
    })?;
    #[cfg(unix)]
    {
        Ok(Client::over(adopt(fd)?, "android app")?)
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        Err(ZpError::failed(
            "the vault process runs on Android only (socket pairs)",
        ))
    }
}
