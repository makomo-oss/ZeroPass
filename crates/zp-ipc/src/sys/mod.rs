//! The platform's local transport: named pipes on Windows, Unix domain sockets
//! elsewhere. Both expose the same things: `Listener`, `Stream`, `connect` and
//! `IDENTIFIES_PEERS`.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{IDENTIFIES_PEERS, Listener, Stream, connect, spawn_detached};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::{IDENTIFIES_PEERS, Listener, Stream, connect, spawn_detached};
