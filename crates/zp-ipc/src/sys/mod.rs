//! The platform's local transport: named pipes on Windows, Unix domain sockets
//! elsewhere. Both expose the same things: `Listener`, `connect` and
//! `IDENTIFIES_PEERS`.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{
    IDENTIFIES_PEERS, Listener, comparable, connect, current_exe, spawn_detached,
};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::{
    IDENTIFIES_PEERS, Listener, comparable, connect, current_exe, spawn_detached,
};
