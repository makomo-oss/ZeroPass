//! Unix domain sockets (`docs/spec/ipc.md` §2.2).

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use crate::peer::PeerProcess;
use crate::{Endpoint, IpcError};

/// A connection.
pub(crate) type Stream = UnixStream;

/// Whether this platform tells which executable is at the other end.
pub(crate) const IDENTIFIES_PEERS: bool = cfg!(target_os = "linux");

/// The directory the sockets live in: private to the user.
fn runtime_dir() -> io::Result<PathBuf> {
    let uid = rustix::process::getuid().as_raw();
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("zeropass"),
        _ => std::env::temp_dir().join(format!("zeropass-{uid}")),
    };
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    // Someone else may have created the directory first: use it only if it is
    // a real directory of this user that nobody else can enter.
    let metadata = fs::symlink_metadata(&dir)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a private directory of this user", dir.display()),
        ));
    }
    Ok(dir)
}

fn socket_path(endpoint: &Endpoint) -> io::Result<PathBuf> {
    Ok(runtime_dir()?.join(format!("vaultd-{}.sock", endpoint.id())))
}

#[cfg(target_os = "linux")]
fn identify(stream: &UnixStream) -> io::Result<PeerProcess> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)?;
    if credentials.uid != rustix::process::getuid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the peer runs as another user",
        ));
    }
    let pid = credentials.pid.as_raw_nonzero().get();
    Ok(PeerProcess {
        pid: u32::try_from(pid).ok(),
        executable: fs::read_link(format!("/proc/{pid}/exe")).ok(),
    })
}

#[cfg(not(target_os = "linux"))]
fn identify(_stream: &UnixStream) -> io::Result<PeerProcess> {
    Ok(PeerProcess {
        pid: None,
        executable: None,
    })
}

/// The listening end of an endpoint.
pub(crate) struct Listener {
    listener: UnixListener,
    path: PathBuf,
}

impl Listener {
    pub(crate) fn bind(endpoint: &Endpoint) -> Result<Self, IpcError> {
        let path = socket_path(endpoint)?;
        if fs::symlink_metadata(&path).is_ok() {
            // A daemon that answers is running; a socket nobody answers on was
            // left behind by one that did not exit cleanly.
            if UnixStream::connect(&path).is_ok() {
                return Err(IpcError::AlreadyRunning);
            }
            fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }

    /// Waits for the next client.
    pub(crate) fn accept(&self) -> io::Result<(Stream, PeerProcess)> {
        let (stream, _) = self.listener.accept()?;
        let process = identify(&stream)?;
        Ok((stream, process))
    }

    /// Makes a blocked `accept` return.
    pub(crate) fn wake(&self) {
        let _ = UnixStream::connect(&self.path);
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Connects to the daemon listening on `endpoint`.
pub(crate) fn connect(endpoint: &Endpoint) -> Result<(Stream, PeerProcess), IpcError> {
    let path = socket_path(endpoint)?;
    let stream = match UnixStream::connect(&path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(IpcError::NotRunning);
        }
        Err(error) => return Err(error.into()),
    };
    let process = identify(&stream)?;
    Ok((stream, process))
}

/// Starts `command` as a process that outlives this one and is not reached by
/// the signals of this one's terminal.
pub(crate) fn spawn_detached(command: &mut std::process::Command) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map(drop)
}
