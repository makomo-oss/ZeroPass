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

/// The directory the sockets are made in.
pub(crate) fn endpoint_directory() -> io::Result<Option<PathBuf>> {
    runtime_dir().map(Some)
}

fn socket_path(endpoint: &Endpoint) -> io::Result<PathBuf> {
    Ok(runtime_dir()?.join(format!("{}-{}.sock", endpoint.service(), endpoint.id())))
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
        executable: executables::of(pid),
    })
}

/// The executables of other processes, read from `/proc/<pid>/exe`: here, or
/// in a helper process started before this one entered its sandbox. Landlock
/// keeps a sandboxed process from reading that link for processes outside
/// its sandbox (`ipc.md` §9.2).
#[cfg(target_os = "linux")]
pub(crate) mod executables {
    use std::ffi::OsString;
    use std::io::{self, BufReader, Read, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::{Mutex, OnceLock};

    /// The longest path the helper answers with (`PATH_MAX`).
    const MAX_PATH: usize = 4096;

    /// The helper, and the pipes to it: a request is a process ID (4 bytes,
    /// little-endian), the answer the length of the path (4 bytes, 0 if
    /// unknown) and the path.
    struct Helper {
        _child: Child,
        requests: ChildStdin,
        answers: BufReader<ChildStdout>,
    }

    static HELPER: OnceLock<Mutex<Helper>> = OnceLock::new();

    fn read(pid: i32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    /// The executable of process `pid`, if it can be told.
    pub(crate) fn of(pid: i32) -> Option<PathBuf> {
        let Some(helper) = HELPER.get() else {
            return read(pid);
        };
        // A helper that went away tells nothing: the peer is turned away.
        helper
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .ask(pid)
            .ok()
            .flatten()
    }

    impl Helper {
        fn ask(&mut self, pid: i32) -> io::Result<Option<PathBuf>> {
            self.requests.write_all(&pid.to_le_bytes())?;
            self.requests.flush()?;
            let mut length = [0u8; 4];
            self.answers.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length == 0 {
                return Ok(None);
            }
            if length > MAX_PATH {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the executable lookup sent a path that is too long",
                ));
            }
            let mut path = vec![0u8; length];
            self.answers.read_exact(&mut path)?;
            Ok(Some(PathBuf::from(OsString::from_vec(path))))
        }
    }

    pub(crate) fn start_helper(program: &Path, args: &[&str]) -> io::Result<()> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let (Some(requests), Some(answers)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            return Err(io::Error::other("the executable lookup has no pipes"));
        };
        let helper = Helper {
            _child: child,
            requests,
            answers: BufReader::new(answers),
        };
        HELPER.set(Mutex::new(helper)).map_err(|mut helper| {
            let _ = helper.get_mut().map(|helper| helper._child.kill());
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the executable lookup is already started",
            )
        })
    }

    /// Answers the requests of [`start_helper`] read from `input` on `output`,
    /// until the input ends.
    pub(crate) fn serve(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
        let mut pid = [0u8; 4];
        loop {
            match input.read_exact(&mut pid) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            }
            let pid = i32::from_le_bytes(pid);
            let path = if pid > 0 { read(pid) } else { None };
            let bytes = path
                .as_ref()
                .map(|path| path.as_os_str().as_bytes())
                .filter(|bytes| bytes.len() <= MAX_PATH)
                .unwrap_or_default();
            output.write_all(&(bytes.len() as u32).to_le_bytes())?;
            output.write_all(bytes)?;
            output.flush()?;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_lookup_answers_with_the_executable_or_nothing() {
            let mut requests = Vec::new();
            requests.extend_from_slice(&(std::process::id() as i32).to_le_bytes());
            requests.extend_from_slice(&i32::MAX.to_le_bytes());
            requests.extend_from_slice(&0i32.to_le_bytes());
            let mut answers = Vec::new();
            serve(requests.as_slice(), &mut answers).unwrap();

            let own = std::env::current_exe().unwrap();
            let own = own.as_os_str().as_bytes();
            let mut expected = (own.len() as u32).to_le_bytes().to_vec();
            expected.extend_from_slice(own);
            expected.extend_from_slice(&0u32.to_le_bytes());
            expected.extend_from_slice(&0u32.to_le_bytes());
            assert_eq!(answers, expected);
        }
    }
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

/// The executable of this process, in the form paths are compared in.
pub(crate) fn current_exe() -> io::Result<PathBuf> {
    std::env::current_exe()
}

/// Brings a path into the form paths are compared in: here, as it is.
pub(crate) fn comparable(path: &std::path::Path) -> PathBuf {
    path.to_path_buf()
}
