//! Windows named pipes (`docs/spec/ipc.md` §2.2).
//!
//! This is the only module in the crate that may use `unsafe`: the named-pipe,
//! token and process APIs have no safe wrapper in the standard library.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use crate::peer::PeerProcess;
use crate::{Endpoint, IpcError};

/// A connection: one end of a pipe instance.
pub(crate) type Stream = File;

/// Whether this platform tells which executable is at the other end.
pub(crate) const IDENTIFIES_PEERS: bool = true;

/// Size of the pipe's kernel buffers, in bytes. Longer frames still pass; the
/// writer just blocks until the reader catches up.
const BUFFER_SIZE: u32 = 64 * 1024;

/// How long a client waits for a free pipe instance while the daemon is busy
/// accepting another client.
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);

fn pipe_path(endpoint: &Endpoint) -> String {
    format!(r"\\.\pipe\zeropass-vaultd-{}", endpoint.id())
}

/// Takes ownership of a handle returned by the system, so that it is closed.
fn owned(handle: HANDLE) -> OwnedHandle {
    // SAFETY: every caller passes a valid handle it has just received from the
    // system and does not use or close it by other means afterwards.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

fn raw(handle: &impl AsRawHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

/// A security descriptor allocated by the system.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is an immutable block of memory owned by this value;
// it is only read (by `CreateNamedPipeW`) and freed once, on drop.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: see above; shared access only reads.
unsafe impl Sync for SecurityDescriptor {}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which documents
        // `LocalFree` as the way to release it, and it is not used afterwards.
        unsafe {
            LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

/// The SID of the user this process runs as, in string form (`S-1-5-21-…`).
fn current_user_sid() -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that is always valid,
    // and `token` is a valid place to store the result.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
    let token = owned(token);

    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 is allowed; the call fails and reports
    // the size it needs in `len`.
    let _ = unsafe { GetTokenInformation(raw(&token), TokenUser, None, 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // `u64` elements give the buffer the alignment `TOKEN_USER` needs.
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: the buffer is writable and at least `len` bytes long.
    unsafe {
        GetTokenInformation(
            raw(&token),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }?;
    // SAFETY: on success the buffer starts with a `TOKEN_USER`, the buffer is
    // suitably aligned, and the SID it points to lives in the same buffer, which
    // outlives this reference.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };

    let mut text = PWSTR::null();
    // SAFETY: the SID is valid (see above) and `text` receives a string
    // allocated by the system.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }?;
    // SAFETY: on success `text` is a valid, null-terminated wide string.
    let sid = unsafe { text.to_string() };
    // SAFETY: `ConvertSidToStringSidW` documents `LocalFree` as the way to
    // release the string, and it is not used afterwards.
    unsafe {
        LocalFree(Some(HLOCAL(text.0.cast())));
    }
    sid.map_err(io::Error::other)
}

/// A security descriptor that gives the current user, and nobody else, access.
fn user_only_descriptor() -> io::Result<SecurityDescriptor> {
    // D:P — a protected DACL (nothing inherited) with one entry: allow (A)
    // generic all (GA) to the user.
    let sddl = HSTRING::from(format!("D:P(A;;GA;;;{})", current_user_sid()?));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is a valid wide string and `descriptor` receives a
    // descriptor allocated by the system.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }?;
    Ok(SecurityDescriptor(descriptor))
}

/// The executable of the process `pid`.
fn executable_of(pid: u32) -> io::Result<PathBuf> {
    // SAFETY: plain call; failure is reported through the result.
    let process = owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }?);
    // The longest path Windows can return.
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer is writable and `len` holds its length in characters;
    // on success `len` is the number of characters written.
    unsafe {
        QueryFullProcessImageNameW(
            raw(&process),
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }?;
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len as usize])))
}

/// Which end of the pipe to ask about.
#[derive(Clone, Copy)]
enum End {
    Client,
    Server,
}

/// The process at the given end of a connected pipe.
fn identify(pipe: &impl AsRawHandle, end: End) -> PeerProcess {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a valid pipe handle and `pid` a valid place for the result.
    let found = unsafe {
        match end {
            End::Client => GetNamedPipeClientProcessId(raw(pipe), &mut pid),
            End::Server => GetNamedPipeServerProcessId(raw(pipe), &mut pid),
        }
    };
    if found.is_err() {
        return PeerProcess {
            pid: None,
            executable: None,
        };
    }
    PeerProcess {
        pid: Some(pid),
        executable: executable_of(pid).ok(),
    }
}

/// The listening end of an endpoint.
pub(crate) struct Listener {
    path: String,
    /// The pipe name as a null-terminated wide string.
    name: Vec<u16>,
    security: SecurityDescriptor,
    /// The pipe instance the next client connects to. There is always one while
    /// the listener lives, so the name stays taken (single instance) and clients
    /// never see "no such pipe" while the daemon runs.
    next: Mutex<Option<OwnedHandle>>,
}

impl Listener {
    pub(crate) fn bind(endpoint: &Endpoint) -> Result<Self, IpcError> {
        let path = pipe_path(endpoint);
        let listener = Self {
            name: path.encode_utf16().chain([0]).collect(),
            path,
            security: user_only_descriptor()?,
            next: Mutex::new(None),
        };
        let first = listener.create_instance(true).map_err(|error| {
            // With FILE_FLAG_FIRST_PIPE_INSTANCE, an existing pipe of that name
            // is reported as "access denied".
            if error.raw_os_error() == Some(ERROR_ACCESS_DENIED.0 as i32) {
                IpcError::AlreadyRunning
            } else {
                IpcError::Io(error)
            }
        })?;
        *listener.lock_next() = Some(first);
        Ok(listener)
    }

    fn lock_next(&self) -> std::sync::MutexGuard<'_, Option<OwnedHandle>> {
        self.next
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn create_instance(&self, first: bool) -> io::Result<OwnedHandle> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.security.0.0,
            bInheritHandle: false.into(),
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: `name` is a null-terminated wide string and `attributes`
        // points to a valid security descriptor; both outlive the call.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(self.name.as_ptr()),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                Some(&attributes),
            )
        };
        if handle.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        Ok(owned(handle))
    }

    /// Waits for the next client.
    pub(crate) fn accept(&self) -> io::Result<(Stream, PeerProcess)> {
        let taken = self.lock_next().take();
        let current = match taken {
            Some(instance) => instance,
            None => self.create_instance(false)?,
        };
        // SAFETY: `current` is a valid pipe handle opened for synchronous I/O.
        match unsafe { ConnectNamedPipe(raw(&current), None) } {
            Ok(()) => {}
            // The client connected between the creation of the instance and this call.
            Err(error) if error.code() == ERROR_PIPE_CONNECTED.to_hresult() => {}
            Err(error) => {
                *self.lock_next() = self.create_instance(false).ok();
                return Err(error.into());
            }
        }
        // Only now: a second free instance would let a client connect to the
        // one nobody is waiting on.
        *self.lock_next() = self.create_instance(false).ok();
        let process = identify(&current, End::Client);
        Ok((File::from(current), process))
    }

    /// Makes a blocked `accept` return.
    pub(crate) fn wake(&self) {
        let _ = OpenOptions::new().read(true).write(true).open(&self.path);
    }
}

/// Connects to the daemon listening on `endpoint`.
pub(crate) fn connect(endpoint: &Endpoint) -> Result<(Stream, PeerProcess), IpcError> {
    let path = pipe_path(endpoint);
    let deadline = Instant::now() + BUSY_TIMEOUT;
    loop {
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            // The server may learn who this process is, but may not act as it.
            .security_qos_flags(SECURITY_IDENTIFICATION.0)
            .open(&path);
        match opened {
            Ok(pipe) => {
                let process = identify(&pipe, End::Server);
                return Ok((pipe, process));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(IpcError::NotRunning);
            }
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32)
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}
