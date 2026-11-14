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
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_SUCCESS,
    GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, HLOCAL, LocalFree,
    SetHandleInformation, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, FreeSid, GetTokenInformation, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
    TokenAppContainerSid, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, GetFinalPathNameByHandleW, PIPE_ACCESS_DUPLEX,
    SECURITY_IDENTIFICATION, VOLUME_NAME_NT,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, GetCurrentProcess, GetCurrentProcessId,
    OpenProcess, OpenProcessToken, PROCESS_NAME_NATIVE, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
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

fn pipe_name(endpoint: &Endpoint) -> String {
    format!("zeropass-vaultd-{}", endpoint.id())
}

/// The path a daemon creates its pipe at.
///
/// A process in an AppContainer may create pipes only in the namespace of its
/// container, which it reaches through the `LOCAL` prefix.
fn server_pipe_path(endpoint: &Endpoint, in_container: bool) -> String {
    let name = pipe_name(endpoint);
    if in_container {
        format!(r"\\.\pipe\LOCAL\{name}")
    } else {
        format!(r"\\.\pipe\{name}")
    }
}

/// The paths a client looks for the daemon at: in the namespace of the
/// daemon's sandbox, then in the global one (a daemon that is not sandboxed).
fn client_pipe_paths(endpoint: &Endpoint) -> Vec<String> {
    let name = pipe_name(endpoint);
    let mut paths = Vec::new();
    if let Ok(path) = container_pipe_path(endpoint.sandbox(), &name) {
        paths.push(path);
    }
    paths.push(format!(r"\\.\pipe\{name}"));
    paths
}

/// Allows the processes of the AppContainer `container` to ask which
/// executable this process runs, and nothing more.
fn show_executable_to(container: PSID) -> io::Result<()> {
    fn check(status: WIN32_ERROR) -> io::Result<()> {
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status.0 as i32))
        }
    }

    // SAFETY: returns a pseudo handle that is always valid.
    let process = unsafe { GetCurrentProcess() };
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `dacl` and `descriptor` are valid places for the results; `dacl`
    // points into the descriptor, which is freed by `SecurityDescriptor`.
    check(unsafe {
        GetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    })?;
    let _descriptor = SecurityDescriptor(descriptor);

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: PROCESS_QUERY_LIMITED_INFORMATION.0,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            // With TRUSTEE_IS_SID, the "name" is the SID itself.
            ptstrName: PWSTR(container.0.cast()),
            ..TRUSTEE_W::default()
        },
    };
    let mut merged: *mut ACL = ptr::null_mut();
    // SAFETY: `entry` holds a valid SID that outlives the call, `dacl` is the
    // valid ACL read above (or null: no ACL), and `merged` receives a new ACL
    // allocated by the system. An entry the ACL already has is not added twice.
    check(unsafe { SetEntriesInAclW(Some(&[entry]), Some(dacl), &mut merged) })?;
    // SAFETY: `merged` is the valid ACL created above.
    let set = check(unsafe {
        SetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(merged),
            None,
        )
    });
    // SAFETY: `SetEntriesInAclW` documents `LocalFree` as the way to release
    // the ACL, and it is not used afterwards.
    unsafe {
        LocalFree(Some(HLOCAL(merged.cast())));
    }
    set
}

/// The path at which a process outside the AppContainer `container` reaches a
/// pipe that a process inside it created as `LOCAL\<name>`.
fn container_pipe_path(container: &str, name: &str) -> io::Result<String> {
    let container = HSTRING::from(container);
    // SAFETY: `container` is a valid, null-terminated wide string.
    let sid = unsafe { DeriveAppContainerSidFromAppContainerName(&container) }?;
    // A daemon in the container cannot look at processes outside it unless
    // they allow it, and it admits only clients whose executable it can see.
    let shown = show_executable_to(sid);
    let text = shown.and_then(|()| sid_to_text(sid));
    // SAFETY: the SID was allocated by the call above, which documents
    // `FreeSid` as the way to release it; it is not used afterwards.
    unsafe {
        FreeSid(sid);
    }
    let mut session = 0u32;
    // SAFETY: plain call; `session` is a valid place for the result.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }?;
    Ok(format!(
        r"\\.\pipe\Sessions\{session}\AppContainerNamedObjects\{}\{name}",
        text?
    ))
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

/// A SID from the token of this process, in string form: the user's
/// (`TokenUser`, `S-1-5-21-…`) or the AppContainer's (`TokenAppContainerSid`,
/// `S-1-15-2-…`). `None` if the token has no such SID.
fn token_sid(class: TOKEN_INFORMATION_CLASS) -> io::Result<Option<String>> {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that is always valid,
    // and `token` is a valid place to store the result.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
    let token = owned(token);

    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 is allowed; the call fails and reports
    // the size it needs in `len`.
    let _ = unsafe { GetTokenInformation(raw(&token), class, None, 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // `u64` elements give the buffer the alignment of a pointer.
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: the buffer is writable and at least `len` bytes long.
    unsafe {
        GetTokenInformation(
            raw(&token),
            class,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }?;
    // SAFETY: both `TOKEN_USER` and `TOKEN_APPCONTAINER_INFORMATION` start with
    // a pointer to the SID, the buffer is suitably aligned, and the SID lives in
    // the same buffer, which outlives its use below.
    let sid = unsafe { *buffer.as_ptr().cast::<PSID>() };
    if sid.0.is_null() {
        return Ok(None);
    }
    sid_to_text(sid).map(Some)
}

/// The string form of a SID.
fn sid_to_text(sid: PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: every caller passes a valid SID, and `text` receives a string
    // allocated by the system.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }?;
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
/// If this process runs in an AppContainer, the container is named too:
/// without that, the process could not open its own pipe.
fn user_only_descriptor(container: Option<&str>) -> io::Result<SecurityDescriptor> {
    let user =
        token_sid(TokenUser)?.ok_or_else(|| io::Error::other("the process token names no user"))?;
    // D:P — a protected DACL (nothing inherited); each entry allows (A)
    // generic all (GA) to one SID.
    let mut sddl = format!("D:P(A;;GA;;;{user})");
    if let Some(container) = container {
        sddl.push_str(&format!("(A;;GA;;;{container})"));
    }
    let sddl = HSTRING::from(sddl);
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

/// The executable a process runs, as a path in the namespace of the kernel
/// (`\Device\HarddiskVolume3\…`).
///
/// Paths are compared in this form, not in the familiar one with a drive
/// letter: a sandboxed process may be unable to translate a volume to its
/// drive letter, and then the system hands it this form anyway.
fn image_of(process: HANDLE) -> io::Result<PathBuf> {
    // The longest path Windows can return.
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    // SAFETY: every caller passes a valid process handle; the buffer is
    // writable and `len` holds its length in characters; on success `len` is
    // the number of characters written.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_NATIVE,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }?;
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len as usize])))
}

/// The executable of the process `pid`.
fn executable_of(pid: u32) -> io::Result<PathBuf> {
    // SAFETY: plain call; failure is reported through the result.
    let process = owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }?);
    image_of(raw(&process))
}

/// The executable of this process, in the form paths are compared in.
pub(crate) fn current_exe() -> io::Result<PathBuf> {
    // SAFETY: returns a pseudo handle that is always valid.
    image_of(unsafe { GetCurrentProcess() })
}

/// Brings the path of an existing file into the form paths are compared in.
/// A path that is already in that form, or that cannot be opened, is returned
/// as it is.
pub(crate) fn comparable(path: &Path) -> PathBuf {
    if path.as_os_str().to_string_lossy().starts_with(r"\Device\") {
        return path.to_path_buf();
    }
    let Ok(file) = File::open(path) else {
        return path.to_path_buf();
    };
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: `file` is a valid file handle and the buffer is writable; the
    // result is the number of characters written, or more than the buffer
    // holds if it is too small, or zero on failure.
    let len = unsafe { GetFinalPathNameByHandleW(raw(&file), &mut buffer, VOLUME_NAME_NT) };
    if len == 0 || len as usize > buffer.len() {
        return path.to_path_buf();
    }
    PathBuf::from(OsString::from_wide(&buffer[..len as usize]))
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
        let container = token_sid(TokenAppContainerSid)?;
        let path = server_pipe_path(endpoint, container.is_some());
        let listener = Self {
            name: path.encode_utf16().chain([0]).collect(),
            path,
            security: user_only_descriptor(container.as_deref())?,
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
    for path in client_pipe_paths(endpoint) {
        if let Some(pipe) = open_pipe(&path)? {
            let process = identify(&pipe, End::Server);
            return Ok((pipe, process));
        }
    }
    Err(IpcError::NotRunning)
}

/// Opens the client end of the pipe at `path`; `None` if there is no such pipe.
fn open_pipe(path: &str) -> io::Result<Option<File>> {
    let deadline = Instant::now() + BUSY_TIMEOUT;
    loop {
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            // The server may learn who this process is, but may not act as it.
            .security_qos_flags(SECURITY_IDENTIFICATION.0)
            .open(path);
        match opened {
            Ok(pipe) => return Ok(Some(pipe)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32)
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

/// A standard handle of this process whose "inheritable" flag is cleared for as
/// long as this value lives.
struct NotInherited(HANDLE);

impl NotInherited {
    /// Clears the flag; `None` if the handle is absent or was not inheritable.
    fn new(handle: HANDLE) -> Option<Self> {
        if handle.0.is_null() || handle.is_invalid() {
            return None;
        }
        let mut flags = 0u32;
        // SAFETY: `handle` is a standard handle of this process, which stays
        // open for the life of the process; `flags` is a valid place for the result.
        unsafe { GetHandleInformation(handle, &mut flags) }.ok()?;
        if flags & HANDLE_FLAG_INHERIT.0 == 0 {
            return None;
        }
        // SAFETY: as above.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.ok()?;
        Some(Self(handle))
    }
}

impl Drop for NotInherited {
    fn drop(&mut self) {
        // SAFETY: the handle was valid in `new` and standard handles are not
        // closed while the process runs.
        let _ = unsafe { SetHandleInformation(self.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) };
    }
}

/// Starts `command` as a process that outlives this one and shares nothing
/// with its console.
pub(crate) fn spawn_detached(command: &mut Command) -> io::Result<()> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags((DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP).0);
    // A child inherits every inheritable handle of its parent, not only the
    // three it is given. If this process's own output is a pipe, the daemon
    // would keep that pipe open, and whoever reads it would wait for the daemon
    // to exit. So the standard handles are not inheritable while spawning.
    let standard = [
        io::stdin().as_raw_handle(),
        io::stdout().as_raw_handle(),
        io::stderr().as_raw_handle(),
    ];
    let guards: Vec<NotInherited> = standard
        .into_iter()
        .filter_map(|handle| NotInherited::new(HANDLE(handle)))
        .collect();
    let spawned = command.spawn();
    drop(guards);
    spawned.map(drop)
}
