//! Windows: an AppContainer without capabilities.
//!
//! This is the only module in the crate that may use `unsafe`: the AppContainer,
//! token and process-creation APIs have no safe wrapper in the standard library.
#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree, WAIT_ABANDONED, WAIT_OBJECT_0,
    WAIT_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, FreeSid, GetTokenInformation, INHERIT_ONLY_ACE,
    InitializeSecurityDescriptor, NO_INHERITANCE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_CAPABILITIES, SECURITY_DESCRIPTOR, SetFileSecurityW, SetSecurityDescriptorDacl,
    TOKEN_QUERY, TokenIsAppContainer,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_ATTRIBUTES, FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CreateMutexW, CreateProcessW, DETACHED_PROCESS,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION,
    ReleaseMutex, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

fn owned(handle: HANDLE) -> OwnedHandle {
    // SAFETY: every caller passes a valid handle it has just received from the
    // system and does not use or close it by other means afterwards.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

fn raw(handle: &impl AsRawHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

/// How often creating a container profile is retried, and how long to wait in
/// between.
const PROFILE_ATTEMPTS: u32 = 20;
const PROFILE_RETRY: std::time::Duration = std::time::Duration::from_millis(100);

/// A lock shared by the processes of this logon session, held while a
/// container profile is created. Best effort: if the lock cannot be taken,
/// creation goes ahead and relies on its retries.
struct ProfileLock(Option<OwnedHandle>);

impl ProfileLock {
    fn acquire() -> Self {
        let name = HSTRING::from(r"Local\ZeroPass.Sandbox.Profile");
        // SAFETY: `name` is a valid wide string; no security attributes.
        let Ok(mutex) = (unsafe { CreateMutexW(None, false, &name) }) else {
            return Self(None);
        };
        let mutex = owned(mutex);
        // SAFETY: `mutex` is a valid mutex handle. Both "acquired" and
        // "acquired after its previous owner died" mean this thread owns it.
        let waited = unsafe { WaitForSingleObject(raw(&mutex), PROFILE_LOCK_TIMEOUT_MS) };
        if waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED {
            Self(Some(mutex))
        } else {
            Self(None)
        }
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        if let Some(mutex) = &self.0 {
            // SAFETY: this thread owns the mutex (see `acquire`).
            let _ = unsafe { ReleaseMutex(raw(mutex)) };
        }
    }
}

/// How long to wait for another process that is creating a profile.
const PROFILE_LOCK_TIMEOUT_MS: u32 = 10_000;

/// The SID of an AppContainer; freed on drop.
struct ContainerSid(PSID);

impl Drop for ContainerSid {
    fn drop(&mut self) {
        // SAFETY: the SID was allocated by `CreateAppContainerProfile` or
        // `DeriveAppContainerSidFromAppContainerName`, both of which document
        // `FreeSid` as the way to release it; it is not used afterwards.
        unsafe {
            FreeSid(self.0);
        }
    }
}

impl ContainerSid {
    /// The SID of the container `name`. It is computed from the name; the
    /// container does not need to exist.
    fn of(name: &str) -> io::Result<Self> {
        let wide = HSTRING::from(name);
        // SAFETY: `wide` is a valid, null-terminated wide string.
        let sid = unsafe { DeriveAppContainerSidFromAppContainerName(&wide) }?;
        Ok(Self(sid))
    }

    /// The SID of the container `name`, after making sure that its profile
    /// (the container's own folders and registry keys) exists.
    fn with_profile(name: &str) -> io::Result<Self> {
        // One process of this user at a time: creating the same profile from
        // two processes at once can fail in both.
        let _exclusive = ProfileLock::acquire();
        let wide = HSTRING::from(name);
        let mut attempt = 0;
        loop {
            // SAFETY: all three strings are valid, null-terminated wide strings.
            match unsafe { CreateAppContainerProfile(&wide, &wide, &wide, None) } {
                Ok(sid) => return Ok(Self(sid)),
                Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                    return Self::of(name);
                }
                // Two processes creating the same profile at once trip over
                // each other's half-written registry keys; the loser of the
                // race finds the profile on a later attempt.
                Err(_) if attempt < PROFILE_ATTEMPTS => {
                    attempt += 1;
                    std::thread::sleep(PROFILE_RETRY);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn to_text(&self) -> io::Result<String> {
        let mut text = PWSTR::null();
        // SAFETY: the SID is valid for the life of `self`, and `text` receives a
        // string allocated by the system.
        unsafe { ConvertSidToStringSidW(self.0, &mut text) }?;
        // SAFETY: on success `text` is a valid, null-terminated wide string.
        let sid = unsafe { text.to_string() };
        // SAFETY: `ConvertSidToStringSidW` documents `LocalFree` as the way to
        // release the string, and it is not used afterwards.
        unsafe {
            LocalFree(Some(HLOCAL(text.0.cast())));
        }
        sid.map_err(io::Error::other)
    }
}

/// The SID of the container `name` in string form (`S-1-15-2-…`).
pub(crate) fn container_sid(name: &str) -> io::Result<String> {
    ContainerSid::of(name)?.to_text()
}

/// Memory allocated by the system that is released with `LocalFree`.
struct Local(*mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an API that documents `LocalFree` as
        // the way to release it (or is null, which `LocalFree` accepts), and it
        // is not used afterwards.
        unsafe {
            LocalFree(Some(HLOCAL(self.0)));
        }
    }
}

fn check(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0 as i32))
    }
}

/// Adds entries for the container `container` to the access control list of
/// the file or directory at `path`. Each entry is a set of rights and the way
/// it is inherited by what the directory contains.
///
/// Existing files of a directory are not touched: inheritable entries apply to
/// what is created afterwards.
fn add_entries(container: &str, path: &Path, entries: &[(u32, ACE_FLAGS)]) -> io::Result<()> {
    let sid = ContainerSid::of(container)?;
    let wide = HSTRING::from(path.as_os_str());

    let mut dacl: *mut ACL = ptr::null_mut();
    let mut current = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is a valid wide string; `dacl` and `current` are valid
    // places for the results. `dacl` points into `current`, which `_current`
    // keeps alive until the end of this function.
    check(unsafe {
        GetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut current,
        )
    })?;
    let _current = Local(current.0);

    let explicit: Vec<EXPLICIT_ACCESS_W> = entries
        .iter()
        .map(|&(rights, inheritance)| EXPLICIT_ACCESS_W {
            grfAccessPermissions: rights,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                // With TRUSTEE_IS_SID, the "name" is the SID itself.
                ptstrName: PWSTR(sid.0.0.cast()),
                ..TRUSTEE_W::default()
            },
        })
        .collect();
    let mut merged: *mut ACL = ptr::null_mut();
    // SAFETY: the entries hold a valid SID that outlives the call, `dacl` is
    // the ACL read above (or null: no ACL), and `merged` receives a new ACL
    // allocated by the system.
    check(unsafe { SetEntriesInAclW(Some(&explicit), Some(dacl), &mut merged) })?;
    let _merged = Local(merged.cast());

    // `SetFileSecurityW`, unlike `SetNamedSecurityInfoW`, changes this object
    // only: it does not push inheritable entries down to the files a directory
    // already contains.
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor = PSECURITY_DESCRIPTOR((&raw mut descriptor).cast());
    // SAFETY: `descriptor` points to a writable SECURITY_DESCRIPTOR that lives
    // until the end of this function; `merged` is a valid ACL that lives as long.
    unsafe {
        InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION)?;
        SetSecurityDescriptorDacl(descriptor, true, Some(merged), false)?;
        SetFileSecurityW(&wide, DACL_SECURITY_INFORMATION, descriptor).ok()?;
    }
    Ok(())
}

/// The only revision of security descriptors.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// Read, write and delete a file.
const MODIFY: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0;

pub(crate) fn allow(container: &str, path: &Path, access: crate::Access) -> io::Result<()> {
    let entries: &[(u32, ACE_FLAGS)] = match access {
        crate::Access::ReadExecute => {
            &[(FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0, NO_INHERITANCE)]
        }
        crate::Access::Modify => &[(MODIFY, NO_INHERITANCE)],
        crate::Access::CreateFiles => &[
            // The directory itself: pass through it and add files, but neither
            // list it nor touch what is in it.
            (
                FILE_ADD_FILE.0
                    | FILE_TRAVERSE.0
                    | FILE_READ_ATTRIBUTES.0
                    | READ_CONTROL.0
                    | SYNCHRONIZE.0,
                NO_INHERITANCE,
            ),
            // Files created in it from now on.
            (MODIFY, OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE),
        ],
    };
    add_entries(container, path, entries)
}

/// Whether this process runs inside an AppContainer.
pub(crate) fn is_sandboxed() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that is always valid,
    // and `token` is a valid place to store the result.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let token = owned(token);
    let mut value = 0u32;
    let mut len = 0u32;
    // SAFETY: `value` is a writable `u32`, which is what `TokenIsAppContainer`
    // returns, and its size is passed along.
    let queried = unsafe {
        GetTokenInformation(
            raw(&token),
            TokenIsAppContainer,
            Some((&raw mut value).cast()),
            size_of::<u32>() as u32,
            &mut len,
        )
    };
    queried.is_ok() && value != 0
}

/// Appends `arg` to a command line the way the C runtime (and Rust) parse it.
fn append_quoted(line: &mut Vec<u16>, arg: &OsStr) {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    let units: Vec<u16> = arg.encode_wide().collect();
    let plain = !units.is_empty()
        && !units
            .iter()
            .any(|&unit| unit == b' ' as u16 || unit == b'\t' as u16 || unit == QUOTE);
    if plain {
        line.extend_from_slice(&units);
        return;
    }
    line.push(QUOTE);
    let mut backslashes = 0;
    for &unit in &units {
        if unit == BACKSLASH {
            backslashes += 1;
        } else {
            if unit == QUOTE {
                // Backslashes before a quote are doubled, and the quote escaped.
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(unit);
    }
    // Backslashes before the closing quote are doubled.
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
    line.push(QUOTE);
}

fn command_line(program: &Path, args: &[OsString]) -> Vec<u16> {
    let mut line = Vec::new();
    append_quoted(&mut line, program.as_os_str());
    for arg in args {
        line.push(b' ' as u16);
        append_quoted(&mut line, arg);
    }
    line.push(0);
    line
}

/// A process attribute list with room for one attribute.
struct AttributeList {
    // `u64` elements give the buffer pointer alignment.
    buffer: Vec<u64>,
}

impl AttributeList {
    fn new() -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: a null list with a size out-parameter asks for the size needed.
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut list = Self {
            buffer: vec![0u64; size.div_ceil(8)],
        };
        // SAFETY: the buffer is writable and at least `size` bytes long.
        unsafe { InitializeProcThreadAttributeList(Some(list.as_ptr()), 1, None, &mut size) }?;
        Ok(list)
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buffer.as_mut_ptr().cast())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialised in `new` and is not used afterwards.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// A running sandboxed process.
pub(crate) struct Child {
    process: OwnedHandle,
    id: u32,
}

impl Child {
    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    /// Waits for the process to end and returns its exit code.
    pub(crate) fn wait(&self) -> io::Result<u32> {
        // SAFETY: `process` is a valid process handle with SYNCHRONIZE access.
        let waited = unsafe { WaitForSingleObject(raw(&self.process), INFINITE) };
        if waited != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        self.exit_code()
    }

    /// The exit code if the process has ended.
    pub(crate) fn try_wait(&self) -> io::Result<Option<u32>> {
        // SAFETY: as in `wait`; a timeout of zero only polls.
        let waited = unsafe { WaitForSingleObject(raw(&self.process), 0) };
        if waited == WAIT_TIMEOUT {
            return Ok(None);
        }
        if waited != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        self.exit_code().map(Some)
    }

    fn exit_code(&self) -> io::Result<u32> {
        let mut code = 0u32;
        // SAFETY: `process` is a valid process handle and `code` a valid place
        // for the result.
        unsafe { GetExitCodeProcess(raw(&self.process), &mut code) }?;
        Ok(code)
    }

    pub(crate) fn kill(&self) -> io::Result<()> {
        // SAFETY: `process` is a valid process handle with terminate access.
        unsafe { TerminateProcess(raw(&self.process), 1) }?;
        Ok(())
    }
}

/// Starts `program` in the AppContainer `container`, with no capabilities: no
/// network, and access only to what was explicitly granted to the container.
/// The process has no console and inherits no handles.
pub(crate) fn spawn(container: &str, program: &Path, args: &[OsString]) -> io::Result<Child> {
    let sid = ContainerSid::with_profile(container)?;
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid.0,
        ..SECURITY_CAPABILITIES::default()
    };
    let mut attributes = AttributeList::new()?;
    // SAFETY: the list was initialised for one attribute; `capabilities` and the
    // SID it points to outlive both this call and `CreateProcessW` below.
    unsafe {
        UpdateProcThreadAttribute(
            attributes.as_ptr(),
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some((&raw const capabilities).cast()),
            size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
    }?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.as_ptr();

    let application: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
    let mut line = command_line(program, args);
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: `application` and `line` are null-terminated wide strings (`line`
    // is writable, as the API requires); `startup` is a STARTUPINFOEXW, which
    // EXTENDED_STARTUPINFO_PRESENT announces; `information` receives the result.
    unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(line.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            None,
            PCWSTR::null(),
            (&raw const startup).cast(),
            &mut information,
        )
    }?;
    drop(owned(information.hThread));
    Ok(Child {
        process: owned(information.hProcess),
        id: information.dwProcessId,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted(arg: &str) -> String {
        let mut line = Vec::new();
        append_quoted(&mut line, OsStr::new(arg));
        String::from_utf16(&line).unwrap()
    }

    #[test]
    fn arguments_are_quoted_as_the_c_runtime_expects() {
        assert_eq!(quoted("plain"), "plain");
        assert_eq!(quoted(r"C:\dir\file.exe"), r"C:\dir\file.exe");
        assert_eq!(quoted(""), r#""""#);
        assert_eq!(quoted("two words"), r#""two words""#);
        assert_eq!(quoted(r"C:\my dir\"), r#""C:\my dir\\""#);
        assert_eq!(quoted(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quoted(r#"a\"b c"#), r#""a\\\"b c""#);
    }

    #[test]
    fn the_test_process_itself_is_not_sandboxed() {
        assert!(!is_sandboxed());
    }

    #[test]
    fn a_container_has_a_stable_sid() {
        let first = container_sid("ZeroPass.Test.Probe").unwrap();
        let second = container_sid("ZeroPass.Test.Probe").unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("S-1-15-2-"), "{first}");
        assert_ne!(first, container_sid("ZeroPass.Vault").unwrap());
    }
}
