//! Windows: what a process does to itself at start-up to be harder to read
//! and to tamper with (`docs/spec/hardening.md`).
//!
//! Like `windows`, this module may use `unsafe`: none of these APIs has a safe
//! wrapper in the standard library.
#![allow(unsafe_code)]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TokenElevation,
    TokenUser,
};
use windows::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
    SetErrorMode, SetUnhandledExceptionFilter,
};
use windows::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories, SetDllDirectoryW,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_MITIGATION_POLICY,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, PROCESS_VM_READ, ProcessDynamicCodePolicy,
    ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
};
use windows::core::{BOOL, HSTRING, PWSTR};

fn owned(handle: HANDLE) -> OwnedHandle {
    // SAFETY: every caller passes a valid handle it has just received from the
    // system and does not use or close it by other means afterwards.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

/// Memory allocated by the system that is released with `LocalFree`.
struct Local(*mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an API that documents `LocalFree` as
        // the way to release it, and it is not used afterwards.
        unsafe {
            LocalFree(Some(HLOCAL(self.0)));
        }
    }
}

/// The SID of the user this process runs as, in string form.
fn user_sid() -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that is always valid,
    // and `token` is a valid place to store the result.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
    let token = owned(token);
    let token = HANDLE(token.as_raw_handle());

    let mut len = 0u32;
    // SAFETY: a null buffer of length 0 is allowed; the call fails and reports
    // the size it needs in `len`.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // `u64` elements give the buffer the alignment of a pointer.
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: the buffer is writable and at least `len` bytes long.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }?;
    // SAFETY: `TOKEN_USER` starts with a pointer to the SID, the buffer is
    // suitably aligned, and the SID lives in the buffer, which outlives its use.
    let sid = unsafe { *buffer.as_ptr().cast::<PSID>() };
    let mut text = PWSTR::null();
    // SAFETY: the SID is valid (see above) and `text` receives a string
    // allocated by the system.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }?;
    let _free = Local(text.0.cast());
    // SAFETY: on success `text` is a valid, null-terminated wide string.
    unsafe { text.to_string() }.map_err(io::Error::other)
}

/// Loads DLLs from the system directory only: not from the directory of the
/// executable, the current directory or `PATH`, where a planted DLL of the
/// same name would be found first.
pub(crate) fn fix_dll_search_path() -> io::Result<()> {
    // SAFETY: plain calls; an empty string removes the current directory from
    // the search order of the legacy loader paths.
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)?;
        SetDllDirectoryW(&HSTRING::new())?;
    }
    Ok(())
}

/// The last resort for an exception nobody handled: end the process without
/// handing it to Windows Error Reporting, which would write its memory to a
/// crash dump.
unsafe extern "system" fn end_without_report(_: *const EXCEPTION_POINTERS) -> i32 {
    /// "Run the handler": for the top-level filter this means the process ends
    /// here, without the error-reporting machinery.
    const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
    EXCEPTION_EXECUTE_HANDLER
}

/// Keeps a crash of this process from producing a dump of its memory or an
/// error dialog.
pub(crate) fn disable_crash_dumps() -> io::Result<()> {
    // SAFETY: plain calls. The filter is a function that lives as long as the
    // process and touches nothing.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        SetUnhandledExceptionFilter(Some(end_without_report));
    }
    Ok(())
}

/// Sets one mitigation policy whose settings are a single word of flags.
fn mitigate(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> io::Result<()> {
    // SAFETY: each policy used with this function is a structure of exactly
    // one `u32` of flags; `flags` outlives the call.
    unsafe { SetProcessMitigationPolicy(policy, (&raw const flags).cast(), size_of::<u32>()) }?;
    Ok(())
}

/// No code may be generated or made executable at run time: injected shellcode
/// has nowhere to run.
pub(crate) fn prohibit_dynamic_code() -> io::Result<()> {
    const PROHIBIT_DYNAMIC_CODE: u32 = 1;
    mitigate(ProcessDynamicCodePolicy, PROHIBIT_DYNAMIC_CODE)
}

/// No legacy extension points: AppInit DLLs, window hooks and the like are not
/// loaded into this process.
pub(crate) fn disable_extension_points() -> io::Result<()> {
    const DISABLE_EXTENSION_POINTS: u32 = 1;
    mitigate(ProcessExtensionPointDisablePolicy, DISABLE_EXTENSION_POINTS)
}

/// No images from network shares, and the system directory first.
pub(crate) fn restrict_image_loads() -> io::Result<()> {
    const NO_REMOTE_IMAGES: u32 = 1;
    const PREFER_SYSTEM32_IMAGES: u32 = 4;
    mitigate(
        ProcessImageLoadPolicy,
        NO_REMOTE_IMAGES | PREFER_SYSTEM32_IMAGES,
    )
}

/// Takes away, from the other processes of the same user, the rights to read
/// and write this process's memory, to start threads in it, to copy its
/// handles and to attach a debugger. What remains: ask which executable it
/// runs (clients check that), ask about it (times, priority: what tools such
/// as `taskkill` and the Task Manager want before they end a process), wait
/// for it, and end it.
///
/// This stops other programs of the user from simply opening the process. It
/// does not stop an administrator, and the user owns the process and could
/// give the rights back: it raises the bar, it is not a wall.
pub(crate) fn protect_memory() -> io::Result<()> {
    let rights = PROCESS_QUERY_LIMITED_INFORMATION.0
        | PROCESS_QUERY_INFORMATION.0
        | PROCESS_SYNCHRONIZE.0
        | PROCESS_TERMINATE.0;
    // D:P — a protected DACL (nothing inherited): the user gets the rights
    // above, the system gets everything (GA).
    let sddl = HSTRING::from(format!("D:P(A;;{rights:#x};;;{})(A;;GA;;;SY)", user_sid()?));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is a valid wide string and `descriptor` receives a
    // descriptor allocated by the system, freed by `_free`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }?;
    let _free = Local(descriptor.0);

    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `descriptor` is the valid descriptor created above; the other
    // arguments are valid places for the results. `dacl` points into it.
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }?;
    // SAFETY: the pseudo handle of this process is always valid and `dacl` is
    // a valid ACL that outlives the call.
    let status = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0 as i32))
    }
}

/// Whether this process is allowed to open the process `pid` for reading its
/// memory.
pub(crate) fn can_read_memory_of(pid: u32) -> bool {
    // SAFETY: plain call; failure is reported through the result.
    match unsafe { OpenProcess(PROCESS_VM_READ, false, pid) } {
        Ok(handle) => {
            drop(owned(handle));
            true
        }
        Err(_) => false,
    }
}

/// Whether the token of this process is elevated (an administrator's full
/// token).
pub(crate) fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that is always valid,
    // and `token` is a valid place to store the result.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let token = owned(token);
    let mut elevated = 0u32;
    let mut len = 0u32;
    // SAFETY: `TokenElevation` returns a structure of one `u32`; `elevated` is
    // a writable `u32` and its size is passed along.
    let queried = unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenElevation,
            Some((&raw mut elevated).cast()),
            size_of::<u32>() as u32,
            &mut len,
        )
    };
    queried.is_ok() && elevated != 0
}
