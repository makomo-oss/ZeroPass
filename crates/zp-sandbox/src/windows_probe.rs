//! Windows: looking for bytes in the memory of another process, for the
//! tests that check where key material is and is not (`probe` feature).
//!
//! This does what a program of the same user can do to a hardened process
//! (`docs/spec/hardening.md` §3): the user owns the process, so the access
//! control list that keeps other programs out can be written back.
//!
//! Like `windows`, this module may use `unsafe`: none of these APIs has a safe
//! wrapper in the standard library.
#![allow(unsafe_code)]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::Security::Authorization::{SE_KERNEL_OBJECT, SetSecurityInfo};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// The right to change the access control list of an object.
const WRITE_DAC: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0004_0000);

fn owned(handle: HANDLE) -> OwnedHandle {
    // SAFETY: every caller passes a valid handle it has just received from the
    // system and does not use or close it by other means afterwards.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

fn open(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> io::Result<OwnedHandle> {
    // SAFETY: plain call; failure is reported through the result.
    let handle = unsafe { OpenProcess(rights, false, pid) }?;
    Ok(owned(handle))
}

/// Opens the process for reading its memory; if its access control list
/// forbids that, removes the list first, as the owner may.
fn open_for_reading(pid: u32) -> io::Result<OwnedHandle> {
    let rights = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    if let Ok(handle) = open(pid, rights) {
        return Ok(handle);
    }
    let process = open(pid, WRITE_DAC)?;
    // SAFETY: the handle is valid and was opened with the right to write the
    // list; no list (a null DACL) grants everyone everything.
    let status = unsafe {
        SetSecurityInfo(
            HANDLE(process.as_raw_handle()),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0 as i32));
    }
    open(pid, rights)
}

/// Whether `needle` occurs in the committed, readable memory of the process
/// `pid`.
pub(crate) fn memory_contains(pid: u32, needle: &[u8]) -> io::Result<bool> {
    const CHUNK: usize = 1 << 20;
    if needle.is_empty() || needle.len() > CHUNK {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let process = open_for_reading(pid)?;
    let process = HANDLE(process.as_raw_handle());
    let mut buffer = vec![0u8; CHUNK + needle.len()];
    let mut address = 0usize;
    loop {
        let mut region = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `region` is a valid place for the result and its size is
        // passed along; any address may be asked about.
        let written = unsafe {
            VirtualQueryEx(
                process,
                Some(address as *const core::ffi::c_void),
                &mut region,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            // Past the end of the address space.
            return Ok(false);
        }
        let start = region.BaseAddress as usize;
        let end = start.saturating_add(region.RegionSize);
        let readable =
            region.State == MEM_COMMIT && (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)).0 == 0;
        if readable {
            // Chunks overlap by the length of the needle, so that an
            // occurrence across a boundary is found.
            let mut at = start;
            while at < end {
                let len = (end - at).min(buffer.len());
                let mut read = 0usize;
                // SAFETY: the buffer is writable and at least `len` bytes
                // long; a failed or partial read is reported, not assumed.
                let ok = unsafe {
                    ReadProcessMemory(
                        process,
                        at as *const core::ffi::c_void,
                        buffer.as_mut_ptr().cast(),
                        len,
                        Some(&mut read),
                    )
                };
                if ok.is_ok()
                    && buffer[..read]
                        .windows(needle.len())
                        .any(|window| window == needle)
                {
                    return Ok(true);
                }
                if end - at <= buffer.len() {
                    break;
                }
                at += CHUNK;
            }
        }
        if end <= address {
            return Ok(false);
        }
        address = end;
    }
}
