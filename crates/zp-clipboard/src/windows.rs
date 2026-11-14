//! The Windows clipboard.
//!
//! This is the only module in the crate that may use `unsafe`: the clipboard
//! API has no safe wrapper in the standard library.
#![allow(unsafe_code)]

use std::io;
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows::core::HSTRING;
use zeroize::Zeroizing;

/// The standard clipboard format for UTF-16 text.
const CF_UNICODETEXT: u32 = 13;

/// Formats that tell Windows how to treat what is on the clipboard. Clipboard
/// managers that follow the convention leave such content alone.
const EXCLUDE_FROM_MONITORS: &str = "ExcludeClipboardContentFromMonitorProcessing";
const INCLUDE_IN_HISTORY: &str = "CanIncludeInClipboardHistory";
const UPLOAD_TO_CLOUD: &str = "CanUploadToCloudClipboard";

/// The clipboard, open for this thread; closed on drop.
struct Open;

impl Open {
    /// Opens the clipboard. Only one program can have it open at a time, so
    /// this tries for a moment.
    fn new() -> io::Result<Self> {
        let mut attempt = 0;
        loop {
            // SAFETY: plain call; no window owns the clipboard for this thread.
            match unsafe { OpenClipboard(None) } {
                Ok(()) => return Ok(Self),
                Err(_) if attempt < 20 => {
                    attempt += 1;
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: this thread opened the clipboard in `new`.
        let _ = unsafe { CloseClipboard() };
    }
}

/// Puts `bytes` on the open clipboard in `format`.
fn put(_open: &Open, format: u32, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: plain call; failure is reported through the result.
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)) }?;
    // SAFETY: `memory` is a valid movable block of at least `bytes.len()`
    // bytes; it is locked while it is written and unlocked afterwards.
    unsafe {
        let target = GlobalLock(memory).cast::<u8>();
        if target.is_null() {
            let error = io::Error::last_os_error();
            let _ = GlobalFree(Some(memory));
            return Err(error);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), target, bytes.len());
        // "Failure" here means the lock count reached zero, which is the aim.
        let _ = GlobalUnlock(memory);
    }
    // SAFETY: the clipboard is open (witnessed by `_open`) and `memory` is a
    // valid block. On success the system owns the block.
    match unsafe { SetClipboardData(format, Some(HANDLE(memory.0))) } {
        Ok(_) => Ok(()),
        Err(error) => {
            // SAFETY: the system did not take the block; it is still ours.
            let _ = unsafe { GlobalFree(Some(memory)) };
            Err(error.into())
        }
    }
}

fn registered(name: &str) -> io::Result<u32> {
    // SAFETY: the name is a valid, null-terminated wide string.
    match unsafe { RegisterClipboardFormatW(&HSTRING::from(name)) } {
        0 => Err(io::Error::last_os_error()),
        format => Ok(format),
    }
}

/// Replaces the clipboard with `text`, marked as not to be kept in the
/// clipboard history nor synced to other devices. Returns the clipboard's
/// sequence number afterwards.
pub(crate) fn copy_secret(text: &str) -> io::Result<u32> {
    let wide: Zeroizing<Vec<u16>> = Zeroizing::new(text.encode_utf16().chain([0]).collect());
    let bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(wide.iter().flat_map(|unit| unit.to_le_bytes()).collect());
    {
        let open = Open::new()?;
        // SAFETY: the clipboard is open for this thread.
        unsafe { EmptyClipboard() }?;
        // The markers first: a monitor that looks as soon as text appears
        // already finds them.
        put(&open, registered(EXCLUDE_FROM_MONITORS)?, &[0])?;
        put(&open, registered(INCLUDE_IN_HISTORY)?, &0u32.to_le_bytes())?;
        put(&open, registered(UPLOAD_TO_CLOUD)?, &0u32.to_le_bytes())?;
        put(&open, CF_UNICODETEXT, &bytes)?;
    }
    Ok(sequence())
}

/// A number that changes whenever the content of the clipboard changes.
pub(crate) fn sequence() -> u32 {
    // SAFETY: plain call.
    unsafe { GetClipboardSequenceNumber() }
}

/// Empties the clipboard.
pub(crate) fn clear() -> io::Result<()> {
    let _open = Open::new()?;
    // SAFETY: the clipboard is open for this thread.
    unsafe { EmptyClipboard() }?;
    Ok(())
}

/// The text on the clipboard, if there is text.
pub(crate) fn text() -> io::Result<Option<String>> {
    let _open = Open::new()?;
    // SAFETY: plain call.
    if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) }.is_err() {
        return Ok(None);
    }
    // SAFETY: the clipboard is open. The returned block belongs to the
    // clipboard and stays valid until the clipboard is closed.
    let memory = HGLOBAL(unsafe { GetClipboardData(CF_UNICODETEXT) }?.0);
    // SAFETY: `memory` is a valid block holding UTF-16 text; it is read within
    // its size, while locked, and unlocked afterwards.
    let text = unsafe {
        let source = GlobalLock(memory).cast::<u16>();
        if source.is_null() {
            return Err(io::Error::last_os_error());
        }
        let units = std::slice::from_raw_parts(source, GlobalSize(memory) / 2);
        let end = units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len());
        let text = String::from_utf16_lossy(&units[..end]);
        let _ = GlobalUnlock(memory);
        text
    };
    Ok(Some(text))
}
