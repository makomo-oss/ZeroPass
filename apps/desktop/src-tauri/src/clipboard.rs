//! Copying a secret to the clipboard, and taking it off again
//! (`docs/spec/hardening.md` §4). The secret goes from the daemon's answer to
//! the clipboard here, never through the page.

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use zp_clipboard::Copied;

/// How long a copied secret stays on the clipboard.
pub(crate) const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// What this application copied last and has not cleared yet.
static PENDING: Mutex<Option<Copied>> = Mutex::new(None);

fn pending() -> std::sync::MutexGuard<'static, Option<Copied>> {
    PENDING.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Copies `secret`, kept out of the clipboard history and cloud sync, and
/// clears the clipboard after [`CLEAR_AFTER`] unless something else was
/// copied in the meantime.
pub(crate) fn copy(secret: &str) -> std::io::Result<()> {
    if !zp_clipboard::SUPPORTED {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "copying secrets is not supported on this platform yet",
        ));
    }
    let copied = zp_clipboard::copy_secret(secret)?;
    *pending() = Some(copied);
    thread::spawn(move || {
        thread::sleep(CLEAR_AFTER);
        let mut pending = pending();
        if *pending == Some(copied) {
            let _ = zp_clipboard::clear_if_unchanged(copied);
            *pending = None;
        }
    });
    Ok(())
}

/// Clears what this application copied, if it is still on the clipboard. For
/// when the application ends before the timer does.
pub(crate) fn clear_now() {
    if let Some(copied) = pending().take() {
        let _ = zp_clipboard::clear_if_unchanged(copied);
    }
}
