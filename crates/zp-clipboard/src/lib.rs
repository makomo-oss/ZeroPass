//! Copies secrets to the clipboard so that they do not stay there
//! (`docs/spec/hardening.md` §4).
//!
//! A password on the clipboard is readable by every program of the user, and
//! clipboard histories and cloud clipboards keep it around. So a secret is
//! copied with the request not to record it ([`copy_secret`]), and is removed
//! again after a while unless the user has copied something else since
//! ([`clear_if_unchanged`]).
//!
//! | Platform | Status |
//! |---|---|
//! | Windows | available |
//! | macOS | planned (P6-09) |
//! | Linux | planned (P6-10) |

#[cfg(windows)]
mod windows;

use std::io;

/// Whether this platform has a clipboard implementation.
pub const SUPPORTED: bool = cfg!(windows);

/// What the clipboard held right after a secret was copied: enough to tell
/// later whether it still holds that secret, without looking at the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Copied(u32);

impl Copied {
    /// A number that stands for this state of the clipboard, to hand to
    /// another process that will clear it.
    pub fn token(self) -> u32 {
        self.0
    }

    /// Rebuilds the value from [`Self::token`].
    pub fn from_token(token: u32) -> Self {
        Self(token)
    }
}

#[cfg(not(windows))]
fn unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the clipboard is not supported on this platform yet",
    ))
}

/// Replaces the content of the clipboard with `secret`, asking the system not
/// to keep it in the clipboard history and not to sync it to other devices.
pub fn copy_secret(secret: &str) -> io::Result<Copied> {
    #[cfg(windows)]
    {
        windows::copy_secret(secret).map(Copied)
    }
    #[cfg(not(windows))]
    {
        let _ = secret;
        unsupported()
    }
}

/// Empties the clipboard if it still holds what [`copy_secret`] put there.
/// Returns whether it was emptied; if the user has copied something else in
/// the meantime, that is left alone.
pub fn clear_if_unchanged(copied: Copied) -> io::Result<bool> {
    #[cfg(windows)]
    {
        if windows::sequence() != copied.0 {
            return Ok(false);
        }
        windows::clear().map(|()| true)
    }
    #[cfg(not(windows))]
    {
        let _ = copied;
        unsupported()
    }
}

/// The text on the clipboard, if it holds text.
pub fn text() -> io::Result<Option<String>> {
    #[cfg(windows)]
    {
        windows::text()
    }
    #[cfg(not(windows))]
    {
        unsupported()
    }
}

/// Replaces the content of the clipboard with ordinary text, without the
/// treatment of a secret.
pub fn set_text(text: &str) -> io::Result<()> {
    // The only difference to a secret would be the history markers, and no
    // caller needs ordinary text to appear in the history.
    copy_secret(text).map(|_| ())
}
