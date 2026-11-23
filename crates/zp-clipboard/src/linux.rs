//! The clipboard on Linux: the X11 `CLIPBOARD` selection, through `arboard`
//! (under Wayland, XWayland's, which the compositor shares with Wayland
//! programs).
//!
//! On X11 nothing is stored anywhere: the program that copied hands the text
//! to whoever pastes, for as long as it runs and nothing else was copied. So
//! the text leaves the clipboard when the program that copied ends, and a
//! program that ends right after copying (the CLI) leaves a helper behind
//! that keeps it there until it is cleared.

use std::io;
use std::sync::{Mutex, MutexGuard};

use zeroize::Zeroizing;

/// The connection to the clipboard, and what this process copied last.
///
/// The connection is never dropped: dropping the last one hands what this
/// process still serves to a clipboard manager, which would keep the secret.
/// When the process ends, the X server takes the selection away instead.
struct State {
    clipboard: arboard::Clipboard,
    /// The number of the last copy and its text, until it is cleared.
    copied: Option<(u32, Zeroizing<String>)>,
    copies: u32,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn other(error: arboard::Error) -> io::Error {
    io::Error::other(error.to_string())
}

/// The state, with a connection to the clipboard.
fn state() -> io::Result<MutexGuard<'static, Option<State>>> {
    let mut state = STATE.lock().unwrap_or_else(|poison| poison.into_inner());
    if state.is_none() {
        *state = Some(State {
            clipboard: arboard::Clipboard::new().map_err(other)?,
            copied: None,
            copies: 0,
        });
    }
    Ok(state)
}

fn current_text(clipboard: &mut arboard::Clipboard) -> io::Result<Option<String>> {
    match clipboard.get_text() {
        Ok(text) => Ok(Some(text)),
        Err(arboard::Error::ContentNotAvailable) => Ok(None),
        Err(error) => Err(other(error)),
    }
}

pub(crate) fn copy_secret(text: &str) -> io::Result<u32> {
    use arboard::SetExtLinux;

    let mut guard = state()?;
    let Some(state) = guard.as_mut() else {
        return Err(io::Error::other("no clipboard"));
    };
    // Marked for the clipboard managers that keep a history (KDE's and
    // others: `x-kde-passwordManagerHint`), so that they leave it out.
    state
        .clipboard
        .set()
        .exclude_from_history()
        .text(text.to_owned())
        .map_err(other)?;
    state.copies = state.copies.wrapping_add(1).max(1);
    state.copied = Some((state.copies, Zeroizing::new(text.to_owned())));
    Ok(state.copies)
}

pub(crate) fn clear_if_unchanged(copy: u32) -> io::Result<bool> {
    let mut guard = state()?;
    let Some(state) = guard.as_mut() else {
        return Ok(false);
    };
    let Some((last, secret)) = state.copied.take() else {
        return Ok(false);
    };
    if last != copy {
        state.copied = Some((last, secret));
        return Ok(false);
    }
    // X11 tells no sequence number, and clearing takes the selection from
    // whoever has it: clear only if it still holds the secret. (Copying the
    // same text again elsewhere looks the same, and is cleared too.)
    let current = current_text(&mut state.clipboard)?.map(Zeroizing::new);
    if current.as_deref().map(String::as_str) != Some(secret.as_str()) {
        return Ok(false);
    }
    state.clipboard.clear().map_err(other)?;
    Ok(true)
}

pub(crate) fn text() -> io::Result<Option<String>> {
    let mut guard = state()?;
    match guard.as_mut() {
        Some(state) => current_text(&mut state.clipboard),
        None => Ok(None),
    }
}
