//! The real clipboard of this session.
//!
//! These tests replace what the user has on the clipboard (and put text back
//! afterwards), so they only run when asked to:
//!
//! ```text
//! ZEROPASS_TEST_CLIPBOARD=1 cargo test -p zp-clipboard
//! ```

#![cfg(windows)]
#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use zp_clipboard::{Copied, clear_if_unchanged, copy_secret, set_text, text};

fn enabled() -> bool {
    std::env::var_os("ZEROPASS_TEST_CLIPBOARD").is_some()
}

/// Puts the user's text back when the test ends.
struct Restore(Option<String>);

impl Drop for Restore {
    fn drop(&mut self) {
        if let Some(text) = &self.0 {
            let _ = set_text(text);
        }
    }
}

#[test]
fn a_secret_is_copied_and_cleared_unless_something_else_was_copied() {
    if !enabled() {
        return;
    }
    let _restore = Restore(text().unwrap());

    // Copied, and cleared while it is still there.
    let copied = copy_secret("hunter2 – パスワード").unwrap();
    assert_eq!(text().unwrap().as_deref(), Some("hunter2 – パスワード"));
    assert!(clear_if_unchanged(copied).unwrap());
    assert_eq!(text().unwrap(), None);
    // Clearing again finds a clipboard that has changed (it was emptied).
    assert!(!clear_if_unchanged(copied).unwrap());

    // The user copies something else before the time is up: left alone.
    let copied = copy_secret("another secret").unwrap();
    set_text("the user's own text").unwrap();
    assert!(!clear_if_unchanged(copied).unwrap());
    assert_eq!(text().unwrap().as_deref(), Some("the user's own text"));

    // The token survives the trip to another process.
    let copied = copy_secret("a third secret").unwrap();
    let token = copied.token();
    assert!(clear_if_unchanged(Copied::from_token(token)).unwrap());
    assert_eq!(text().unwrap(), None);
}
