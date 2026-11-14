//! Copying a secret to the clipboard, and taking it off again
//! (`docs/spec/hardening.md` §4).

use std::io::Write;
use std::process::Command as Process;
use std::thread;
use std::time::Duration;

use zp_clipboard::Copied;

use super::CliResult;

/// How long a copied secret stays on the clipboard, in seconds.
pub(crate) const CLEAR_AFTER_SECS: u64 = 30;

/// Copies `secret` to the clipboard and leaves a helper process behind that
/// clears the clipboard later, also if this process has long ended. `what`
/// names the secret for the message, such as "password".
pub(crate) fn copy(secret: &str, what: &str, out: &mut impl Write) -> CliResult<()> {
    let copied = zp_clipboard::copy_secret(secret)?;
    let mut helper = Process::new(std::env::current_exe()?);
    helper
        .arg("clipboard-clear")
        .arg("--after")
        .arg(CLEAR_AFTER_SECS.to_string())
        .arg("--token")
        .arg(copied.token().to_string());
    match zp_ipc::spawn_detached(&mut helper) {
        Ok(()) => writeln!(
            out,
            "{what} copied to the clipboard; it is removed from there in {CLEAR_AFTER_SECS} seconds"
        )?,
        Err(error) => writeln!(
            out,
            "{what} copied to the clipboard; it could NOT be arranged to remove it later ({error})"
        )?,
    }
    Ok(())
}

/// `clipboard-clear`: what the helper process does. Waits, then empties the
/// clipboard unless the user has copied something else in the meantime.
pub(crate) fn clear_later(after_secs: u64, token: u32) -> CliResult<()> {
    thread::sleep(Duration::from_secs(after_secs));
    zp_clipboard::clear_if_unchanged(Copied::from_token(token))?;
    Ok(())
}
