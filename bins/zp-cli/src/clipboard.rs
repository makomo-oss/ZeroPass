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
    if cfg!(target_os = "linux") {
        return copy_through_helper(secret, what, out);
    }
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

/// On Linux the program that copied hands the text over to whoever pastes,
/// and the text is gone when it ends (`zp_clipboard`): a helper process,
/// given the secret through a pipe, copies it and stays until it clears it.
fn copy_through_helper(secret: &str, what: &str, out: &mut impl Write) -> CliResult<()> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let mut command = Process::new(std::env::current_exe()?);
    command
        .arg("clipboard-serve")
        .arg("--after")
        .arg(CLEAR_AFTER_SECS.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Not reached by the signals of this terminal (Ctrl+C after the copy).
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut helper = command.spawn()?;
    let (Some(mut input), Some(answer)) = (helper.stdin.take(), helper.stdout.take()) else {
        let _ = helper.kill();
        return Err(std::io::Error::other("the clipboard helper has no pipes").into());
    };
    input.write_all(secret.as_bytes())?;
    drop(input);
    // The helper answers with one line once the text is on the clipboard.
    let mut line = String::new();
    BufReader::new(answer).read_line(&mut line)?;
    match line.trim_end() {
        "ok" => writeln!(
            out,
            "{what} copied to the clipboard; it is removed from there in {CLEAR_AFTER_SECS} seconds"
        )?,
        "" => {
            return Err(std::io::Error::other("the clipboard helper ended without copying").into());
        }
        error => return Err(std::io::Error::other(format!("cannot copy: {error}")).into()),
    }
    Ok(())
}

/// `clipboard-serve`: what the helper of [`copy_through_helper`] does.
pub(crate) fn serve(after_secs: u64) -> CliResult<()> {
    use std::io::Read;

    let mut secret = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut secret)?;
    let mut answer = std::io::stdout().lock();
    let copied = match zp_clipboard::copy_secret(&secret) {
        Ok(copied) => copied,
        Err(error) => {
            writeln!(answer, "{error}")?;
            return Ok(());
        }
    };
    drop(secret);
    writeln!(answer, "ok")?;
    answer.flush()?;
    drop(answer);
    thread::sleep(Duration::from_secs(after_secs));
    zp_clipboard::clear_if_unchanged(copied)?;
    Ok(())
}

/// `clipboard-clear`: what the helper process does. Waits, then empties the
/// clipboard unless the user has copied something else in the meantime.
pub(crate) fn clear_later(after_secs: u64, token: u32) -> CliResult<()> {
    thread::sleep(Duration::from_secs(after_secs));
    zp_clipboard::clear_if_unchanged(Copied::from_token(token))?;
    Ok(())
}
