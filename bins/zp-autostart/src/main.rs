//! ZeroPass logon launcher (ADR-0008).
//!
//! Windows starts this program when the user logs on (the `Run` key that the
//! installer writes). It has no console, so nothing flashes on the screen: it
//! runs `zp-cli daemon autostart` beside it without a window and waits for it.
//! That command starts the vault daemon, in its sandbox, and the sync daemon,
//! if the user has a vault; only the command-line client knows how to start
//! the vault daemon in its sandbox.
//!
//! Arguments are passed on before the command, so that `--vault <PATH>` names
//! another vault than the default one.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

/// The file name of the command-line client, without the platform's suffix.
const CLI_NAME: &str = "zp-cli";

fn cli() -> std::io::Result<PathBuf> {
    let name = format!("{CLI_NAME}{}", std::env::consts::EXE_SUFFIX);
    Ok(std::env::current_exe()?.with_file_name(name))
}

fn main() -> ExitCode {
    let Ok(cli) = cli() else {
        return ExitCode::FAILURE;
    };
    let mut command = Command::new(cli);
    command
        .args(std::env::args_os().skip(1))
        .args(["daemon", "autostart"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // The client is a console program; without this flag it would open
        // a console window.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
