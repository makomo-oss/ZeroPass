//! Shared by the tests that run the real `zp-cli`, which in turn starts the real
//! `zp-vaultd` from the directory it is in.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Once;

/// Makes sure the daemon executable is beside `zp-cli` and up to date.
///
/// Cargo builds the binaries of the package under test, but `zp-vaultd` is
/// another package: `cargo test -p zp-cli` alone would not build it.
pub(crate) fn daemon_is_built() {
    static BUILT: Once = Once::new();
    BUILT.call_once(|| {
        let cli = Path::new(env!("CARGO_BIN_EXE_zp-cli"));
        let dir = cli.parent().unwrap();
        let mut cargo = Command::new(env!("CARGO"));
        cargo.args(["build", "--locked", "-p", "zp-vaultd"]);
        if dir.file_name().is_some_and(|name| name == "release") {
            cargo.arg("--release");
        }
        let output = cargo.output().unwrap();
        assert!(
            output.status.success(),
            "building zp-vaultd failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let daemon = dir.join(format!("zp-vaultd{}", std::env::consts::EXE_SUFFIX));
        assert!(daemon.exists(), "{} was not built", daemon.display());
    });
}

/// Stops the daemon of `vault` if one is running, so that it does not outlive
/// the test and the vault file can be deleted.
pub(crate) fn stop_daemon(vault: &Path) {
    let _ = Command::new(env!("CARGO_BIN_EXE_zp-cli"))
        .arg("--vault")
        .arg(vault)
        .args(["daemon", "stop"])
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// What `zp-cli daemon status` prints for the vault at `vault`.
fn daemon_status(vault: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_zp-cli"))
        .arg("--vault")
        .arg(vault)
        .args(["daemon", "status"])
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Ends the daemon of `vault` the hard way, as a crash or a power cut would:
/// no chance to finish what it is writing. Waits until it is gone.
#[allow(
    dead_code,
    reason = "not every test binary that includes this module uses it"
)]
pub(crate) fn kill_daemon(vault: &Path) {
    let status = daemon_status(vault);
    let pid: u32 = status
        .lines()
        .find_map(|line| line.trim().strip_prefix("process: "))
        .and_then(|pid| pid.trim().parse().ok())
        .unwrap_or_else(|| panic!("no process id in: {status}"));
    let killed = if cfg!(windows) {
        Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .status()
    } else {
        Command::new("kill").args(["-9", &pid.to_string()]).status()
    };
    assert!(killed.unwrap().success(), "could not kill process {pid}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !daemon_status(vault).contains("not running") {
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not go away"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
