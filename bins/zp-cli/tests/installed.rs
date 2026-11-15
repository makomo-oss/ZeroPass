//! The programs as installed under Program Files (ADR-0008), where the user
//! may run them but not change their access rights. The client must still
//! start the vault daemon in its sandbox, and the daemon its workers.
//!
//! The installed directory is imitated: the programs are copied to a
//! temporary directory and given the access rights they get under Program
//! Files, with "OWNER RIGHTS" limited to reading and running, so that not even
//! the user who copied them can change those rights.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]
#![cfg(windows)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod common;

const PASSWORD: &str = "correct horse battery staple";
const TOTP_URI: &str =
    "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

/// Copies the programs to `dir` and gives them the rights they get under
/// Program Files.
fn install(dir: &Path) {
    let built = Path::new(env!("CARGO_BIN_EXE_zp-cli")).parent().unwrap();
    for name in ["zp-cli", "zp-vaultd", "zp-syncd", "zp-keyagent"] {
        let file = format!("{name}.exe");
        let target = dir.join(&file);
        std::fs::copy(built.join(&file), &target).unwrap();
        // Owner: read and run only. Every app container: read and run (what
        // Program Files grants). The system: everything.
        let status = Command::new("icacls")
            .arg(&target)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-3-4:(RX)",
                "*S-1-15-2-1:(RX)",
                "*S-1-5-18:(F)",
            ])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "icacls failed on {}", target.display());
    }
}

fn cli(program: &Path, vault: &Path, args: &[&str], input: &[&str]) -> String {
    let mut child = Command::new(program)
        .arg("--vault")
        .arg(vault)
        .arg("--insecure-software-keystore")
        .args(args)
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for line in input {
        if writeln!(stdin, "{line}").is_err() {
            break;
        }
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

struct StopDaemon(PathBuf, PathBuf);

impl Drop for StopDaemon {
    fn drop(&mut self) {
        let _ = Command::new(&self.0)
            .arg("--vault")
            .arg(&self.1)
            .args(["daemon", "stop"])
            .env_remove("ZEROPASS_VAULT")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
fn the_daemon_runs_from_a_directory_whose_rights_the_user_cannot_change() {
    common::daemon_is_built();
    let dir = tempfile::tempdir().unwrap();
    let programs = dir.path().join("ZeroPass");
    std::fs::create_dir(&programs).unwrap();
    install(&programs);
    let daemon = programs.join("zp-vaultd.exe");
    // The imitation holds for a standard user: the container cannot be given
    // access. An administrator (as CI runs) can still change the rights; the
    // rest of the test runs all the same, and the CI install test runs the
    // client as a standard user under Program Files.
    if !zp_sandbox::runs_as_administrator() {
        let granted = zp_sandbox::allow(
            zp_ipc::DAEMON_SANDBOX,
            &daemon,
            zp_sandbox::Access::ReadExecute,
        );
        assert_eq!(
            granted.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    let program = programs.join("zp-cli.exe");
    let vault_dir = dir.path().join("Vault");
    std::fs::create_dir(&vault_dir).unwrap();
    let vault = vault_dir.join("vault.zpvault");
    let _stop = StopDaemon(program.clone(), vault.clone());

    cli(&program, &vault, &["init"], &[PASSWORD, PASSWORD]);
    let status = cli(&program, &vault, &["daemon", "status"], &[]);
    assert!(status.contains("sandbox: yes"), "{status}");
    // The TOTP domain lives in a worker, which the daemon starts from the
    // same directory, inside its sandbox.
    let added = cli(&program, &vault, &["add", "totp"], &[TOTP_URI]);
    let id = added.trim().strip_prefix("added ").unwrap().to_owned();
    let code = cli(&program, &vault, &["totp", &id], &[]);
    assert_eq!(code.split_whitespace().next().unwrap().len(), 6, "{code}");
    let login = cli(
        &program,
        &vault,
        &["add", "login", "--title", "Bank"],
        &[PASSWORD, "bank-password-123"],
    );
    assert!(login.starts_with("added "), "{login}");
}
