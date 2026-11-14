//! The real daemon binary, from the outside: who may connect, and that only one
//! daemon serves a vault. What the daemon does for an admitted client is
//! covered by the end-to-end tests of `zp-cli`, which is on its list.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Stdio};

use zp_ipc::proto::{self, request, response};
use zp_ipc::{Client, DaemonPolicy, Endpoint, IpcError};

const DAEMON: &str = env!("CARGO_BIN_EXE_zp-vaultd");

/// Whether this platform tells the daemon which executable connects
/// (`docs/spec/ipc.md` §3.3).
const IDENTIFIES_PEERS: bool = cfg!(any(windows, target_os = "linux"));

struct Daemon {
    child: Child,
    log: BufReader<ChildStderr>,
    endpoint: Endpoint,
    _dir: tempfile::TempDir,
}

fn command(vault: &Path) -> Command {
    let mut command = Command::new(DAEMON);
    command
        .arg("--vault")
        .arg(vault)
        .arg("--no-hardware-keystore")
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

impl Daemon {
    /// Starts the daemon for a vault file that does not exist yet and waits
    /// until it listens.
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("test.zpvault");
        let mut child = command(&vault).spawn().unwrap();
        let log = BufReader::new(child.stderr.take().unwrap());
        let mut daemon = Self {
            child,
            log,
            endpoint: Endpoint::for_vault(&vault).unwrap(),
            _dir: dir,
        };
        // It says what it hardened, then that it serves.
        loop {
            let line = daemon.log_line();
            assert!(!line.is_empty(), "the daemon ended before it served");
            if line.contains("serving") {
                break;
            }
        }
        daemon
    }

    fn vault(&self) -> std::path::PathBuf {
        self._dir.path().join("test.zpvault")
    }

    fn log_line(&mut self) -> String {
        let mut line = String::new();
        self.log.read_line(&mut line).unwrap();
        line
    }

    /// Connects as this test binary, which trusts the daemon under test.
    fn connect(&self) -> Result<Client, IpcError> {
        let policy = DaemonPolicy::default().allow(DAEMON);
        Client::connect(&self.endpoint, &policy, "test")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_program_that_is_not_installed_beside_the_daemon_is_refused() {
    let mut daemon = Daemon::start();
    if !IDENTIFIES_PEERS {
        // Here the operating system only guarantees the same user: the client
        // is admitted. Stop the daemon through it.
        let mut client = daemon.connect().unwrap();
        match client
            .call(request::Body::Status(proto::Status {}))
            .unwrap()
        {
            response::Body::Status(status) => assert!(!status.vault_exists),
            other => panic!("unexpected reply: {other:?}"),
        }
        client
            .call(request::Body::Shutdown(proto::Shutdown {}))
            .unwrap();
        assert!(daemon.child.wait().unwrap().success());
        return;
    }

    // This test binary is not one of the executables beside the daemon.
    for _ in 0..2 {
        assert!(matches!(daemon.connect(), Err(IpcError::Refused(_))));
        let line = daemon.log_line();
        assert!(line.contains("refused a connection from"), "{line}");
        let this = std::env::current_exe().unwrap();
        let name = this.file_name().unwrap().to_string_lossy().into_owned();
        assert!(line.contains(&name), "{line}");
    }
    // It keeps running, and nothing was created.
    assert!(daemon.child.try_wait().unwrap().is_none());
    assert!(!daemon.vault().exists());
}

#[test]
fn a_second_daemon_for_the_same_vault_does_not_start() {
    let mut daemon = Daemon::start();
    let output = command(&daemon.vault()).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already running"), "{stderr}");
    // The first one is unaffected.
    assert!(daemon.child.try_wait().unwrap().is_none());

    // Another vault gets its own daemon.
    let other = Daemon::start();
    assert_ne!(other.endpoint, daemon.endpoint);
}

#[test]
fn the_daemon_needs_a_vault_path() {
    let output = Command::new(DAEMON)
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--vault"));
}

#[test]
fn another_program_of_the_user_cannot_read_the_memory_of_the_daemon() {
    let daemon = Daemon::start();
    // The control: this test process did nothing to protect itself.
    let Some(own) = zp_sandbox::can_read_memory_of(std::process::id()) else {
        // This platform has no such protection yet (docs/spec/hardening.md).
        return;
    };
    assert!(own, "a process can normally be opened by its user");
    assert_eq!(
        zp_sandbox::can_read_memory_of(daemon.child.id()),
        Some(false)
    );
}
