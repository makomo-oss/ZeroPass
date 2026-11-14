//! The real sync daemon binary, from the outside: who may use it, that only one
//! serves a vault, and that it protects its memory. What it does for the user
//! interface is covered by the end-to-end tests of `zp-cli`.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};

use zp_ipc::proto::{self, request};
use zp_ipc::{Client, DaemonPolicy, Endpoint, IpcError};

const DAEMON: &str = env!("CARGO_BIN_EXE_zp-syncd");

/// Whether this platform tells the daemon which executable connects
/// (`docs/spec/ipc.md` §3.3).
const IDENTIFIES_PEERS: bool = cfg!(any(windows, target_os = "linux"));

struct Daemon {
    child: Child,
    log: BufReader<ChildStderr>,
    endpoint: Endpoint,
    dir: tempfile::TempDir,
}

fn command(vault: &Path) -> Command {
    let mut command = Command::new(DAEMON);
    command
        .arg("--vault")
        .arg(vault)
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

impl Daemon {
    /// Starts the sync daemon for a vault whose vault daemon is not running:
    /// it serves its endpoint and keeps waiting for the vault daemon.
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("test.zpvault");
        let mut child = command(&vault).spawn().unwrap();
        let log = BufReader::new(child.stderr.take().unwrap());
        let mut daemon = Self {
            child,
            log,
            endpoint: Endpoint::for_sync_daemon(&vault).unwrap(),
            dir,
        };
        // It says that the vault daemon is not there once it serves.
        let line = daemon.log_line();
        assert!(line.contains("vault daemon"), "{line}");
        daemon
    }

    fn vault(&self) -> PathBuf {
        self.dir.path().join("test.zpvault")
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
fn only_a_user_interface_installed_beside_it_may_use_it() {
    let mut daemon = Daemon::start();
    if !IDENTIFIES_PEERS {
        // The operating system only guarantees the same user here.
        let mut client = daemon.connect().unwrap();
        client
            .call(request::Body::SyncdStatus(proto::SyncdStatus {}))
            .unwrap();
        return;
    }
    // This test binary is not one of the programs beside the daemon.
    assert!(matches!(daemon.connect(), Err(IpcError::Refused(_))));
    let line = daemon.log_line();
    assert!(line.contains("refused a connection from"), "{line}");
    assert!(daemon.child.try_wait().unwrap().is_none());
}

#[test]
fn a_second_sync_daemon_for_the_same_vault_does_not_start() {
    let daemon = Daemon::start();
    let output = command(&daemon.vault()).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already running"), "{stderr}");
}

#[test]
fn another_program_of_the_user_cannot_read_its_memory() {
    let daemon = Daemon::start();
    let Some(own) = zp_sandbox::can_read_memory_of(std::process::id()) else {
        // This platform has no such protection yet (docs/spec/hardening.md).
        return;
    };
    assert!(own, "a process can normally be opened by its user");
    // An administrator can open any process; that is outside what the daemon
    // defends against (docs/spec/hardening.md §1), and it is how CI runs.
    if zp_sandbox::runs_as_administrator() {
        return;
    }
    assert_eq!(
        zp_sandbox::can_read_memory_of(daemon.child.id()),
        Some(false)
    );
    // Unlike the vault daemon, it leaves the right to duplicate its handles:
    // Windows needs it to duplicate a socket, and without it the local
    // network discovery stays silent (docs/spec/hardening.md §2.1).
    assert_ne!(
        zp_sandbox::can_duplicate_handles_of(daemon.child.id()),
        Some(false)
    );
}
