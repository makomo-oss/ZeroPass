//! The key agent (`docs/spec/ipc.md` §13): a small program beside this one
//! that asks the platform's hardware key store (Windows Hello) for the vault
//! daemon, which cannot reach it from its sandbox. This program starts it for
//! the operations that need the store and never sees what it signs.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use zp_ipc::KEY_AGENT_NAME;

use super::{CliResult, KeyStoreChoice};

/// How long the agent may take to attach to the vault daemon.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the agent has to end by itself before it is ended.
const EXIT_TIMEOUT: Duration = Duration::from_secs(2);

/// A running key agent. It ends when this is dropped.
pub(crate) struct KeyAgent {
    child: Child,
}

impl KeyAgent {
    /// Starts the key agent for the daemon of `vault`, which must be running,
    /// and waits until the daemon uses it. `None` if this vault's daemon does
    /// not use the platform's key store.
    pub(crate) fn start(vault: &Path, choice: KeyStoreChoice) -> CliResult<Option<Self>> {
        // Only Windows has a hardware key store implementation so far
        // (`zp-hwkey`); elsewhere the daemon has none to ask.
        if choice != KeyStoreChoice::Platform || !cfg!(windows) {
            return Ok(None);
        }
        let name = format!("{KEY_AGENT_NAME}{}", std::env::consts::EXE_SUFFIX);
        let executable = std::env::current_exe()?.with_file_name(name);
        let failed = |why: &dyn std::fmt::Display| {
            format!(
                "cannot start the key agent ({}): {why}",
                executable.display()
            )
        };
        let mut child = Command::new(&executable)
            .arg("--vault")
            .arg(std::path::absolute(vault)?)
            .env_remove("ZEROPASS_VAULT")
            // The agent ends when this end closes, which it does at the
            // latest when this process is gone.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| failed(&error))?;
        let stdout = child.stdout.take();
        let mut agent = Self { child };
        let (ready_tx, ready) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let attached = stdout
                .map(BufReader::new)
                .is_some_and(|mut reader| reader.read_line(&mut line).is_ok())
                && line.trim() == "ready";
            let _ = ready_tx.send(attached);
        });
        match ready.recv_timeout(ATTACH_TIMEOUT) {
            Ok(true) => Ok(Some(agent)),
            // It said why on standard error.
            Ok(false) => Err(failed(&"it did not attach to the vault daemon").into()),
            Err(_) => {
                agent.end();
                Err(failed(&"it did not attach to the vault daemon in time").into())
            }
        }
    }

    fn end(&mut self) {
        // Closing its input asks it to end.
        drop(self.child.stdin.take());
        let deadline = Instant::now() + EXIT_TIMEOUT;
        while Instant::now() < deadline {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for KeyAgent {
    fn drop(&mut self) {
        self.end();
    }
}
