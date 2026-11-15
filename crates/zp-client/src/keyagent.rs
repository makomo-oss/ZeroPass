//! The key agent (`docs/spec/ipc.md` §13): a small program beside the client
//! that asks the platform's hardware key store (Windows Hello) for the vault
//! daemon, which cannot reach it from its sandbox. A client starts it for the
//! operations that need the store and never sees what it signs.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use zp_ipc::KEY_AGENT_NAME;

use crate::{Error, KeyStoreChoice, Result, sibling};

/// How long the agent may take to attach to the vault daemon.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the agent has to end by itself before it is ended.
const EXIT_TIMEOUT: Duration = Duration::from_secs(2);

/// A running key agent. It ends when this is dropped.
#[derive(Debug)]
pub struct KeyAgent {
    child: Child,
}

impl KeyAgent {
    /// Starts the key agent for the daemon of `vault`, which must be running,
    /// and waits until the daemon uses it. `None` if this vault's daemon does
    /// not use the platform's key store.
    ///
    /// The agent shares this process's console: what it reports appears on
    /// this process's standard error. In a windowed process
    /// ([`crate::set_windowed`]) it gets no console window instead, and what
    /// it reports becomes part of the error if it does not attach.
    pub fn start(vault: &Path, choice: KeyStoreChoice) -> Result<Option<Self>> {
        let quiet = crate::is_windowed();
        // Only Windows has a hardware key store implementation so far
        // (`zp-hwkey`); elsewhere the daemon has none to ask.
        if choice != KeyStoreChoice::Platform || !cfg!(windows) {
            return Ok(None);
        }
        let executable = sibling(KEY_AGENT_NAME)?;
        let failed = |why: &dyn std::fmt::Display| {
            Error::message(format!(
                "cannot start the key agent ({}): {why}",
                executable.display()
            ))
        };
        let mut command = Command::new(&executable);
        command
            .arg("--vault")
            .arg(std::path::absolute(vault)?)
            .env_remove("ZEROPASS_VAULT")
            // The agent ends when this end closes, which it does at the
            // latest when this process is gone.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if quiet {
            command.stderr(Stdio::piped());
            no_console_window(&mut command);
        } else {
            command.stderr(Stdio::inherit());
        }
        let mut child = command.spawn().map_err(|error| failed(&error))?;
        let stdout = child.stdout.take();
        let reported = Arc::new(Mutex::new(String::new()));
        let mut draining = None;
        if let Some(mut stderr) = child.stderr.take() {
            let reported = Arc::clone(&reported);
            // Drains it for as long as the agent runs, so that it never
            // blocks on a full pipe.
            draining = Some(thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                while let Ok(n @ 1..) = stderr.read(&mut buffer) {
                    let mut text = reported.lock().unwrap_or_else(|poison| poison.into_inner());
                    // Enough to say why; never grows without bound.
                    if text.len() < 4096 {
                        text.push_str(&String::from_utf8_lossy(&buffer[..n]));
                    }
                }
            }));
        }
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
        // Only once the agent has ended: what it said is all there then.
        let mut why = |default: &str| {
            if let Some(draining) = draining.take() {
                let _ = draining.join();
            }
            let text = reported.lock().unwrap_or_else(|poison| poison.into_inner());
            let text = text.trim();
            if text.is_empty() {
                default.to_owned()
            } else {
                format!("{default}: {text}")
            }
        };
        match ready.recv_timeout(ATTACH_TIMEOUT) {
            Ok(true) => Ok(Some(agent)),
            // It said why on standard error.
            Ok(false) => {
                agent.end();
                Err(failed(&why("it did not attach to the vault daemon")))
            }
            Err(_) => {
                agent.end();
                Err(failed(&why(
                    "it did not attach to the vault daemon in time",
                )))
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

/// Keeps a console program started from a windowed one from opening a
/// console window of its own.
pub(crate) fn no_console_window(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = command;
}
