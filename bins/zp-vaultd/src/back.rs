//! The processes behind the one the clients talk to (ADR-0007).
//!
//! A [`Back`] is one of them, seen from the front: a worker that holds one
//! hardware-bound domain, or the short-lived process that holds every domain
//! for one operation. They are child processes of the front, which talks to
//! each over its standard input and output (`wire`). The unit tests run the
//! same worker code on threads of their own, over the same kind of pipes.

use std::ffi::OsString;
use std::io::{self, PipeReader, PipeWriter};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use zp_crypto::{DomainId, PUBLIC_KEY_LEN};
use zp_ipc::proto::{self, ErrorCode, request, response};
use zp_ipc::{RelayEnd, read_frame, write_frame};

use crate::convert::{domain_from_proto, domain_to_proto};
use crate::port::KeyAgentPort;
use crate::service::{KeyStoreChoice, Scope};
use crate::wire::{Down, Empty, ExportKey, KeyTransfer, Up, down, up};

fn internal(message: impl Into<String>) -> proto::Error {
    proto::Error::new(ErrorCode::Internal, message)
}

fn as_result(reply: response::Body) -> Result<response::Body, proto::Error> {
    match reply {
        response::Body::Error(error) => Err(error),
        reply => Ok(reply),
    }
}

/// One of the processes behind the front.
pub(crate) trait Back: Send {
    /// Has it answer a client's request.
    fn call(&mut self, request: request::Body) -> response::Body;

    /// Has it run a client's relay request.
    fn relay(&mut self, request: request::Body, relay: RelayEnd) -> response::Body;

    /// The public key to seal a vault key to that is meant for it.
    fn import_key(&mut self) -> Result<[u8; PUBLIC_KEY_LEN], proto::Error>;

    /// Unlocks `domain` in it with a key sealed to [`Self::import_key`].
    fn import(&mut self, domain: DomainId, epoch: u32, sealed: Vec<u8>)
    -> Result<(), proto::Error>;

    /// Has it seal the slot key of the unlocked `domain` to `to`.
    fn export(
        &mut self,
        domain: DomainId,
        to: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(u32, Vec<u8>), proto::Error>;

    /// Tells it that the vault file was replaced.
    fn reset(&mut self) -> Result<(), proto::Error>;

    /// Whether `domain` is unlocked in it. `false` if it is not running or
    /// cannot be asked.
    fn unlocked(&mut self, domain: DomainId) -> bool;

    /// Ends it, with whatever keys it holds. It starts again when it is
    /// next needed.
    fn stop(&mut self);
}

/// Starts the processes behind the front.
pub(crate) trait Spawner: Send + Sync {
    /// A process of the given scope. It starts when it is first needed.
    fn back(&self, scope: Scope) -> Box<dyn Back>;
}

/// How a process behind the front is started.
#[derive(Clone)]
enum Launch {
    /// This executable, told which part it plays.
    Executable {
        executable: PathBuf,
        args: Vec<OsString>,
    },
    /// The same code on a thread of this process (unit tests).
    #[cfg(test)]
    Thread {
        vault: PathBuf,
        key_store: KeyStoreChoice,
    },
}

/// A running process and the pipes to it.
struct Live {
    /// `None` for a thread.
    child: Option<Child>,
    to_child: Arc<Mutex<PipeWriter>>,
    from_child: PipeReader,
}

impl Drop for Live {
    fn drop(&mut self) {
        // It also ends by itself when its input closes; do not wait for that
        // with keys in its memory.
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn send(to_child: &Mutex<PipeWriter>, body: down::Body) -> io::Result<()> {
    let mut writer = to_child.lock().unwrap_or_else(|poison| poison.into_inner());
    write_frame(&mut *writer, &Down { body: Some(body) }).map_err(io::Error::other)
}

/// A [`Back`] that is a child process of this one.
pub(crate) struct Process {
    launch: Launch,
    scope: Scope,
    port: Arc<dyn KeyAgentPort>,
    live: Option<Live>,
}

impl Process {
    fn start(&self) -> io::Result<Live> {
        // Anonymous pipes: the daemon's sandbox allows no others.
        let (child_in, to_child) = io::pipe()?;
        let (from_child, child_out) = io::pipe()?;
        let child = match &self.launch {
            Launch::Executable { executable, args } => {
                let mut command = Command::new(executable);
                command
                    .args(args)
                    .stdin(Stdio::from(child_in))
                    .stdout(Stdio::from(child_out))
                    // What it logs goes where this process's log goes.
                    .stderr(Stdio::inherit());
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    // This process has no console; without this flag the
                    // child would get a new one, in a window.
                    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                    command.creation_flags(CREATE_NO_WINDOW);
                }
                Some(command.spawn()?)
            }
            #[cfg(test)]
            Launch::Thread { vault, key_store } => {
                let (vault, key_store, scope) = (vault.clone(), *key_store, self.scope);
                thread::spawn(move || {
                    if let Err(error) =
                        crate::worker::run(vault, key_store, scope, child_in, child_out)
                    {
                        crate::service::log(&format!("worker: {}", error.message));
                    }
                });
                None
            }
        };
        Ok(Live {
            child,
            to_child: Arc::new(Mutex::new(to_child)),
            from_child,
        })
    }

    fn live(&mut self) -> Result<&mut Live, proto::Error> {
        if self.live.is_none() {
            let live = self.start().map_err(|error| {
                internal(format!(
                    "cannot start the {} process of the vault daemon: {error}",
                    self.scope.name()
                ))
            })?;
            self.live = Some(live);
        }
        self.live
            .as_mut()
            .ok_or_else(|| internal("the process did not start"))
    }

    /// Sends `order` and reads what comes back until its answer. Meanwhile,
    /// carries the process's questions to the key agent, and the messages of
    /// a relay to `to_client`.
    fn exchange(
        &mut self,
        order: down::Body,
        to_client: Option<&Sender<response::Body>>,
    ) -> Result<up::Body, proto::Error> {
        self.exchange_then(order, to_client, |_| {})
    }

    /// Like [`Self::exchange`]; `sent` runs once the order is on its way.
    fn exchange_then(
        &mut self,
        order: down::Body,
        to_client: Option<&Sender<response::Body>>,
        sent: impl FnOnce(&Arc<Mutex<PipeWriter>>),
    ) -> Result<up::Body, proto::Error> {
        let port = Arc::clone(&self.port);
        let name = self.scope.name();
        let live = self.live()?;
        let outcome = (|| -> io::Result<up::Body> {
            send(&live.to_child, order)?;
            sent(&live.to_child);
            loop {
                let up: Up = read_frame(&mut live.from_child)
                    .map_err(io::Error::other)?
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                match up.body {
                    Some(up::Body::AgentRequest(question)) => {
                        let outcome = question.ask.map(|ask| port.ask(ask));
                        let reply = proto::KeyAgentReply {
                            id: question.id,
                            outcome,
                        };
                        send(&live.to_child, down::Body::AgentReply(reply))?;
                    }
                    Some(up::Body::RelayData(message)) => {
                        if let (Some(to_client), Some(body)) = (to_client, message.body) {
                            // A client that left is noticed by the process
                            // itself, when its link closes.
                            let _ = to_client.send(body);
                        }
                    }
                    Some(answer) => return Ok(answer),
                    None => return Err(io::ErrorKind::InvalidData.into()),
                }
            }
        })();
        outcome.map_err(|error| {
            // Whatever it was doing, it is not in a state to go on from.
            self.live = None;
            internal(format!(
                "the {name} process of the vault daemon stopped: {error}"
            ))
        })
    }

    fn reply(answer: up::Body) -> Result<response::Body, proto::Error> {
        match answer {
            up::Body::Reply(proto::Response { body: Some(body) }) => as_result(body),
            _ => Err(internal(
                "a process of the vault daemon answered out of turn",
            )),
        }
    }
}

impl Back for Process {
    fn call(&mut self, request: request::Body) -> response::Body {
        let order = down::Body::Call(proto::Request {
            body: Some(request),
        });
        self.exchange(order, None)
            .and_then(Self::reply)
            .unwrap_or_else(response::Body::Error)
    }

    fn relay(&mut self, request: request::Body, relay: RelayEnd) -> response::Body {
        let RelayEnd { incoming, outgoing } = relay;
        let order = down::Body::Relay(proto::Request {
            body: Some(request),
        });
        // Client → process, for as long as the client's uplink is open. The
        // process opens the relay's uplink when it reads the order, so what
        // follows the order right away is not lost.
        let carry = move |to_child: &Arc<Mutex<PipeWriter>>| {
            let to_child = Arc::clone(to_child);
            thread::spawn(move || {
                for message in incoming {
                    let data = down::Body::RelayData(proto::Request {
                        body: Some(message),
                    });
                    if send(&to_child, data).is_err() {
                        return;
                    }
                }
                let _ = send(&to_child, down::Body::RelayClosed(Empty {}));
            });
        };
        self.exchange_then(order, Some(&outgoing), carry)
            .and_then(Self::reply)
            .unwrap_or_else(response::Body::Error)
    }

    fn import_key(&mut self) -> Result<[u8; PUBLIC_KEY_LEN], proto::Error> {
        match self.exchange(down::Body::ImportKey(Empty {}), None)? {
            up::Body::ImportKey(key) => key
                .key
                .as_slice()
                .try_into()
                .map_err(|_| internal("a process of the vault daemon gave a malformed key")),
            other => Self::reply(other).and(Err(internal("no key was given"))),
        }
    }

    fn import(
        &mut self,
        domain: DomainId,
        epoch: u32,
        sealed: Vec<u8>,
    ) -> Result<(), proto::Error> {
        let transfer = KeyTransfer {
            domain: domain_to_proto(domain) as i32,
            epoch,
            sealed,
        };
        self.exchange(down::Body::Import(transfer), None)
            .and_then(Self::reply)
            .map(drop)
    }

    fn export(
        &mut self,
        domain: DomainId,
        to: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(u32, Vec<u8>), proto::Error> {
        let order = down::Body::Export(ExportKey {
            domain: domain_to_proto(domain) as i32,
            to: to.to_vec(),
        });
        match self.exchange(order, None)? {
            up::Body::Exported(transfer) if domain_from_proto(transfer.domain)? == domain => {
                Ok((transfer.epoch, transfer.sealed))
            }
            other => Self::reply(other).and(Err(internal("no key was handed over"))),
        }
    }

    fn reset(&mut self) -> Result<(), proto::Error> {
        // A process that is not running has nothing open.
        if self.live.is_none() {
            return Ok(());
        }
        self.exchange(down::Body::Reset(Empty {}), None)
            .and_then(Self::reply)
            .map(drop)
    }

    fn unlocked(&mut self, domain: DomainId) -> bool {
        // A process that is not running holds nothing; do not start it to ask.
        if self.live.is_none() {
            return false;
        }
        let wanted = domain_to_proto(domain) as i32;
        match self.call(request::Body::Status(proto::Status {})) {
            response::Body::Status(status) => status
                .domains
                .iter()
                .any(|status| status.domain == wanted && status.unlocked),
            _ => false,
        }
    }

    fn stop(&mut self) {
        self.live = None;
    }
}

/// Starts the processes behind the front.
pub(crate) struct ProcessSpawner {
    launch: Launch,
    port: Arc<dyn KeyAgentPort>,
}

impl ProcessSpawner {
    /// As child processes of this one, started from `executable` (this
    /// daemon's own executable).
    pub(crate) fn new(
        executable: PathBuf,
        vault: PathBuf,
        key_store: KeyStoreChoice,
        port: Arc<dyn KeyAgentPort>,
    ) -> Self {
        let mut args: Vec<OsString> = vec!["--vault".into(), vault.into()];
        match key_store {
            KeyStoreChoice::Platform => {}
            KeyStoreChoice::None => args.push("--no-hardware-keystore".into()),
            KeyStoreChoice::InsecureSoftware => args.push("--insecure-software-keystore".into()),
        }
        Self {
            launch: Launch::Executable { executable, args },
            port,
        }
    }

    /// On threads of this process, over the same pipes (unit tests).
    #[cfg(test)]
    pub(crate) fn threads(
        vault: PathBuf,
        key_store: KeyStoreChoice,
        port: Arc<dyn KeyAgentPort>,
    ) -> Self {
        Self {
            launch: Launch::Thread { vault, key_store },
            port,
        }
    }
}

impl Spawner for ProcessSpawner {
    fn back(&self, scope: Scope) -> Box<dyn Back> {
        let mut launch = self.launch.clone();
        #[cfg_attr(
            not(test),
            expect(irrefutable_let_patterns, reason = "one kind outside tests")
        )]
        if let Launch::Executable { args, .. } = &mut launch {
            args.push("--worker".into());
            args.push(scope.name().into());
        }
        Box::new(Process {
            launch,
            scope,
            port: Arc::clone(&self.port),
            live: None,
        })
    }
}
