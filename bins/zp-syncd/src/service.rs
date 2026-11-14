//! What the sync daemon does for the user interface (`docs/spec/ipc.md` §12).
//!
//! Requests arrive on the IPC threads; the sync loop owns the transports. The
//! two meet through [`Command`]s, which the loop takes in between its steps.

use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use zp_crypto::DeviceId;
use zp_ipc::proto::{self, ErrorCode, Role, request, response};
use zp_ipc::{Handler, Peer, PeerProcess, RelayEnd};
use zp_transport::Link;
use zp_transport::Transport;
use zp_transport::daemon::{Event, SyncDaemon, SyncStore};
use zp_transport::discovery::{TAG_LEN, Tag};

use crate::{log, relay};

/// The longest a `SyncNow` may take, in seconds.
const MAX_SYNC_SECS: u32 = 300;
/// The longest a pairing may wait for the other device, in seconds.
const MAX_LISTEN_SECS: u32 = 300;

/// What the IPC threads ask the sync loop to do.
pub(crate) enum Command {
    /// Sync with every other device now, for at most `seconds`, and report.
    SyncNow {
        seconds: u32,
        reply: Sender<Result<proto::SyncResults, String>>,
    },
    /// Show `tag` and hand the next pairing link to `sink`, until `until`.
    /// `ready` is told once the loop waits.
    Listen {
        tag: Tag,
        until: Instant,
        sink: Sender<Box<dyn Link>>,
        ready: Sender<()>,
    },
    /// Stop waiting for a pairing.
    StopListen,
}

/// What the sync daemon tells about itself.
#[derive(Debug, Clone, Default)]
pub(crate) struct Status {
    pub(crate) syncing: bool,
    pub(crate) not_syncing_because: String,
    pub(crate) lan_endpoints: Vec<String>,
    pub(crate) transports: Vec<String>,
    pub(crate) problems: Vec<String>,
}

/// The IPC side of the sync daemon.
pub(crate) struct Service {
    commands: Mutex<Sender<Command>>,
    status: Mutex<Status>,
}

fn error(code: ErrorCode, message: impl Into<String>) -> response::Body {
    response::Body::Error(proto::Error::new(code, message))
}

impl Service {
    pub(crate) fn new(commands: Sender<Command>) -> Self {
        Self {
            commands: Mutex::new(commands),
            status: Mutex::new(Status {
                not_syncing_because: "starting".into(),
                ..Status::default()
            }),
        }
    }

    fn lock_status(&self) -> MutexGuard<'_, Status> {
        self.status
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub(crate) fn set_status(&self, status: Status) {
        *self.lock_status() = status;
    }

    fn command(&self, command: Command) -> bool {
        self.commands
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .send(command)
            .is_ok()
    }

    /// Answers a command while the sync loop is not running.
    pub(crate) fn refuse(&self, command: Command) {
        let reason = format!(
            "the sync daemon is not syncing: {}",
            self.lock_status().not_syncing_because
        );
        match command {
            Command::SyncNow { reply, .. } => {
                let _ = reply.send(Err(reason));
            }
            // Dropping the sink tells the waiting thread.
            Command::Listen { .. } | Command::StopListen => {}
        }
    }

    fn status_reply(&self) -> response::Body {
        let status = self.lock_status().clone();
        response::Body::SyncdStatus(proto::SyncdStatusReply {
            lan_endpoints: status.lan_endpoints,
            transports: status.transports,
            problems: status.problems,
            syncing: status.syncing,
            not_syncing_because: status.not_syncing_because,
            pid: std::process::id(),
        })
    }

    fn sync_now(&self, seconds: u32) -> response::Body {
        let seconds = seconds.min(MAX_SYNC_SECS);
        let (reply, answer) = mpsc::channel();
        if !self.command(Command::SyncNow { seconds, reply }) {
            return error(ErrorCode::Internal, "the sync loop has stopped");
        }
        // The loop answers by the deadline; allow it a few steps more.
        let wait = Duration::from_secs(u64::from(seconds) + 10);
        match answer.recv_timeout(wait) {
            Ok(Ok(results)) => response::Body::SyncResults(results),
            Ok(Err(reason)) => error(ErrorCode::Internal, reason),
            Err(_) => error(ErrorCode::Internal, "the sync loop did not answer"),
        }
    }

    /// `PairListen`: waits for a device that opens a pairing, then carries its
    /// link.
    fn listen(&self, listen: &proto::PairListen, relay: RelayEnd) -> response::Body {
        let Ok(tag) = <[u8; TAG_LEN]>::try_from(listen.tag.as_slice()) else {
            return error(ErrorCode::BadRequest, "a pairing tag is 8 bytes");
        };
        let seconds = listen.seconds.min(MAX_LISTEN_SECS);
        let until = Instant::now() + Duration::from_secs(u64::from(seconds));
        let (sink, links) = mpsc::channel();
        let (ready, waiting) = mpsc::channel();
        if !self.command(Command::Listen {
            tag,
            until,
            sink,
            ready,
        }) {
            return error(ErrorCode::Internal, "the sync loop has stopped");
        }
        // Only once the loop waits may the user show the code: a device that
        // connected before would find nobody waiting.
        if waiting.recv_timeout(Duration::from_secs(10)).is_err() {
            self.command(Command::StopListen);
            return error(
                ErrorCode::Internal,
                format!(
                    "the sync daemon is not syncing: {}",
                    self.lock_status().not_syncing_because
                ),
            );
        }
        if relay
            .outgoing
            .send(response::Body::Listening(proto::Listening {}))
            .is_err()
        {
            self.command(Command::StopListen);
            return error(ErrorCode::Internal, "the client went away");
        }
        match links.recv_timeout(Duration::from_secs(u64::from(seconds))) {
            Ok(link) => relay::carry(link, relay),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.command(Command::StopListen);
                response::Body::LinkEnded(proto::LinkEnded {
                    reason: "no device connected before the pairing code expired".into(),
                })
            }
            // The loop dropped the sink: it is not running.
            Err(mpsc::RecvTimeoutError::Disconnected) => error(
                ErrorCode::Internal,
                format!(
                    "the sync daemon is not syncing: {}",
                    self.lock_status().not_syncing_because
                ),
            ),
        }
    }
}

impl Handler for Service {
    fn handle(&self, peer: &Peer, request: request::Body) -> response::Body {
        if peer.role != Role::Ui {
            return error(
                ErrorCode::Denied,
                "only a user interface may use the sync daemon",
            );
        }
        match request {
            request::Body::SyncdStatus(_) => self.status_reply(),
            request::Body::SyncNow(sync) => self.sync_now(sync.seconds),
            request::Body::Shutdown(_) => response::Body::Done(proto::Done {}),
            _ => error(
                ErrorCode::BadRequest,
                "that request is not one the sync daemon answers",
            ),
        }
    }

    fn starts_relay(&self, request: &request::Body) -> bool {
        matches!(
            request,
            request::Body::PairListen(_) | request::Body::PairConnect(_)
        )
    }

    fn relay(&self, peer: &Peer, request: request::Body, relay: RelayEnd) -> response::Body {
        if peer.role != Role::Ui {
            return error(
                ErrorCode::Denied,
                "only a user interface may use the sync daemon",
            );
        }
        match request {
            request::Body::PairListen(listen) => self.listen(&listen, relay),
            request::Body::PairConnect(connect) => relay::connect(&connect.addresses, relay),
            _ => error(ErrorCode::BadRequest, "not a relay request"),
        }
    }

    fn rejected(&self, process: &PeerProcess) {
        let who = process.executable.as_deref().map_or_else(
            || "an unidentified process".to_owned(),
            |path| path.display().to_string(),
        );
        log(&format!("refused a connection from {who}"));
    }
}

/// A `SyncNow` that waits for its sessions.
struct PendingSync {
    until: Instant,
    others: usize,
    reply: Sender<Result<proto::SyncResults, String>>,
    results: Vec<proto::SyncResult>,
    synced: HashSet<DeviceId>,
}

/// What the sync loop is doing for the user interface.
#[derive(Default)]
pub(crate) struct Requests {
    syncs: Vec<PendingSync>,
    listening_until: Option<Instant>,
}

/// How many other active devices the vault has.
fn other_devices<S: SyncStore, T: Transport>(daemon: &SyncDaemon<S, T>) -> Result<usize, String> {
    let store = daemon.store();
    let own = store.device_id();
    let registry = store.registry().map_err(|error| error.to_string())?;
    Ok(registry
        .active()
        .filter(|record| record.device_id != own)
        .count())
}

impl Requests {
    /// Takes in what the IPC threads asked for since the last step.
    pub(crate) fn take<S: SyncStore, T: Transport>(
        &mut self,
        daemon: &mut SyncDaemon<S, T>,
        commands: &Receiver<Command>,
    ) {
        while let Ok(command) = commands.try_recv() {
            match command {
                Command::SyncNow { seconds, reply } => {
                    let others = match other_devices(daemon) {
                        Ok(others) => others,
                        Err(reason) => {
                            let _ = reply.send(Err(reason));
                            continue;
                        }
                    };
                    if others == 0 {
                        let _ = reply.send(Ok(proto::SyncResults::default()));
                        continue;
                    }
                    daemon.sync_soon();
                    self.syncs.push(PendingSync {
                        until: Instant::now() + Duration::from_secs(u64::from(seconds)),
                        others,
                        reply,
                        results: Vec::new(),
                        synced: HashSet::new(),
                    });
                }
                Command::Listen {
                    tag,
                    until,
                    sink,
                    ready,
                } => match daemon.wait_for_pairing(tag, sink) {
                    Ok(()) => {
                        self.listening_until = Some(until);
                        let _ = ready.send(());
                    }
                    // Dropping `ready` tells the waiting thread.
                    Err(error) => log(&format!("cannot wait for a pairing: {error}")),
                },
                Command::StopListen => {
                    let _ = daemon.stop_pairing();
                    self.listening_until = None;
                }
            }
        }
    }

    /// Accounts for what a step did, and answers what is complete.
    pub(crate) fn progress<S: SyncStore, T: Transport>(
        &mut self,
        daemon: &mut SyncDaemon<S, T>,
        events: &[Event],
        now: Instant,
    ) {
        for sync in &mut self.syncs {
            for event in events {
                sync.results.push(match event {
                    Event::Synced {
                        peer, name, report, ..
                    } => {
                        sync.synced.insert(*peer);
                        proto::SyncResult {
                            device_id: peer.as_bytes().to_vec(),
                            name: name.clone(),
                            sent: report.sent as u64,
                            received: report.received.applied as u64,
                            error: String::new(),
                        }
                    }
                    Event::Failed { peer, error, .. } => proto::SyncResult {
                        device_id: peer
                            .map(|peer| peer.as_bytes().to_vec())
                            .unwrap_or_default(),
                        name: String::new(),
                        sent: 0,
                        received: 0,
                        error: error.to_string(),
                    },
                });
            }
        }
        let (done, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.syncs)
            .into_iter()
            .partition(|sync| sync.synced.len() >= sync.others || now >= sync.until);
        self.syncs = waiting;
        for sync in done {
            let _ = sync.reply.send(Ok(proto::SyncResults {
                other_devices: u32::try_from(sync.others).unwrap_or(u32::MAX),
                results: sync.results,
            }));
        }
        if self.listening_until.is_some_and(|until| now >= until) {
            let _ = daemon.stop_pairing();
            self.listening_until = None;
        }
    }
}
