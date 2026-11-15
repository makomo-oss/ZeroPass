//! The sync daemon (`docs/spec/ipc.md` §12).
//!
//! The sync daemon holds every connection to other devices; a client has
//! none. For pairing it asks the sync daemon for a link to the other device
//! and gets its bytes over an IPC relay ([`DeviceLink`]).

use std::io::{self, Write};
use std::path::Path;
use std::process::Command as Process;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use zp_drive::{ChannelReader, Link};
use zp_ipc::proto::{self, request, response};
use zp_ipc::{Client, DaemonPolicy, Downlink, Endpoint, IpcError, SYNC_DAEMON_NAME, Uplink};

use crate::vaultd::{STOP_TIMEOUT, client_name};
use crate::{Error, Result, sibling};

/// How long a sync daemon that was just started may take to listen, or to
/// start syncing.
const START_TIMEOUT: Duration = Duration::from_secs(10);

fn unexpected() -> Error {
    Error::message("the sync daemon gave an unexpected answer")
}

/// Starts the sync daemon for `vault` as a background process. It is not
/// sandboxed: it is the process that talks to other devices.
fn start(vault: &Path) -> Result<()> {
    let executable = sibling(SYNC_DAEMON_NAME)?;
    let vault = std::path::absolute(vault)?;
    let mut daemon = Process::new(&executable);
    daemon.arg("--vault").arg(&vault);
    zp_ipc::spawn_detached(&mut daemon).map_err(|error| {
        Error::message(format!(
            "cannot start the sync daemon ({}): {error}",
            executable.display()
        ))
    })
}

/// Connects to the sync daemon of `vault`, starting it if `start_it` says so.
/// `Ok(None)` means it is not running and was not to be started.
pub fn connect(vault: &Path, start_it: bool) -> Result<Option<Client>> {
    let endpoint = Endpoint::for_sync_daemon(vault)?;
    let policy = DaemonPolicy::program_beside_current_exe(SYNC_DAEMON_NAME)?;
    let name = client_name();
    let attempt = || Client::connect(&endpoint, &policy, &name);
    match attempt() {
        Ok(client) => return Ok(Some(client)),
        Err(IpcError::NotRunning) => {}
        Err(error) => return Err(error.into()),
    }
    if !start_it {
        return Ok(None);
    }
    start(vault)?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        thread::sleep(Duration::from_millis(20));
        match attempt() {
            Ok(client) => return Ok(Some(client)),
            Err(IpcError::NotRunning) if Instant::now() < deadline => {}
            Err(IpcError::NotRunning) => {
                return Err(Error::message("the sync daemon did not start"));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Connects to the sync daemon of `vault`, starting it if necessary.
pub fn open(vault: &Path) -> Result<Client> {
    connect(vault, true)?.ok_or_else(|| Error::message("the sync daemon is not running"))
}

/// What the sync daemon tells about itself.
pub fn status(client: &mut Client) -> Result<proto::SyncdStatusReply> {
    match client.call(request::Body::SyncdStatus(proto::SyncdStatus {}))? {
        response::Body::SyncdStatus(status) => Ok(status),
        _ => Err(unexpected()),
    }
}

/// What the sync daemon tells about itself, once it is syncing: a sync daemon
/// that was just started takes a moment to reach the vault daemon and to open
/// its transports. Fails with its reason if it is not syncing by then.
pub fn status_when_syncing(client: &mut Client) -> Result<proto::SyncdStatusReply> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        let status = status(client)?;
        if status.syncing {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(Error::message(format!(
                "the sync daemon cannot reach other devices: {}",
                status.not_syncing_because
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Has the sync daemon of `vault` sync with the other devices of the vault
/// now, for at most `seconds`, and returns what it did. Starts the sync daemon
/// if it is not running.
pub fn sync_now(vault: &Path, seconds: u32) -> Result<proto::SyncResults> {
    let mut client = open(vault)?;
    match client.call(request::Body::SyncNow(proto::SyncNow { seconds }))? {
        response::Body::SyncResults(results) => Ok(results),
        _ => Err(unexpected()),
    }
}

/// Stops the sync daemon of `vault` if it is running. Returns whether it was.
pub fn stop(vault: &Path) -> Result<bool> {
    let Some(mut client) = connect(vault, false)? else {
        return Ok(false);
    };
    client.call(request::Body::Shutdown(proto::Shutdown {}))?;
    // It answers before it lets go of its endpoint.
    zp_ipc::wait_until_closed(&Endpoint::for_sync_daemon(vault)?, STOP_TIMEOUT);
    Ok(true)
}

/// A link to another device, held by the sync daemon and reached through an
/// IPC relay. What crosses it is the pairing channel's ciphertext.
pub struct DeviceLink {
    downlink: Downlink,
    uplink: Uplink,
}

impl DeviceLink {
    /// Asks the sync daemon for a link (`PairListen` or `PairConnect`) and
    /// waits until it is up: until the other device has connected, or this
    /// one has reached it. Fails with the sync daemon's reason otherwise.
    ///
    /// For `PairListen`, `listening` runs once the sync daemon waits for the
    /// device: the moment to show the pairing code.
    pub fn open(
        vault: &Path,
        request: request::Body,
        mut listening: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let (id, mut downlink) = open(vault)?.start_relay(request)?;
        let uplink = match open(vault)?.attach_relay(id) {
            Ok(uplink) => uplink,
            // The relay ended at once; its reason is on the downlink.
            Err(attach_error) => {
                return match downlink.receive() {
                    Err(reason) => Err(reason.into()),
                    Ok(response::Body::LinkEnded(ended)) => Err(Error::Message(ended.reason)),
                    Ok(_) => Err(attach_error.into()),
                };
            }
        };
        loop {
            match downlink.receive()? {
                response::Body::Listening(_) => listening()?,
                response::Body::Done(_) => return Ok(Self { downlink, uplink }),
                response::Body::LinkEnded(ended) => return Err(Error::Message(ended.reason)),
                _ => return Err(unexpected()),
            }
        }
    }
}

/// Writes to the other device through the relay's uplink.
struct UplinkWriter(Uplink);

impl Write for UplinkWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let data = bytes.to_vec();
        self.0
            .send(request::Body::LinkData(proto::LinkData { data }))
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Link for DeviceLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn io::Read + Send>, Box<dyn Write + Send>)> {
        let Self {
            mut downlink,
            uplink,
        } = *self;
        let (chunks, incoming) = mpsc::channel();
        // Ends with the relay; dropping the sender ends the reader's stream.
        thread::spawn(move || {
            while let Ok(response::Body::LinkData(chunk)) = downlink.receive() {
                if chunks.send(chunk.data).is_err() {
                    break;
                }
            }
        });
        Ok((
            Box::new(ChannelReader::new(incoming)),
            Box::new(UplinkWriter(uplink)),
        ))
    }

    fn peer(&self) -> String {
        "the sync daemon".to_owned()
    }
}
