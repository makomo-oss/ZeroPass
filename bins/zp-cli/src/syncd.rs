//! The sync daemon, as seen from the command-line client
//! (`docs/spec/ipc.md` §12).
//!
//! The sync daemon holds every connection to other devices; this program has
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

use super::CliResult;

/// How long a sync daemon that was just started may take to listen.
const START_TIMEOUT: Duration = Duration::from_secs(10);

fn unexpected() -> Box<dyn std::error::Error> {
    "the sync daemon gave an unexpected answer".into()
}

/// Starts the sync daemon for `vault` as a background process. It is not
/// sandboxed: it is the process that talks to other devices.
fn start(vault: &Path) -> CliResult<()> {
    let name = format!("{SYNC_DAEMON_NAME}{}", std::env::consts::EXE_SUFFIX);
    let executable = std::env::current_exe()?.with_file_name(name);
    let vault = std::path::absolute(vault)?;
    let mut daemon = Process::new(&executable);
    daemon.arg("--vault").arg(&vault);
    zp_ipc::spawn_detached(&mut daemon).map_err(|error| {
        format!(
            "cannot start the sync daemon ({}): {error}",
            executable.display()
        )
        .into()
    })
}

/// Connects to the sync daemon of `vault`, starting it if `start_it` says so.
/// `Ok(None)` means it is not running and was not to be started.
pub(crate) fn connect(vault: &Path, start_it: bool) -> CliResult<Option<Client>> {
    let endpoint = Endpoint::for_sync_daemon(vault)?;
    let policy = DaemonPolicy::program_beside_current_exe(SYNC_DAEMON_NAME)?;
    let attempt = || Client::connect(&endpoint, &policy, "zp-cli");
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
            Err(IpcError::NotRunning) => return Err("the sync daemon did not start".into()),
            Err(error) => return Err(error.into()),
        }
    }
}

/// Connects to the sync daemon of `vault`, starting it if necessary.
pub(crate) fn open(vault: &Path) -> CliResult<Client> {
    Ok(connect(vault, true)?.ok_or("the sync daemon is not running")?)
}

/// What the sync daemon tells about itself.
pub(crate) fn status(client: &mut Client) -> CliResult<proto::SyncdStatusReply> {
    match client.call(request::Body::SyncdStatus(proto::SyncdStatus {}))? {
        response::Body::SyncdStatus(status) => Ok(status),
        _ => Err(unexpected()),
    }
}

/// What the sync daemon tells about itself, once it is syncing: a sync daemon
/// that was just started takes a moment to reach the vault daemon and to open
/// its transports. Fails with its reason if it is not syncing by then.
pub(crate) fn status_when_syncing(client: &mut Client) -> CliResult<proto::SyncdStatusReply> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        let status = status(client)?;
        if status.syncing {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the sync daemon cannot reach other devices: {}",
                status.not_syncing_because
            )
            .into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Stops the sync daemon of `vault` if it is running. Returns whether it was.
pub(crate) fn stop(vault: &Path) -> CliResult<bool> {
    let Some(mut client) = connect(vault, false)? else {
        return Ok(false);
    };
    client.call(request::Body::Shutdown(proto::Shutdown {}))?;
    Ok(true)
}

/// A link to another device, held by the sync daemon and reached through an
/// IPC relay. What crosses it is the pairing channel's ciphertext.
pub(crate) struct DeviceLink {
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
    pub(crate) fn open(
        vault: &Path,
        request: request::Body,
        mut listening: impl FnMut() -> CliResult<()>,
    ) -> CliResult<Self> {
        let (id, mut downlink) = open(vault)?.start_relay(request)?;
        let uplink = match open(vault)?.attach_relay(id) {
            Ok(uplink) => uplink,
            // The relay ended at once; its reason is on the downlink.
            Err(attach_error) => {
                return match downlink.receive() {
                    Err(reason) => Err(reason.into()),
                    Ok(response::Body::LinkEnded(ended)) => Err(ended.reason.into()),
                    Ok(_) => Err(attach_error.into()),
                };
            }
        };
        loop {
            match downlink.receive()? {
                response::Body::Listening(_) => listening()?,
                response::Body::Done(_) => return Ok(Self { downlink, uplink }),
                response::Body::LinkEnded(ended) => return Err(ended.reason.into()),
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
