//! Drivers: run the handshakes, the sync session and the pairing conversation
//! over a [`Link`], using blocking I/O.
//!
//! The protocols themselves are state machines without I/O (`zp-sync`,
//! `zp-pairing`); these functions only move bytes between them and the link, in
//! this layering:
//!
//! ```text
//! sync / pairing messages
//!   length(4) frames            zp_sync::encode_frame / FrameDecoder
//!   Noise transport frames      zp_pairing::SecureChannel
//!   link (TCP, BLE, memory)     Connection
//! ```

use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};

use zp_crypto::{ChannelKey, DeviceId, HardwareKeyStore, VaultId};
use zp_pairing::flow::{ack_message, is_ack, refusal_message};
use zp_pairing::noise::PSK_LEN;
use zp_pairing::{
    ChannelPublicKey, Handshake, JoinRequest, Joiner, PairingError, SecureChannel, admit,
};
use zp_sync::{FrameDecoder, OpLog, Session, SessionReport, encode_frame};
use zp_vault::{CreateOptions, Vault};

use crate::DriveError;
use crate::link::{Connection, Link};

/// Settings of a driver run.
#[derive(Debug, Clone, Copy)]
pub struct DriveConfig {
    /// How long the peer may stay silent before the run is abandoned.
    pub idle_timeout: Duration,
    /// In a sync session, how long this side may send nothing while the peer's
    /// data keeps arriving before it sends a `Progress` message
    /// (`docs/spec/sync.md` §7). Well below the peer's idle timeout.
    pub progress_interval: Duration,
}

impl Default for DriveConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            progress_interval: Duration::from_secs(10),
        }
    }
}

fn store_error(error: impl core::fmt::Display) -> DriveError {
    DriveError::Sync(error.to_string())
}

fn run_handshake(
    connection: &mut Connection,
    mut handshake: Handshake,
) -> Result<SecureChannel, DriveError> {
    let first = handshake.step(&[])?;
    connection.send(&first)?;
    while !handshake.is_finished() {
        let received = connection.receive()?;
        let reply = handshake.step(&received)?;
        connection.send(&reply)?;
    }
    Ok(handshake.into_channel()?)
}

/// Framed messages over an established secure channel.
struct Messenger {
    connection: Connection,
    channel: SecureChannel,
    decoder: FrameDecoder,
    ready: VecDeque<Vec<u8>>,
    progress_interval: Duration,
    /// When this side last sent something.
    last_sent: Instant,
    /// Whether bytes arrived from the peer since then.
    received_since_sent: bool,
}

impl Messenger {
    fn new(
        connection: Connection,
        channel: SecureChannel,
        config: &DriveConfig,
    ) -> Result<Self, DriveError> {
        let mut messenger = Self {
            connection,
            channel,
            decoder: FrameDecoder::new(),
            ready: VecDeque::new(),
            progress_interval: config.progress_interval,
            last_sent: Instant::now(),
            received_since_sent: false,
        };
        // Data the peer sent right behind its last handshake message.
        messenger.absorb(&[])?;
        Ok(messenger)
    }

    fn absorb(&mut self, bytes: &[u8]) -> Result<(), DriveError> {
        self.decoder.push(&self.channel.receive(bytes)?);
        while let Some(message) = self.decoder.next_message().map_err(store_error)? {
            self.ready.push_back(message);
        }
        Ok(())
    }

    fn send(&mut self, message: &[u8]) -> Result<(), DriveError> {
        let frame = encode_frame(message).map_err(store_error)?;
        let bytes = self.channel.send(&frame)?;
        self.connection.send(&bytes)?;
        self.last_sent = Instant::now();
        self.received_since_sent = false;
        Ok(())
    }

    /// Waits for the next message, for at most the idle timeout of silence.
    ///
    /// With `progress`, sends that message whenever bytes from the peer keep
    /// arriving but this side has sent nothing for the progress interval, so
    /// that the peer, which may be waiting for us, does not time out.
    fn receive(&mut self, progress: Option<&[u8]>) -> Result<Vec<u8>, DriveError> {
        let idle_timeout = self.connection.idle_timeout();
        let mut silent_since = Instant::now();
        loop {
            if let Some(progress) = progress
                && self.received_since_sent
                && self.last_sent.elapsed() >= self.progress_interval
            {
                self.send(progress)?;
            }
            if let Some(message) = self.ready.pop_front() {
                return Ok(message);
            }
            let left = idle_timeout.saturating_sub(silent_since.elapsed());
            if left.is_zero() {
                return Err(DriveError::Timeout);
            }
            let wait = match progress {
                Some(_) => left.min(self.progress_interval),
                None => left,
            };
            if let Some(bytes) = self.connection.receive_within(wait)? {
                silent_since = Instant::now();
                self.received_since_sent = true;
                self.absorb(&bytes)?;
            }
        }
    }
}

/// Runs one sync session, bound to the channel key of the peer.
fn run_session<S: OpLog>(
    messenger: &mut Messenger,
    log: &mut S,
) -> Result<SessionReport, DriveError> {
    let channel_peer = *messenger.channel.remote_static();
    let mut session = Session::start(log, Some(channel_peer)).map_err(store_error)?;
    let progress = Session::progress_message();
    loop {
        while let Some(message) = session.poll_send(log).map_err(store_error)? {
            messenger.send(&message)?;
        }
        if session.is_complete() {
            return Ok(session.report().clone());
        }
        // While the peer's ops are still coming, tell it now and then that
        // they are: it may have sent everything and be waiting for `Done`.
        let message = messenger.receive(session.is_receiving().then_some(progress.as_slice()))?;
        session.receive(log, &message).map_err(store_error)?;
    }
}

/// Connects to the device that owns `remote` and syncs with it.
///
/// The handshake only completes with that device and only within `vault_id`;
/// the session then checks that the device is a member in good standing.
pub fn sync_as_initiator<S: OpLog>(
    link: Box<dyn Link>,
    log: &mut S,
    local: &ChannelKey,
    remote: &ChannelPublicKey,
    config: &DriveConfig,
) -> Result<SessionReport, DriveError> {
    let vault_id: VaultId = log.vault_id();
    let mut connection = Connection::open(link, config.idle_timeout)?;
    let channel = run_handshake(
        &mut connection,
        Handshake::sync_initiator(local, remote, &vault_id)?,
    )?;
    run_session(&mut Messenger::new(connection, channel, config)?, log)
}

/// Answers an incoming link and syncs with whoever connected, provided it turns
/// out to be a member of the vault.
///
/// Anyone who knows this device's channel public key and the vault identifier
/// can complete the handshake; nothing but this device's registry and version
/// vector is sent before the session has established that the peer's channel
/// key belongs to an active device.
pub fn sync_as_responder<S: OpLog>(
    link: Box<dyn Link>,
    log: &mut S,
    local: &ChannelKey,
    config: &DriveConfig,
) -> Result<SessionReport, DriveError> {
    let vault_id: VaultId = log.vault_id();
    let mut connection = Connection::open(link, config.idle_timeout)?;
    let channel = run_handshake(
        &mut connection,
        Handshake::sync_responder(local, &vault_id)?,
    )?;
    run_session(&mut Messenger::new(connection, channel, config)?, log)
}

/// How a pairing connection was set up, as far as the handshake is concerned.
#[derive(Debug, Clone)]
pub struct PairingLink<'a> {
    /// Whether this side scanned the code (and therefore initiates).
    pub scanned: bool,
    /// The one-time secret from the pairing offer.
    pub psk: &'a [u8; PSK_LEN],
    /// For the scanning side: the channel key named in the offer. The handshake
    /// must authenticate exactly this key.
    pub offered_key: Option<ChannelPublicKey>,
}

fn pairing_channel(
    connection: &mut Connection,
    local: &ChannelKey,
    pairing: &PairingLink<'_>,
) -> Result<SecureChannel, DriveError> {
    let handshake = Handshake::pairing(pairing.scanned, local, pairing.psk)?;
    let channel = run_handshake(connection, handshake)?;
    if pairing
        .offered_key
        .is_some_and(|key| key != *channel.remote_static())
    {
        return Err(PairingError::KeyMismatch.into());
    }
    Ok(channel)
}

/// What pairing achieved on the existing device.
#[derive(Debug, Clone)]
pub struct Admitted {
    /// The device that joined.
    pub device: DeviceId,
    /// Its name.
    pub name: String,
    /// The first sync, or why it did not complete. The device is a member
    /// either way and will catch up at the next sync.
    pub sync: Result<SessionReport, String>,
}

/// The existing device's side of pairing over `link`: admits the device at the
/// other end (after `confirm`) and runs the first sync.
///
/// Every domain of `vault` must be unlocked.
pub fn pair_as_existing(
    link: Box<dyn Link>,
    vault: &mut Vault,
    pairing: &PairingLink<'_>,
    confirm: impl FnOnce(&JoinRequest) -> bool,
    config: &DriveConfig,
) -> Result<Admitted, DriveError> {
    let local = vault.channel_key().map_err(store_error)?;
    let mut connection = Connection::open(link, config.idle_timeout)?;
    let channel = pairing_channel(&mut connection, &local, pairing)?;
    let peer_key = *channel.remote_static();
    let mut messenger = Messenger::new(connection, channel, config)?;

    let request = messenger.receive(None)?;
    let mut joined = None;
    let grant = match admit(vault, &peer_key, &request, |request| {
        let approved = confirm(request);
        if approved {
            joined = Some((request.device_id, request.name.clone()));
        }
        approved
    }) {
        Ok(grant) => grant,
        Err(error) => {
            // Tell the other side instead of leaving it waiting.
            let _ = messenger.send(&refusal_message());
            return Err(error.into());
        }
    };
    messenger.send(&grant)?;
    let (device, name) = joined.ok_or(PairingError::Protocol)?;

    if !is_ack(&messenger.receive(None)?) {
        return Err(PairingError::Protocol.into());
    }
    let sync = run_session(&mut messenger, vault).map_err(|error| error.to_string());
    Ok(Admitted { device, name, sync })
}

/// What pairing achieved on the new device.
pub struct Joined {
    /// The new device's vault: unlocked, and filled if the first sync completed.
    pub vault: Vault,
    /// The first sync, or why it did not complete. The vault file is valid
    /// either way and will catch up at the next sync.
    pub sync: Result<SessionReport, String>,
}

/// Where and how the new device creates its vault file.
pub struct NewVault<'a> {
    /// Path of the vault file to create.
    pub path: &'a Path,
    /// This device's own master password.
    pub master_password: &'a str,
    /// This device's hardware key store, if it has one.
    pub hardware: Option<&'a dyn HardwareKeyStore>,
    /// Creation options.
    pub options: CreateOptions,
}

/// The new device's side of pairing over `link`: asks to join, creates its
/// vault file from the grant and runs the first sync.
pub fn pair_as_new(
    link: Box<dyn Link>,
    joiner: Joiner,
    pairing: &PairingLink<'_>,
    new_vault: NewVault<'_>,
    config: &DriveConfig,
) -> Result<Joined, DriveError> {
    let mut connection = Connection::open(link, config.idle_timeout)?;
    let channel = pairing_channel(&mut connection, joiner.channel_key(), pairing)?;
    let mut messenger = Messenger::new(connection, channel, config)?;

    messenger.send(&joiner.request())?;
    let reply = messenger.receive(None)?;
    let mut vault = joiner.accept(
        &reply,
        new_vault.path,
        new_vault.master_password,
        new_vault.hardware,
        new_vault.options,
    )?;
    messenger.send(&ack_message())?;
    let sync = run_session(&mut messenger, &mut vault).map_err(|error| error.to_string());
    Ok(Joined { vault, sync })
}
