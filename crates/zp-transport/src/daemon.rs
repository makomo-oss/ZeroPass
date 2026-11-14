//! The sync loop: keeps one vault file in sync with whichever devices of the
//! vault are nearby (`docs/spec/lan.md` §5).
//!
//! The loop works on the locked vault file. It holds the channel key and the
//! device registry, never a vault key, and handles nothing but ciphertext and
//! signatures.
//!
//! Each [`SyncDaemon::step`]:
//! 1. announces this device under its current anonymous tag,
//! 2. answers one incoming connection, if there is one,
//! 3. looks for announcements of other devices of the vault and connects to
//!    those it is due to sync with.
//!
//! Who connects: of two devices, only the one with the lower device identifier
//! ever opens the connection. It does so at once when it has changes the peer
//! has not been offered, and otherwise every [`DaemonConfig::poll_interval`] to
//! pick up the peer's changes. The loop is single-threaded, so if both sides
//! could connect, two devices dialling each other at the same moment would each
//! wait for the other to answer; with one fixed direction per pair that cannot
//! happen, and chains of waiting devices always end at the highest identifier.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zp_crypto::{ChannelKey, DeviceId};
use zp_ipc::RemoteOpLog;
use zp_sync::{OpLog, SessionReport};
use zp_vault::Store;

use crate::DriveError;
use crate::discovery::{identify, slot_of, tag_for};
use crate::driver::{DriveConfig, sync_as_initiator, sync_as_responder};
use crate::transport::Transport;

/// Settings of the sync loop.
#[derive(Debug, Clone, Copy)]
pub struct DaemonConfig {
    /// How long one step waits for an incoming connection.
    pub accept_wait: Duration,
    /// How long one step listens for announcements.
    pub discover_wait: Duration,
    /// How often the device with the lower identifier asks a peer for changes.
    pub poll_interval: Duration,
    /// How long to leave a peer alone after a failed attempt.
    pub retry_after: Duration,
    /// Limits of a single session.
    pub drive: DriveConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            accept_wait: Duration::from_millis(300),
            discover_wait: Duration::from_millis(300),
            poll_interval: Duration::from_secs(2),
            retry_after: Duration::from_secs(10),
            drive: DriveConfig::default(),
        }
    }
}

/// Something the sync loop did.
#[derive(Debug)]
pub enum Event {
    /// A session with a peer completed.
    Synced {
        /// The peer.
        peer: DeviceId,
        /// Its name in the registry.
        name: String,
        /// Whether this device opened the connection.
        initiated: bool,
        /// What the session did.
        report: SessionReport,
    },
    /// A session failed or was refused.
    Failed {
        /// The peer, if it was identified.
        peer: Option<DeviceId>,
        /// Whether this device opened the connection.
        initiated: bool,
        /// Why.
        error: DriveError,
    },
}

#[derive(Debug, Clone, Copy)]
struct PeerState {
    /// When this device last connected to the peer (successfully or not).
    last_attempt: Instant,
    /// Whether that attempt failed.
    failed: bool,
    /// This device's own sequence number at the last completed session.
    own_seq_synced: u64,
}

/// What the sync loop keeps in sync: the ops of a vault, and the key that
/// authenticates this device to its peers.
pub trait SyncStore: OpLog {
    /// This device's channel key.
    fn channel_key(&self) -> Result<ChannelKey, DriveError>;
}

/// The vault file itself, opened without any key.
impl SyncStore for Store {
    fn channel_key(&self) -> Result<ChannelKey, DriveError> {
        Store::channel_key(self).map_err(store_error)
    }
}

/// The vault file as served by the vault daemon.
impl SyncStore for RemoteOpLog {
    fn channel_key(&self) -> Result<ChannelKey, DriveError> {
        let secret = RemoteOpLog::channel_key(self).secret_bytes();
        Ok(ChannelKey::from_secret_bytes(secret))
    }
}

fn store_error(error: impl core::fmt::Display) -> DriveError {
    DriveError::Sync(error.to_string())
}

/// The sync loop of one vault over one transport.
pub struct SyncDaemon<S: SyncStore, T: Transport> {
    store: S,
    transport: T,
    config: DaemonConfig,
    peers: HashMap<DeviceId, PeerState>,
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl<S: SyncStore, T: Transport> SyncDaemon<S, T> {
    /// Prepares the loop. `store` holds the ops of the vault: the vault file
    /// opened without any key, or the vault daemon.
    pub fn new(store: S, transport: T, config: DaemonConfig) -> Self {
        Self {
            store,
            transport,
            config,
            peers: HashMap::new(),
        }
    }

    /// The store being synced.
    pub fn store(&self) -> &S {
        &self.store
    }

    fn own_seq(&self) -> Result<u64, DriveError> {
        let vector = self.store.version_vector().map_err(store_error)?;
        Ok(vector.get(&self.store.device_id()))
    }

    fn record(&mut self, peer: DeviceId, failed: bool, own_seq_synced: Option<u64>) {
        let previous = self
            .peers
            .get(&peer)
            .map_or(0, |state| state.own_seq_synced);
        self.peers.insert(
            peer,
            PeerState {
                last_attempt: Instant::now(),
                failed,
                own_seq_synced: own_seq_synced.unwrap_or(previous),
            },
        );
    }

    /// Whether this device should connect to `peer` now.
    fn is_due(&self, peer: DeviceId, own_seq: u64) -> bool {
        // Only the lower identifier of a pair dials; see the module docs.
        if self.store.device_id() >= peer {
            return false;
        }
        let Some(state) = self.peers.get(&peer) else {
            return true;
        };
        let since = state.last_attempt.elapsed();
        if state.failed {
            return since >= self.config.retry_after;
        }
        own_seq > state.own_seq_synced || since >= self.config.poll_interval
    }

    /// Runs one round of the loop and reports what happened.
    pub fn step(&mut self) -> Result<Vec<Event>, DriveError> {
        let mut events = Vec::new();
        let now = unix_secs();
        let key = self.store.channel_key()?;
        let vault_id = self.store.vault_id();
        self.transport
            .advertise(tag_for(&vault_id, key.public_bytes(), slot_of(now)))?;

        // Answer a waiting connection.
        if let Some(link) = self.transport.accept(self.config.accept_wait)? {
            let own_seq = self.own_seq()?;
            match sync_as_responder(link, &mut self.store, &key, &self.config.drive) {
                Ok(report) => {
                    if let Some(peer) = report.peer {
                        self.record(peer, false, Some(own_seq));
                        let name = self.peer_name(peer);
                        events.push(Event::Synced {
                            peer,
                            name,
                            initiated: false,
                            report,
                        });
                    }
                }
                Err(error) => events.push(Event::Failed {
                    peer: None,
                    initiated: false,
                    error,
                }),
            }
        }

        // Connect to the peers that are due.
        let registry = self.store.registry().map_err(store_error)?;
        let own = self.store.device_id();
        for discovered in self.transport.discover(self.config.discover_wait)? {
            let Some(record) = identify(&registry, &discovered.tag, now) else {
                continue;
            };
            let (peer, name, noise_pk) = (record.device_id, record.name.clone(), record.noise_pk);
            let own_seq = self.own_seq()?;
            if peer == own || !self.is_due(peer, own_seq) {
                continue;
            }
            let result = self
                .transport
                .connect(&discovered.address)
                .map_err(DriveError::from)
                .and_then(|link| {
                    sync_as_initiator(link, &mut self.store, &key, &noise_pk, &self.config.drive)
                });
            match result {
                Ok(report) => {
                    self.record(peer, false, Some(own_seq));
                    events.push(Event::Synced {
                        peer,
                        name,
                        initiated: true,
                        report,
                    });
                }
                Err(error) => {
                    self.record(peer, true, None);
                    events.push(Event::Failed {
                        peer: Some(peer),
                        initiated: true,
                        error,
                    });
                }
            }
        }
        Ok(events)
    }

    fn peer_name(&self, peer: DeviceId) -> String {
        self.store
            .registry()
            .ok()
            .and_then(|registry| registry.get(&peer).map(|record| record.name.clone()))
            .unwrap_or_default()
    }

    /// Runs steps until `deadline`, or until `enough` says so after a step.
    /// Returns every event.
    pub fn run_until(
        &mut self,
        deadline: Instant,
        mut enough: impl FnMut(&[Event]) -> bool,
    ) -> Result<Vec<Event>, DriveError> {
        let mut events = Vec::new();
        while Instant::now() < deadline {
            events.extend(self.step()?);
            if enough(&events) {
                break;
            }
        }
        Ok(events)
    }

    /// Stops announcing this device.
    pub fn stop(&mut self) {
        let _ = self.transport.stop_advertising();
    }
}

impl<S: SyncStore, T: Transport> Drop for SyncDaemon<S, T> {
    fn drop(&mut self) {
        self.stop();
    }
}
