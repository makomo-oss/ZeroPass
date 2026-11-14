//! The vault daemon as a store of ops (`docs/spec/ipc.md` §10).
//!
//! The sync daemon runs the sync protocol with other devices, but the ops live
//! in the vault file, which only the vault daemon opens. [`RemoteOpLog`] is the
//! sync daemon's view of that file: every [`OpLog`] call becomes a request to
//! the vault daemon. What crosses is ciphertext, signatures and public keys,
//! plus this device's channel key; never a vault key.

use std::sync::{Mutex, MutexGuard};

use zp_crypto::{ChannelKey, DeviceId, VaultId};
use zp_sync::{
    ApplyReport, DeviceRecord, KeyUpdate, Op, OpLog, Registry, Revocation, SyncError,
    VersionVector, decode_key_updates, decode_ops, decode_registry, decode_vector,
    encode_key_updates, encode_ops, encode_registry,
};

use crate::proto::{self, request, response};
use crate::{Client, IpcError};

/// An error of [`RemoteOpLog`].
#[derive(Debug, thiserror::Error)]
pub enum RemoteSyncError {
    /// What the daemon returned breaks the rules of the sync protocol.
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// The daemon refused the request or could not be reached.
    #[error(transparent)]
    Ipc(#[from] IpcError),
}

/// The ops of a vault, reached through its daemon.
pub struct RemoteOpLog {
    client: Mutex<Client>,
    vault_id: VaultId,
    device_id: DeviceId,
    channel_key: ChannelKey,
}

impl core::fmt::Debug for RemoteOpLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteOpLog")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

fn unexpected() -> IpcError {
    IpcError::Protocol("the daemon gave an unexpected answer")
}

impl RemoteOpLog {
    /// Asks the daemon at the other end of `client` who this device is and
    /// keeps the connection for the calls that follow.
    pub fn new(mut client: Client) -> Result<Self, RemoteSyncError> {
        let reply = client.call(request::Body::SyncIdentity(proto::SyncIdentity {}))?;
        let response::Body::SyncIdentity(identity) = reply else {
            return Err(unexpected().into());
        };
        let malformed = || IpcError::Protocol("the daemon sent a malformed identity");
        let vault_id = VaultId::from_slice(&identity.vault_id).ok_or_else(malformed)?;
        let device_id = DeviceId::from_slice(&identity.device_id).ok_or_else(malformed)?;
        let secret: &[u8; 32] = identity
            .channel_key
            .as_slice()
            .try_into()
            .map_err(|_| malformed())?;
        Ok(Self {
            client: Mutex::new(client),
            vault_id,
            device_id,
            channel_key: ChannelKey::from_secret_bytes(secret),
        })
    }

    /// The key that authenticates this device to its peers.
    pub fn channel_key(&self) -> &ChannelKey {
        &self.channel_key
    }

    fn client(&self) -> MutexGuard<'_, Client> {
        self.client
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// A request that is answered with sync data.
    fn fetch(&self, request: request::Body) -> Result<Vec<u8>, RemoteSyncError> {
        match self.client().call(request)? {
            response::Body::SyncData(data) => Ok(data.data),
            _ => Err(unexpected().into()),
        }
    }

    /// A request that hands sync data in.
    fn hand_in(&self, request: request::Body) -> Result<proto::SyncMerged, RemoteSyncError> {
        match self.client().call(request)? {
            response::Body::SyncMerged(merged) => Ok(merged),
            _ => Err(unexpected().into()),
        }
    }
}

fn count(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

impl OpLog for RemoteOpLog {
    type Error = RemoteSyncError;

    fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    fn device_id(&self) -> DeviceId {
        self.device_id
    }

    fn registry(&self) -> Result<Registry, Self::Error> {
        let bytes = self.fetch(request::Body::SyncRegistry(proto::SyncRegistry {}))?;
        let (records, revocations) = decode_registry(&bytes)?;
        // The daemon speaks for this device's own vault file, so the vault's
        // founding record is taken on its word; every other record and every
        // revocation is verified again here.
        Ok(Registry::from_trusted(self.vault_id, records, revocations)?)
    }

    fn merge_registry(
        &mut self,
        records: Vec<DeviceRecord>,
        revocations: Vec<Revocation>,
    ) -> Result<bool, Self::Error> {
        let merged = self.hand_in(request::Body::SyncMergeRegistry(proto::SyncMergeRegistry {
            registry: encode_registry(&records, &revocations),
        }))?;
        Ok(merged.added > 0)
    }

    fn version_vector(&self) -> Result<VersionVector, Self::Error> {
        let bytes = self.fetch(request::Body::SyncVector(proto::SyncVector {}))?;
        Ok(decode_vector(&bytes)?)
    }

    fn ops_after(
        &self,
        device: DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Op>, Self::Error> {
        let bytes = self.fetch(request::Body::SyncOpsAfter(proto::SyncOpsAfter {
            device_id: device.as_bytes().to_vec(),
            after_seq,
            limit: u32::try_from(limit).unwrap_or(u32::MAX),
        }))?;
        Ok(decode_ops(&bytes)?)
    }

    fn apply(&mut self, ops: Vec<Op>) -> Result<ApplyReport, Self::Error> {
        let merged = self.hand_in(request::Body::SyncApply(proto::SyncApply {
            ops: encode_ops(&ops),
        }))?;
        Ok(ApplyReport {
            applied: count(merged.added),
            duplicates: count(merged.duplicates),
            became_current: count(merged.became_current),
        })
    }

    fn key_updates(&self) -> Result<Vec<KeyUpdate>, Self::Error> {
        let bytes = self.fetch(request::Body::SyncKeyUpdates(proto::SyncKeyUpdates {}))?;
        Ok(decode_key_updates(&bytes)?)
    }

    fn merge_key_updates(&mut self, updates: Vec<KeyUpdate>) -> Result<usize, Self::Error> {
        let merged = self.hand_in(request::Body::SyncMergeKeyUpdates(
            proto::SyncMergeKeyUpdates {
                updates: encode_key_updates(&updates),
            },
        ))?;
        Ok(count(merged.added))
    }
}
