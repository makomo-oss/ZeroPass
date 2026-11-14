//! The sync requests (`docs/spec/ipc.md` §10): the vault as a store of ops for
//! the sync daemon. Everything here works on the locked vault and moves
//! ciphertext, signatures and public keys; the one secret is this device's
//! channel key, which is not a vault key.

use zp_ipc::proto::{self, ErrorCode, request, response};
use zp_sync::{
    OpLog, decode_key_updates, decode_ops, decode_registry, encode_key_updates, encode_ops,
    encode_registry, encode_vector,
};
use zp_vault::Vault;

use crate::convert::{self, vault_error};

type Reply = Result<response::Body, proto::Error>;

/// Sync data that does not parse is the peer's fault, not the daemon's.
fn rejected(error: zp_sync::SyncError) -> proto::Error {
    proto::Error::new(ErrorCode::SyncRejected, error.to_string())
}

fn data(bytes: Vec<u8>) -> Reply {
    Ok(response::Body::SyncData(proto::SyncData { data: bytes }))
}

fn merged(added: usize, duplicates: usize, became_current: usize) -> Reply {
    Ok(response::Body::SyncMerged(proto::SyncMerged {
        added: added as u64,
        duplicates: duplicates as u64,
        became_current: became_current as u64,
    }))
}

/// Whether `request` is one of the sync requests.
pub(crate) fn is_sync_request(request: &request::Body) -> bool {
    use request::Body;
    matches!(
        request,
        Body::SyncIdentity(_)
            | Body::SyncRegistry(_)
            | Body::SyncMergeRegistry(_)
            | Body::SyncVector(_)
            | Body::SyncOpsAfter(_)
            | Body::SyncApply(_)
            | Body::SyncKeyUpdates(_)
            | Body::SyncMergeKeyUpdates(_)
    )
}

/// Answers a sync request. `request` must be one ([`is_sync_request`]).
pub(crate) fn handle(vault: &mut Vault, request: request::Body) -> Reply {
    use request::Body;
    match request {
        Body::SyncIdentity(_) => {
            let key = vault.channel_key().map_err(vault_error)?;
            Ok(response::Body::SyncIdentity(proto::SyncIdentityReply {
                vault_id: vault.vault_id().as_bytes().to_vec(),
                device_id: vault.device_id().as_bytes().to_vec(),
                channel_key: key.secret_bytes().to_vec(),
            }))
        }
        Body::SyncRegistry(_) => {
            let registry = OpLog::registry(vault).map_err(vault_error)?;
            data(encode_registry(registry.records(), registry.revocations()))
        }
        Body::SyncMergeRegistry(request) => {
            let (records, revocations) = decode_registry(&request.registry).map_err(rejected)?;
            let changed = vault
                .merge_registry(records, revocations)
                .map_err(vault_error)?;
            merged(usize::from(changed), 0, 0)
        }
        Body::SyncVector(_) => {
            let vector = OpLog::version_vector(vault).map_err(vault_error)?;
            data(encode_vector(&vector))
        }
        Body::SyncOpsAfter(request) => {
            let device = convert::device_id(&request.device_id)?;
            let ops = vault
                .ops_after(device, request.after_seq, request.limit as usize)
                .map_err(vault_error)?;
            data(encode_ops(&ops))
        }
        Body::SyncApply(request) => {
            let ops = decode_ops(&request.ops).map_err(rejected)?;
            let report = vault.apply(ops).map_err(vault_error)?;
            merged(report.applied, report.duplicates, report.became_current)
        }
        Body::SyncKeyUpdates(_) => {
            let updates = vault.key_updates().map_err(vault_error)?;
            data(encode_key_updates(&updates))
        }
        Body::SyncMergeKeyUpdates(request) => {
            let updates = decode_key_updates(&request.updates).map_err(rejected)?;
            let added = vault.merge_key_updates(updates).map_err(vault_error)?;
            merged(added, 0, 0)
        }
        _ => Err(convert::bad_request("not a sync request")),
    }
}
