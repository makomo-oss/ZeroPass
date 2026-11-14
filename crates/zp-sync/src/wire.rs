//! The messages of the sync session on the wire (`docs/spec/sync.md` §7).
//!
//! Messages are Protocol Buffers. Field tags are part of the protocol and must
//! never be reused. Everything received is converted into the validated domain
//! types before it is used; a message that does not convert is a protocol error.

use prost::Message;
use zp_crypto::{DeviceId, DomainId, ItemId, SignPublicKey, VaultId};

use crate::{DeviceRecord, KeyUpdate, Op, OpBody, Payload, Revocation, SyncError, VersionVector};

/// Largest encoded message accepted or produced: 1 MiB.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Envelope {
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub(crate) body: Option<Body>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub(crate) enum Body {
    #[prost(message, tag = "1")]
    Hello(Hello),
    #[prost(message, tag = "2")]
    Devices(Devices),
    #[prost(message, tag = "3")]
    Vector(Vector),
    #[prost(message, tag = "4")]
    Ops(Ops),
    #[prost(message, tag = "5")]
    Done(Vector),
    #[prost(message, tag = "6")]
    KeyUpdates(KeyUpdates),
    #[prost(message, tag = "7")]
    Progress(Progress),
}

/// "Still receiving": sent by a side that is taking in the peer's data but has
/// had nothing else to send for a while, so that the peer does not give up on
/// the connection as silent. It has no content.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Progress {}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Hello {
    #[prost(uint32, tag = "1")]
    pub(crate) protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) vault_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) device_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Devices {
    #[prost(message, repeated, tag = "1")]
    pub(crate) records: Vec<DeviceRecordMsg>,
    #[prost(message, repeated, tag = "2")]
    pub(crate) revocations: Vec<RevocationMsg>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DeviceRecordMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) device_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) sign_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) noise_pk: Vec<u8>,
    #[prost(string, tag = "4")]
    pub(crate) name: String,
    #[prost(bytes = "vec", tag = "5")]
    pub(crate) introduced_by: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RevocationMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) device_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) revoked_by: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Vector {
    #[prost(message, repeated, tag = "1")]
    pub(crate) entries: Vec<VectorEntry>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct VectorEntry {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) device_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub(crate) seq: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Ops {
    #[prost(message, repeated, tag = "1")]
    pub(crate) ops: Vec<OpMsg>,
    /// Set on the last batch: the sender has no more ops for this session.
    #[prost(bool, tag = "2")]
    pub(crate) last: bool,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct OpMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) device_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub(crate) seq: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) item_id: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub(crate) domain: u32,
    #[prost(uint64, tag = "5")]
    pub(crate) hlc: u64,
    #[prost(uint32, tag = "6")]
    pub(crate) key_epoch: u32,
    #[prost(bool, tag = "7")]
    pub(crate) deleted: bool,
    #[prost(bytes = "vec", tag = "8")]
    pub(crate) wrapped_dek: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub(crate) ciphertext: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct KeyUpdates {
    #[prost(message, repeated, tag = "1")]
    pub(crate) updates: Vec<KeyUpdateMsg>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct KeyUpdateMsg {
    #[prost(uint32, tag = "1")]
    pub(crate) domain: u32,
    #[prost(uint32, tag = "2")]
    pub(crate) epoch: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) device_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) wrapped_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub(crate) signature: Vec<u8>,
}

const MALFORMED: SyncError = SyncError::MalformedMessage("a field has the wrong length or value");

pub(crate) fn device_id(bytes: &[u8]) -> Result<DeviceId, SyncError> {
    DeviceId::from_slice(bytes).ok_or(MALFORMED)
}

pub(crate) fn vault_id(bytes: &[u8]) -> Result<VaultId, SyncError> {
    VaultId::from_slice(bytes).ok_or(MALFORMED)
}

fn array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], SyncError> {
    bytes.try_into().map_err(|_| MALFORMED)
}

impl Envelope {
    pub(crate) fn encode_body(body: Body) -> Result<Vec<u8>, SyncError> {
        let bytes = Envelope { body: Some(body) }.encode_to_vec();
        if bytes.len() > MAX_MESSAGE_LEN {
            return Err(SyncError::MessageTooLarge);
        }
        Ok(bytes)
    }

    pub(crate) fn decode_body(bytes: &[u8]) -> Result<Body, SyncError> {
        if bytes.len() > MAX_MESSAGE_LEN {
            return Err(SyncError::MessageTooLarge);
        }
        Envelope::decode(bytes)
            .ok()
            .and_then(|envelope| envelope.body)
            .ok_or(SyncError::MalformedMessage("not a sync message"))
    }
}

impl From<&DeviceRecord> for DeviceRecordMsg {
    fn from(record: &DeviceRecord) -> Self {
        Self {
            device_id: record.device_id.as_bytes().to_vec(),
            sign_pk: record.sign_pk.as_bytes().to_vec(),
            noise_pk: record.noise_pk.to_vec(),
            name: record.name.clone(),
            introduced_by: record.introduced_by.as_bytes().to_vec(),
            signature: record.signature.to_vec(),
        }
    }
}

impl TryFrom<DeviceRecordMsg> for DeviceRecord {
    type Error = SyncError;

    fn try_from(message: DeviceRecordMsg) -> Result<Self, SyncError> {
        Ok(Self {
            device_id: device_id(&message.device_id)?,
            sign_pk: SignPublicKey::from_bytes(array(message.sign_pk)?),
            noise_pk: array(message.noise_pk)?,
            name: message.name,
            introduced_by: device_id(&message.introduced_by)?,
            signature: array(message.signature)?,
        })
    }
}

impl From<&Revocation> for RevocationMsg {
    fn from(revocation: &Revocation) -> Self {
        Self {
            device_id: revocation.device_id.as_bytes().to_vec(),
            revoked_by: revocation.revoked_by.as_bytes().to_vec(),
            signature: revocation.signature.to_vec(),
        }
    }
}

impl TryFrom<RevocationMsg> for Revocation {
    type Error = SyncError;

    fn try_from(message: RevocationMsg) -> Result<Self, SyncError> {
        Ok(Self {
            device_id: device_id(&message.device_id)?,
            revoked_by: device_id(&message.revoked_by)?,
            signature: array(message.signature)?,
        })
    }
}

impl From<&VersionVector> for Vector {
    fn from(vector: &VersionVector) -> Self {
        Self {
            entries: vector
                .iter()
                .map(|(device, seq)| VectorEntry {
                    device_id: device.as_bytes().to_vec(),
                    seq,
                })
                .collect(),
        }
    }
}

impl TryFrom<Vector> for VersionVector {
    type Error = SyncError;

    fn try_from(message: Vector) -> Result<Self, SyncError> {
        message
            .entries
            .into_iter()
            .map(|entry| Ok((device_id(&entry.device_id)?, entry.seq)))
            .collect()
    }
}

impl From<&Op> for OpMsg {
    fn from(op: &Op) -> Self {
        let (wrapped_dek, ciphertext) = match &op.body.payload {
            Some(payload) => (payload.wrapped_dek.clone(), payload.ciphertext.clone()),
            None => (Vec::new(), Vec::new()),
        };
        Self {
            device_id: op.body.device_id.as_bytes().to_vec(),
            seq: op.body.seq,
            item_id: op.body.item_id.as_bytes().to_vec(),
            domain: u32::from(op.body.domain.as_u8()),
            hlc: op.body.hlc,
            key_epoch: op.body.key_epoch,
            deleted: op.body.payload.is_none(),
            wrapped_dek,
            ciphertext,
            signature: op.signature.to_vec(),
        }
    }
}

impl TryFrom<OpMsg> for Op {
    type Error = SyncError;

    fn try_from(message: OpMsg) -> Result<Self, SyncError> {
        let payload = match message.deleted {
            // A tombstone carries no payload; anything else is not a tombstone.
            true if message.wrapped_dek.is_empty() && message.ciphertext.is_empty() => None,
            true => return Err(MALFORMED),
            false => Some(Payload {
                wrapped_dek: message.wrapped_dek,
                ciphertext: message.ciphertext,
            }),
        };
        let domain = u8::try_from(message.domain)
            .ok()
            .and_then(DomainId::from_u8)
            .ok_or(MALFORMED)?;
        Ok(Op {
            body: OpBody {
                device_id: device_id(&message.device_id)?,
                seq: message.seq,
                item_id: ItemId::from_slice(&message.item_id).ok_or(MALFORMED)?,
                domain,
                hlc: message.hlc,
                key_epoch: message.key_epoch,
                payload,
            },
            signature: array(message.signature)?,
        })
    }
}

impl From<&KeyUpdate> for KeyUpdateMsg {
    fn from(update: &KeyUpdate) -> Self {
        Self {
            domain: u32::from(update.domain.as_u8()),
            epoch: update.epoch,
            device_id: update.device_id.as_bytes().to_vec(),
            wrapped_key: update.wrapped_key.clone(),
            signature: update.signature.to_vec(),
        }
    }
}

impl TryFrom<KeyUpdateMsg> for KeyUpdate {
    type Error = SyncError;

    fn try_from(message: KeyUpdateMsg) -> Result<Self, SyncError> {
        Ok(Self {
            domain: u8::try_from(message.domain)
                .ok()
                .and_then(DomainId::from_u8)
                .ok_or(MALFORMED)?,
            epoch: message.epoch,
            device_id: device_id(&message.device_id)?,
            wrapped_key: message.wrapped_key,
            signature: array(message.signature)?,
        })
    }
}

/// Serialises device records and revocations, for protocols other than the sync
/// session that need to carry a registry (pairing).
pub fn encode_registry<'a>(
    records: impl IntoIterator<Item = &'a DeviceRecord>,
    revocations: impl IntoIterator<Item = &'a Revocation>,
) -> Vec<u8> {
    Devices {
        records: records.into_iter().map(Into::into).collect(),
        revocations: revocations.into_iter().map(Into::into).collect(),
    }
    .encode_to_vec()
}

/// Parses what [`encode_registry`] produced. The records are not verified here;
/// build a [`Registry`](crate::Registry) from them for that.
pub fn decode_registry(bytes: &[u8]) -> Result<(Vec<DeviceRecord>, Vec<Revocation>), SyncError> {
    let devices =
        Devices::decode(bytes).map_err(|_| SyncError::MalformedMessage("not a device registry"))?;
    Ok((
        devices
            .records
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?,
        devices
            .revocations
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?,
    ))
}

#[cfg(test)]
mod tests {
    use zp_crypto::DeviceSigningKey;

    use super::*;

    const VAULT: VaultId = VaultId::from_bytes([1; 16]);

    fn op(payload: Option<Payload>) -> Op {
        OpBody {
            device_id: DeviceId::from_bytes([2; 16]),
            seq: 3,
            item_id: ItemId::from_bytes([4; 16]),
            domain: DomainId::Totp,
            hlc: 99,
            key_epoch: 2,
            payload,
        }
        .sign(&VAULT, &DeviceSigningKey::generate().unwrap())
    }

    #[test]
    fn ops_round_trip() {
        let live = op(Some(Payload {
            wrapped_dek: vec![1; 73],
            ciphertext: vec![2; 50],
        }));
        let tombstone = op(None);
        for original in [live, tombstone] {
            let back = Op::try_from(OpMsg::from(&original)).unwrap();
            assert_eq!(back, original);
        }
    }

    #[test]
    fn malformed_ops_do_not_convert() {
        let good = OpMsg::from(&op(Some(Payload {
            wrapped_dek: vec![1; 73],
            ciphertext: vec![2; 50],
        })));
        let changes: [fn(&mut OpMsg); 7] = [
            |m| m.device_id.truncate(15),
            |m| m.item_id.push(0),
            |m| m.domain = 0,
            |m| m.domain = 300,
            |m| m.signature.truncate(63),
            // A "tombstone" that still carries a payload.
            |m| m.deleted = true,
            |m| m.signature.clear(),
        ];
        for change in changes {
            let mut bad = good.clone();
            change(&mut bad);
            assert!(Op::try_from(bad).is_err());
        }
    }

    #[test]
    fn version_vectors_round_trip() {
        let vector: VersionVector = [
            (DeviceId::from_bytes([1; 16]), 5),
            (DeviceId::from_bytes([2; 16]), 9),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            VersionVector::try_from(Vector::from(&vector)).unwrap(),
            vector
        );
        let bad = Vector {
            entries: vec![VectorEntry {
                device_id: vec![1; 3],
                seq: 1,
            }],
        };
        assert!(VersionVector::try_from(bad).is_err());
    }

    #[test]
    fn envelopes_reject_garbage_and_oversized_messages() {
        let hello = Body::Hello(Hello {
            protocol_version: 1,
            vault_id: vec![1; 16],
            device_id: vec![2; 16],
        });
        let bytes = Envelope::encode_body(hello.clone()).unwrap();
        assert_eq!(Envelope::decode_body(&bytes).unwrap(), hello);

        assert!(matches!(
            Envelope::decode_body(&[0xFF; 10]),
            Err(SyncError::MalformedMessage(_))
        ));
        // An empty message has no body.
        assert!(matches!(
            Envelope::decode_body(&[]),
            Err(SyncError::MalformedMessage(_))
        ));
        assert_eq!(
            Envelope::decode_body(&vec![0; MAX_MESSAGE_LEN + 1]),
            Err(SyncError::MessageTooLarge)
        );

        let huge = Body::Ops(Ops {
            ops: vec![OpMsg {
                ciphertext: vec![0; MAX_MESSAGE_LEN],
                ..Default::default()
            }],
            last: true,
        });
        assert_eq!(Envelope::encode_body(huge), Err(SyncError::MessageTooLarge));
    }
}
