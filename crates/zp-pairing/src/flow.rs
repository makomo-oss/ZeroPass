//! The pairing conversation (`docs/spec/pairing.md` §3.3, §3.4), without I/O.
//!
//! ```text
//! new device                              existing device
//!    │── JoinRequest ────────────────────────▶│  (the user confirms the name)
//!    │◀──────────────────────────── JoinGrant ─│  vault id, registry, vault keys
//!    │── JoinAck ────────────────────────────▶│
//!
//! registered device                       device with the keys
//!    │── KeysRequest ────────────────────────▶│  (the user confirms the name)
//!    │◀──────────────────────────── KeysGrant ─│  vault id, TOTP and passkey keys
//!    │── JoinAck ────────────────────────────▶│
//! ```
//!
//! The messages travel inside the pairing channel
//! ([`Handshake::pairing`](crate::Handshake::pairing)), framed like sync
//! messages. [`Joiner`] is the new device's side; [`admit`] is the existing
//! device's, and [`answer`] answers either request. A registered device that
//! lacks the TOTP or passkey keys asks for them with [`keys_request`] and takes
//! them in with [`take_keys`] (ADR-0011). Which side showed the QR code does
//! not matter here.

use std::path::Path;

use prost::Message;
use zeroize::{Zeroize, Zeroizing};
use zp_crypto::{ChannelKey, DeviceId, DomainId, HardwareKeyStore, SignPublicKey, VaultId};
use zp_sync::{decode_registry, encode_registry};
use zp_vault::{CreateOptions, GrantedKey, JoinIdentity, Vault, VaultGrant};

use crate::PairingError;
use crate::noise::ChannelPublicKey;

#[derive(Clone, PartialEq, Message)]
struct Envelope {
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6")]
    body: Option<Body>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
enum Body {
    #[prost(message, tag = "1")]
    Request(RequestMsg),
    #[prost(message, tag = "2")]
    Grant(GrantMsg),
    #[prost(bool, tag = "3")]
    Ack(bool),
    #[prost(bool, tag = "4")]
    Refused(bool),
    #[prost(message, tag = "5")]
    KeysRequest(KeysRequestMsg),
    #[prost(message, tag = "6")]
    KeysGrant(KeysGrantMsg),
}

/// A registered device asks for the TOTP and passkey keys (ADR-0011).
#[derive(Clone, PartialEq, Message)]
struct KeysRequestMsg {
    #[prost(bytes = "vec", tag = "1")]
    device_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct KeysGrantMsg {
    #[prost(bytes = "vec", tag = "1")]
    vault_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    keys: Vec<KeyMsg>,
}

impl core::fmt::Debug for KeysGrantMsg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeysGrantMsg(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Message)]
struct RequestMsg {
    #[prost(bytes = "vec", tag = "1")]
    device_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    sign_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    noise_pk: Vec<u8>,
    #[prost(string, tag = "4")]
    name: String,
}

#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct GrantMsg {
    #[prost(bytes = "vec", tag = "1")]
    vault_id: Vec<u8>,
    /// The registry, as encoded by `zp_sync::encode_registry`.
    #[prost(bytes = "vec", tag = "2")]
    registry: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    keys: Vec<KeyMsg>,
}

#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct KeyMsg {
    #[prost(uint32, tag = "1")]
    domain: u32,
    #[prost(uint32, tag = "2")]
    epoch: u32,
    #[prost(bytes = "vec", tag = "3")]
    key: Vec<u8>,
}

impl core::fmt::Debug for GrantMsg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GrantMsg(<redacted>)")
    }
}

impl core::fmt::Debug for KeyMsg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyMsg(<redacted>)")
    }
}

/// What a new device tells the vault it wants to join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// The identifier the device chose for itself.
    pub device_id: DeviceId,
    /// Its signing key.
    pub sign_pk: SignPublicKey,
    /// Its channel key.
    pub noise_pk: ChannelPublicKey,
    /// The name to show to the user and to record in the registry.
    pub name: String,
}

fn encode(body: Body) -> Zeroizing<Vec<u8>> {
    let mut envelope = Envelope { body: Some(body) };
    let bytes = Zeroizing::new(envelope.encode_to_vec());
    // The prost structs hold copies of the vault keys.
    match &mut envelope.body {
        Some(Body::Grant(grant)) => grant.keys.iter_mut().for_each(|key| key.key.zeroize()),
        Some(Body::KeysGrant(grant)) => grant.keys.iter_mut().for_each(|key| key.key.zeroize()),
        _ => {}
    }
    bytes
}

fn decode(message: &[u8]) -> Result<Body, PairingError> {
    Envelope::decode(message)
        .ok()
        .and_then(|envelope| envelope.body)
        .ok_or(PairingError::Protocol)
}

fn vault_error(error: zp_vault::VaultError) -> PairingError {
    PairingError::Vault(error.to_string())
}

/// The encoded `JoinAck`, sent by the new device once its vault file exists.
pub fn ack_message() -> Vec<u8> {
    encode(Body::Ack(true)).to_vec()
}

/// Whether `message` is a `JoinAck`.
pub fn is_ack(message: &[u8]) -> bool {
    matches!(decode(message), Ok(Body::Ack(true)))
}

/// The existing device's side: handles a `JoinRequest` and returns the reply to
/// send (a `JoinGrant`).
///
/// * `channel_peer` is the channel key the pairing handshake authenticated; the
///   request must name the same key, so a grant can only go to the device at the
///   other end of this channel.
/// * `confirm` shows the request to the user and returns whether they approve.
///   Declining returns [`PairingError::Declined`] and a refusal for the peer.
/// * Every domain of `vault` must be unlocked.
pub fn admit(
    vault: &mut Vault,
    channel_peer: &ChannelPublicKey,
    request: &[u8],
    confirm: impl FnOnce(&JoinRequest) -> bool,
) -> Result<Zeroizing<Vec<u8>>, PairingError> {
    let Body::Request(message) = decode(request)? else {
        return Err(PairingError::Protocol);
    };
    let request = JoinRequest {
        device_id: DeviceId::from_slice(&message.device_id).ok_or(PairingError::Protocol)?,
        sign_pk: SignPublicKey::from_bytes(
            message
                .sign_pk
                .try_into()
                .map_err(|_| PairingError::Protocol)?,
        ),
        noise_pk: message
            .noise_pk
            .try_into()
            .map_err(|_| PairingError::Protocol)?,
        name: message.name,
    };
    if request.noise_pk != *channel_peer {
        return Err(PairingError::KeyMismatch);
    }
    if !confirm(&request) {
        return Err(PairingError::Declined);
    }
    let grant = vault
        .grant(
            request.device_id,
            request.sign_pk,
            request.noise_pk,
            &request.name,
        )
        .map_err(vault_error)?;

    Ok(encode(Body::Grant(GrantMsg {
        vault_id: grant.vault_id.as_bytes().to_vec(),
        registry: encode_registry(&grant.records, &grant.revocations),
        keys: grant
            .keys
            .iter()
            .map(|key| KeyMsg {
                domain: u32::from(key.domain.as_u8()),
                epoch: key.epoch,
                key: key.key.to_vec(),
            })
            .collect(),
    })))
}

/// What the device at the other end of the pairing channel asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asking {
    /// To join the vault.
    Join(JoinRequest),
    /// The TOTP and passkey keys, for a device that is already a member
    /// (ADR-0011).
    Keys {
        /// The asking device.
        device_id: DeviceId,
        /// Its name as the device registry has it.
        name: String,
    },
}

/// The existing device's side for either request: a `JoinRequest` is admitted
/// as by [`admit`]; a `KeysRequest` gets the TOTP and passkey keys, if it
/// comes from a member in good standing whose registered channel key is the
/// one the handshake authenticated (`channel_peer`) and `confirm` agrees.
/// Returns the reply to send and what was asked.
pub fn answer(
    vault: &mut Vault,
    channel_peer: &ChannelPublicKey,
    request: &[u8],
    confirm: impl FnOnce(&Asking) -> bool,
) -> Result<(Zeroizing<Vec<u8>>, Asking), PairingError> {
    match decode(request)? {
        Body::Request(_) => {
            let mut asked = None;
            let reply = admit(vault, channel_peer, request, |request| {
                let asking = Asking::Join(request.clone());
                let approved = confirm(&asking);
                asked = Some(asking);
                approved
            })?;
            Ok((reply, asked.ok_or(PairingError::Protocol)?))
        }
        Body::KeysRequest(message) => {
            let device_id =
                DeviceId::from_slice(&message.device_id).ok_or(PairingError::Protocol)?;
            let registry = vault.registry().map_err(vault_error)?;
            let record = registry
                .get(&device_id)
                .filter(|_| !registry.is_revoked(&device_id) && device_id != vault.device_id())
                .ok_or(PairingError::UnknownPeer)?;
            if record.noise_pk != *channel_peer {
                return Err(PairingError::KeyMismatch);
            }
            let asking = Asking::Keys {
                device_id,
                name: record.name.clone(),
            };
            if !confirm(&asking) {
                return Err(PairingError::Declined);
            }
            let keys = vault.hand_over_keys().map_err(vault_error)?;
            let reply = encode(Body::KeysGrant(KeysGrantMsg {
                vault_id: vault.vault_id().as_bytes().to_vec(),
                keys: keys
                    .iter()
                    .map(|key| KeyMsg {
                        domain: u32::from(key.domain.as_u8()),
                        epoch: key.epoch,
                        key: key.key.to_vec(),
                    })
                    .collect(),
            }));
            Ok((reply, asking))
        }
        _ => Err(PairingError::Protocol),
    }
}

/// The encoded `KeysRequest` of the registered device `device_id`, which
/// lacks the TOTP or passkey keys (ADR-0011). It must speak on the pairing
/// channel with its registered channel key.
pub fn keys_request(device_id: DeviceId) -> Vec<u8> {
    encode(Body::KeysRequest(KeysRequestMsg {
        device_id: device_id.as_bytes().to_vec(),
    }))
    .to_vec()
}

/// Takes in the reply to [`keys_request`]: on a `KeysGrant`, the keys go
/// into `vault` ([`Vault::take_keys`]; `hardware` verifies the user). Returns
/// the domains that gained keys; the caller then sends [`ack_message`].
pub fn take_keys(
    vault: &mut Vault,
    reply: &[u8],
    hardware: &dyn HardwareKeyStore,
) -> Result<Vec<DomainId>, PairingError> {
    let mut message = match decode(reply)? {
        Body::KeysGrant(message) => message,
        Body::Refused(_) => return Err(PairingError::Declined),
        _ => return Err(PairingError::Protocol),
    };
    let keys = (|| {
        let mut keys = Vec::with_capacity(message.keys.len());
        for key in &message.keys {
            keys.push(GrantedKey {
                domain: u8::try_from(key.domain).ok().and_then(DomainId::from_u8)?,
                epoch: key.epoch,
                key: Zeroizing::new(key.key.as_slice().try_into().ok()?),
            });
        }
        Some((VaultId::from_slice(&message.vault_id)?, keys))
    })();
    message.keys.iter_mut().for_each(|key| key.key.zeroize());
    let (vault_id, keys) = keys.ok_or(PairingError::Protocol)?;
    vault
        .take_keys(vault_id, &keys, hardware)
        .map_err(vault_error)
}

/// The reply to send when the user declined a request.
pub fn refusal_message() -> Vec<u8> {
    encode(Body::Refused(true)).to_vec()
}

/// The new device's side of pairing.
#[derive(Debug)]
pub struct Joiner {
    identity: JoinIdentity,
    name: String,
}

impl Joiner {
    /// Generates the new device's keys. `name` is what the existing device shows
    /// to the user for confirmation.
    pub fn new(name: &str) -> Result<Self, PairingError> {
        Ok(Self {
            identity: JoinIdentity::generate().map_err(vault_error)?,
            name: name.to_owned(),
        })
    }

    /// The channel key to use as this device's static key in the pairing
    /// handshake.
    pub fn channel_key(&self) -> &ChannelKey {
        self.identity.channel_key()
    }

    /// The encoded `JoinRequest`.
    pub fn request(&self) -> Vec<u8> {
        encode(Body::Request(RequestMsg {
            device_id: self.identity.device_id().as_bytes().to_vec(),
            sign_pk: self.identity.sign_pk().as_bytes().to_vec(),
            noise_pk: self.identity.channel_key().public_bytes().to_vec(),
            name: self.name.clone(),
        }))
        .to_vec()
    }

    /// Handles the existing device's reply. On a `JoinGrant`, creates this
    /// device's vault file at `path`, protected by `master_password` (this
    /// device's own) and, for the TOTP and passkey domains, by `hardware`.
    ///
    /// Returns the unlocked, still empty vault; the caller then sends
    /// [`ack_message`] and syncs.
    pub fn accept(
        self,
        reply: &[u8],
        path: &Path,
        master_password: &str,
        hardware: Option<&dyn HardwareKeyStore>,
        options: CreateOptions,
    ) -> Result<Vault, PairingError> {
        let mut message = match decode(reply)? {
            Body::Grant(message) => message,
            Body::Refused(_) => return Err(PairingError::Declined),
            _ => return Err(PairingError::Protocol),
        };
        let grant = (|| {
            let (records, revocations) = decode_registry(&message.registry).ok()?;
            let mut keys = Vec::with_capacity(message.keys.len());
            for key in &message.keys {
                keys.push(GrantedKey {
                    domain: u8::try_from(key.domain).ok().and_then(DomainId::from_u8)?,
                    epoch: key.epoch,
                    key: Zeroizing::new(key.key.as_slice().try_into().ok()?),
                });
            }
            Some(VaultGrant {
                vault_id: VaultId::from_slice(&message.vault_id)?,
                records,
                revocations,
                keys,
            })
        })();
        message.keys.iter_mut().for_each(|key| key.key.zeroize());
        let grant = grant.ok_or(PairingError::Protocol)?;

        Vault::join(
            path,
            self.identity,
            grant,
            master_password,
            hardware,
            options,
        )
        .map_err(vault_error)
    }
}
