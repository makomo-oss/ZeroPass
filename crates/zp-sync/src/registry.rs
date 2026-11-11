//! The device registry: which devices belong to a vault (`docs/spec/sync.md` §6).
//!
//! Every device is described by a [`DeviceRecord`] signed by the device that
//! introduced it; the first device of a vault introduces itself. A
//! [`Revocation`] permanently removes a device from the set of sync partners.
//! Records and revocations are exchanged during sync and can be verified without
//! any vault key.

use std::collections::BTreeMap;

use zp_crypto::{
    DeviceId, DeviceSigningKey, PUBLIC_KEY_LEN, SignPublicKey, SignatureBytes, VaultId,
};

use crate::SyncError;

/// Longest device name, in bytes of UTF-8.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

const LABEL_DEVICE: &[u8] = b"zeropass/v1/device\0";
const LABEL_REVOKE: &[u8] = b"zeropass/v1/device-revoke\0";

/// A device's X25519 public key for the Noise channel.
pub type ChannelPublicKey = [u8; PUBLIC_KEY_LEN];

/// The public description of a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device.
    pub device_id: DeviceId,
    /// Its Ed25519 key, which verifies the ops and records it signs.
    pub sign_pk: SignPublicKey,
    /// Its X25519 key, which authenticates it on the sync channel.
    pub noise_pk: ChannelPublicKey,
    /// A human-readable name such as "Study PC".
    pub name: String,
    /// The device that vouches for this record.
    pub introduced_by: DeviceId,
    /// The introducer's signature.
    pub signature: SignatureBytes,
}

fn check_name(name: &str) -> Result<(), SyncError> {
    if name.len() > MAX_DEVICE_NAME_LEN {
        return Err(SyncError::MalformedDevice("the name is too long"));
    }
    if name.chars().any(char::is_control) {
        return Err(SyncError::MalformedDevice(
            "the name contains control characters",
        ));
    }
    Ok(())
}

impl DeviceRecord {
    fn signing_message(&self, vault_id: &VaultId) -> Vec<u8> {
        let mut message =
            Vec::with_capacity(LABEL_DEVICE.len() + 16 * 3 + 32 * 2 + 1 + self.name.len());
        message.extend_from_slice(LABEL_DEVICE);
        message.extend_from_slice(vault_id.as_bytes());
        message.extend_from_slice(self.device_id.as_bytes());
        message.extend_from_slice(self.sign_pk.as_bytes());
        message.extend_from_slice(&self.noise_pk);
        // `check_name` bounds the length to 64, so it fits one byte.
        message.push(self.name.len() as u8);
        message.extend_from_slice(self.name.as_bytes());
        message.extend_from_slice(self.introduced_by.as_bytes());
        message
    }

    /// Creates the record of a device introduced by `introducer`.
    pub fn introduce(
        vault_id: &VaultId,
        introducer: DeviceId,
        introducer_key: &DeviceSigningKey,
        device_id: DeviceId,
        sign_pk: SignPublicKey,
        noise_pk: ChannelPublicKey,
        name: &str,
    ) -> Result<Self, SyncError> {
        check_name(name)?;
        let mut record = Self {
            device_id,
            sign_pk,
            noise_pk,
            name: name.to_owned(),
            introduced_by: introducer,
            signature: [0; 64],
        };
        record.signature = introducer_key.sign(&record.signing_message(vault_id));
        Ok(record)
    }

    /// Creates the record of a vault's first device, which introduces itself.
    pub fn root(
        vault_id: &VaultId,
        device_id: DeviceId,
        signing_key: &DeviceSigningKey,
        noise_pk: ChannelPublicKey,
        name: &str,
    ) -> Result<Self, SyncError> {
        Self::introduce(
            vault_id,
            device_id,
            signing_key,
            device_id,
            signing_key.public_key(),
            noise_pk,
            name,
        )
    }

    /// Whether the device introduced itself.
    pub fn is_self_introduced(&self) -> bool {
        self.introduced_by == self.device_id
    }

    /// Verifies the record against its introducer's public key.
    pub fn verify(&self, vault_id: &VaultId, introducer: &SignPublicKey) -> Result<(), SyncError> {
        check_name(&self.name)?;
        introducer
            .verify(&self.signing_message(vault_id), &self.signature)
            .map_err(|_| SyncError::BadSignature)
    }
}

/// A signed statement that a device no longer belongs to the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The revoked device.
    pub device_id: DeviceId,
    /// The device that revoked it.
    pub revoked_by: DeviceId,
    /// The revoker's signature.
    pub signature: SignatureBytes,
}

impl Revocation {
    fn signing_message(&self, vault_id: &VaultId) -> Vec<u8> {
        let mut message = Vec::with_capacity(LABEL_REVOKE.len() + 48);
        message.extend_from_slice(LABEL_REVOKE);
        message.extend_from_slice(vault_id.as_bytes());
        message.extend_from_slice(self.device_id.as_bytes());
        message.extend_from_slice(self.revoked_by.as_bytes());
        message
    }

    /// Revokes `device_id` on behalf of `revoker`.
    pub fn sign(
        vault_id: &VaultId,
        device_id: DeviceId,
        revoker: DeviceId,
        revoker_key: &DeviceSigningKey,
    ) -> Self {
        let mut revocation = Self {
            device_id,
            revoked_by: revoker,
            signature: [0; 64],
        };
        revocation.signature = revoker_key.sign(&revocation.signing_message(vault_id));
        revocation
    }

    /// Verifies the revocation against the revoker's public key.
    pub fn verify(&self, vault_id: &VaultId, revoker: &SignPublicKey) -> Result<(), SyncError> {
        revoker
            .verify(&self.signing_message(vault_id), &self.signature)
            .map_err(|_| SyncError::BadSignature)
    }
}

/// The registry of one vault as seen by one device.
///
/// The registry starts from the device's own record (or, for a device that just
/// joined, from the records it was granted) and grows by accepting records and
/// revocations received from sync partners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registry {
    vault_id: VaultId,
    devices: BTreeMap<DeviceId, DeviceRecord>,
    revocations: BTreeMap<DeviceId, Revocation>,
}

impl Registry {
    /// A registry holding only the root record of a new vault.
    pub fn with_root(vault_id: VaultId, root: DeviceRecord) -> Result<Self, SyncError> {
        if !root.is_self_introduced() {
            return Err(SyncError::MalformedDevice(
                "the first device must introduce itself",
            ));
        }
        root.verify(&vault_id, &root.sign_pk)?;
        let mut devices = BTreeMap::new();
        devices.insert(root.device_id, root);
        Ok(Self {
            vault_id,
            devices,
            revocations: BTreeMap::new(),
        })
    }

    /// Rebuilds a registry from records obtained from a **trusted** source: this
    /// device's own vault file, or the grant received over the pairing channel.
    ///
    /// Self-introduced records are accepted here (they are the vault's roots as
    /// vouched for by the source); everything else must still verify.
    pub fn from_trusted(
        vault_id: VaultId,
        records: impl IntoIterator<Item = DeviceRecord>,
        revocations: impl IntoIterator<Item = Revocation>,
    ) -> Result<Self, SyncError> {
        let mut registry = Self {
            vault_id,
            devices: BTreeMap::new(),
            revocations: BTreeMap::new(),
        };
        let mut pending = Vec::new();
        for record in records {
            if record.is_self_introduced() {
                record.verify(&vault_id, &record.sign_pk)?;
                registry.insert(record)?;
            } else {
                pending.push(record);
            }
        }
        registry.merge(pending, revocations)?;
        Ok(registry)
    }

    /// The vault this registry belongs to.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    fn insert(&mut self, record: DeviceRecord) -> Result<bool, SyncError> {
        match self.devices.get(&record.device_id) {
            Some(existing) if *existing == record => Ok(false),
            Some(_) => Err(SyncError::ConflictingDevice(record.device_id)),
            None => {
                self.devices.insert(record.device_id, record);
                Ok(true)
            }
        }
    }

    /// Accepts one record received from a sync partner. Returns whether it was
    /// new.
    ///
    /// The introducer must already be known and the signature must verify.
    /// A self-introduced record is only accepted if it is already present: a
    /// stranger cannot declare itself a member.
    pub fn accept(&mut self, record: DeviceRecord) -> Result<bool, SyncError> {
        if let Some(existing) = self.devices.get(&record.device_id) {
            return if *existing == record {
                Ok(false)
            } else {
                Err(SyncError::ConflictingDevice(record.device_id))
            };
        }
        if record.is_self_introduced() {
            return Err(SyncError::UnknownDevice(record.device_id));
        }
        let introducer = self
            .devices
            .get(&record.introduced_by)
            .ok_or(SyncError::UnknownDevice(record.introduced_by))?;
        record.verify(&self.vault_id, &introducer.sign_pk)?;
        self.insert(record)
    }

    /// Accepts a revocation. Returns whether it was new. Revocations are
    /// permanent; a second revocation of the same device is ignored.
    pub fn accept_revocation(&mut self, revocation: Revocation) -> Result<bool, SyncError> {
        if !self.devices.contains_key(&revocation.device_id) {
            return Err(SyncError::UnknownDevice(revocation.device_id));
        }
        let revoker = self
            .devices
            .get(&revocation.revoked_by)
            .ok_or(SyncError::UnknownDevice(revocation.revoked_by))?;
        revocation.verify(&self.vault_id, &revoker.sign_pk)?;
        if self.revocations.contains_key(&revocation.device_id) {
            return Ok(false);
        }
        self.revocations.insert(revocation.device_id, revocation);
        Ok(true)
    }

    /// Accepts a batch of records and revocations in any order: a record may be
    /// introduced by a device described later in the same batch. Returns whether
    /// anything changed. On error the registry may hold part of the batch; every
    /// accepted element was individually valid.
    pub fn merge(
        &mut self,
        records: impl IntoIterator<Item = DeviceRecord>,
        revocations: impl IntoIterator<Item = Revocation>,
    ) -> Result<bool, SyncError> {
        let mut changed = false;
        let mut pending: Vec<DeviceRecord> = records.into_iter().collect();
        while !pending.is_empty() {
            let before = pending.len();
            let mut still_pending = Vec::new();
            for record in pending {
                match self.accept(record.clone()) {
                    Ok(new) => changed |= new,
                    // The introducer may appear later in the batch.
                    Err(SyncError::UnknownDevice(id))
                        if id == record.introduced_by && !record.is_self_introduced() =>
                    {
                        still_pending.push(record);
                    }
                    Err(error) => return Err(error),
                }
            }
            if still_pending.len() == before {
                return Err(SyncError::UnknownDevice(still_pending[0].introduced_by));
            }
            pending = still_pending;
        }
        for revocation in revocations {
            changed |= self.accept_revocation(revocation)?;
        }
        Ok(changed)
    }

    /// The record of a device, revoked or not.
    pub fn get(&self, device: &DeviceId) -> Option<&DeviceRecord> {
        self.devices.get(device)
    }

    /// Whether a device has been revoked.
    pub fn is_revoked(&self, device: &DeviceId) -> bool {
        self.revocations.contains_key(device)
    }

    /// Whether a device is a member in good standing: known and not revoked.
    pub fn is_active(&self, device: &DeviceId) -> bool {
        self.devices.contains_key(device) && !self.is_revoked(device)
    }

    /// The key that verifies what `device` signed. Revoked devices keep their
    /// key: the ops they authored before remain part of the history.
    pub fn sign_pk(&self, device: &DeviceId) -> Result<&SignPublicKey, SyncError> {
        self.get(device)
            .map(|record| &record.sign_pk)
            .ok_or(SyncError::UnknownDevice(*device))
    }

    /// The active device that owns a Noise channel key, if any.
    pub fn active_by_noise_pk(&self, noise_pk: &ChannelPublicKey) -> Option<&DeviceRecord> {
        self.devices
            .values()
            .find(|record| record.noise_pk == *noise_pk && !self.is_revoked(&record.device_id))
    }

    /// All records, in device order.
    pub fn records(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.devices.values()
    }

    /// All revocations, in device order.
    pub fn revocations(&self) -> impl Iterator<Item = &Revocation> {
        self.revocations.values()
    }

    /// The devices that are members in good standing.
    pub fn active(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.devices
            .values()
            .filter(|record| !self.is_revoked(&record.device_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: VaultId = VaultId::from_bytes([1; 16]);

    struct Device {
        id: DeviceId,
        key: DeviceSigningKey,
        noise_pk: ChannelPublicKey,
    }

    fn device(n: u8) -> Device {
        Device {
            id: DeviceId::from_bytes([n; 16]),
            key: DeviceSigningKey::generate().unwrap(),
            noise_pk: [n; 32],
        }
    }

    fn root(d: &Device) -> DeviceRecord {
        DeviceRecord::root(&VAULT, d.id, &d.key, d.noise_pk, "root").unwrap()
    }

    fn introduced(by: &Device, d: &Device, name: &str) -> DeviceRecord {
        DeviceRecord::introduce(
            &VAULT,
            by.id,
            &by.key,
            d.id,
            d.key.public_key(),
            d.noise_pk,
            name,
        )
        .unwrap()
    }

    #[test]
    fn a_new_vault_has_exactly_its_root() {
        let a = device(1);
        let registry = Registry::with_root(VAULT, root(&a)).unwrap();
        assert!(registry.is_active(&a.id));
        assert_eq!(registry.records().count(), 1);
        assert_eq!(registry.sign_pk(&a.id).unwrap(), &a.key.public_key());
        assert_eq!(
            registry.active_by_noise_pk(&a.noise_pk).unwrap().device_id,
            a.id
        );
        assert!(registry.active_by_noise_pk(&[0xEE; 32]).is_none());

        // A non-root record cannot found a registry.
        let b = device(2);
        assert!(Registry::with_root(VAULT, introduced(&a, &b, "b")).is_err());
    }

    #[test]
    fn devices_join_through_an_introducer_chain() {
        let (a, b, c) = (device(1), device(2), device(3));
        let mut registry = Registry::with_root(VAULT, root(&a)).unwrap();
        assert!(registry.accept(introduced(&a, &b, "phone")).unwrap());
        assert!(registry.accept(introduced(&b, &c, "tablet")).unwrap());
        // Receiving the same record again changes nothing.
        assert!(!registry.accept(introduced(&a, &b, "phone")).unwrap());
        assert_eq!(registry.active().count(), 3);
        assert_eq!(registry.get(&c.id).unwrap().name, "tablet");
    }

    #[test]
    fn strangers_and_forgeries_are_refused() {
        let (a, b, stranger) = (device(1), device(2), device(9));
        let mut registry = Registry::with_root(VAULT, root(&a)).unwrap();

        // Introduced by a device the registry does not know.
        assert_eq!(
            registry.accept(introduced(&stranger, &b, "b")),
            Err(SyncError::UnknownDevice(stranger.id))
        );
        // A stranger declaring itself a root.
        assert_eq!(
            registry.accept(root(&stranger)),
            Err(SyncError::UnknownDevice(stranger.id))
        );
        // Claims to be introduced by A, but signed by someone else.
        let mut forged = introduced(&stranger, &b, "b");
        forged.introduced_by = a.id;
        assert_eq!(registry.accept(forged), Err(SyncError::BadSignature));
        // A valid record with any field changed afterwards.
        let genuine = introduced(&a, &b, "b");
        for change in [
            (|r: &mut DeviceRecord| r.noise_pk = [0xEE; 32]) as fn(&mut DeviceRecord),
            |r| r.name = "c".into(),
            |r| r.sign_pk = SignPublicKey::from_bytes([7; 32]),
            |r| r.device_id = DeviceId::from_bytes([8; 16]),
        ] {
            let mut tampered = genuine.clone();
            change(&mut tampered);
            assert_eq!(registry.accept(tampered), Err(SyncError::BadSignature));
        }
        // A record made for another vault.
        let other_vault = VaultId::from_bytes([2; 16]);
        let foreign = DeviceRecord::introduce(
            &other_vault,
            a.id,
            &a.key,
            b.id,
            b.key.public_key(),
            b.noise_pk,
            "b",
        )
        .unwrap();
        assert_eq!(registry.accept(foreign), Err(SyncError::BadSignature));
        assert_eq!(registry.records().count(), 1);
    }

    #[test]
    fn a_device_identifier_cannot_be_reassigned() {
        let (a, b) = (device(1), device(2));
        let mut registry = Registry::with_root(VAULT, root(&a)).unwrap();
        registry.accept(introduced(&a, &b, "phone")).unwrap();

        let impostor = Device {
            id: b.id,
            ..device(7)
        };
        assert_eq!(
            registry.accept(introduced(&a, &impostor, "phone")),
            Err(SyncError::ConflictingDevice(b.id))
        );
        assert_eq!(registry.sign_pk(&b.id).unwrap(), &b.key.public_key());
    }

    #[test]
    fn names_are_bounded_and_printable() {
        let (a, b) = (device(1), device(2));
        let make = |name: &str| {
            DeviceRecord::introduce(
                &VAULT,
                a.id,
                &a.key,
                b.id,
                b.key.public_key(),
                b.noise_pk,
                name,
            )
        };
        assert!(make(&"x".repeat(64)).is_ok());
        assert!(make("書斎のPC").is_ok());
        assert!(make("").is_ok());
        assert!(make(&"x".repeat(65)).is_err());
        assert!(make("bad\nname").is_err());
        assert!(make("bad\u{0}name").is_err());

        // The limits also apply to records received from others.
        let mut record = make("ok").unwrap();
        record.name = "x".repeat(300);
        assert!(matches!(
            record.verify(&VAULT, &a.key.public_key()),
            Err(SyncError::MalformedDevice(_))
        ));
    }

    #[test]
    fn revocation_is_permanent_and_keeps_the_history_verifiable() {
        let (a, b, c) = (device(1), device(2), device(3));
        let mut registry = Registry::with_root(VAULT, root(&a)).unwrap();
        registry.accept(introduced(&a, &b, "phone")).unwrap();
        registry.accept(introduced(&b, &c, "tablet")).unwrap();

        let revocation = Revocation::sign(&VAULT, b.id, a.id, &a.key);
        assert!(registry.accept_revocation(revocation.clone()).unwrap());
        assert!(!registry.accept_revocation(revocation).unwrap());
        // A second revocation by someone else is ignored, not an error.
        assert!(
            !registry
                .accept_revocation(Revocation::sign(&VAULT, b.id, c.id, &c.key))
                .unwrap()
        );

        assert!(registry.is_revoked(&b.id));
        assert!(!registry.is_active(&b.id));
        assert!(registry.active_by_noise_pk(&b.noise_pk).is_none());
        // Its signing key stays available: old ops must still verify.
        assert_eq!(registry.sign_pk(&b.id).unwrap(), &b.key.public_key());
        // The device it introduced remains a member.
        assert!(registry.is_active(&c.id));
        assert_eq!(registry.active().count(), 2);
        // The same record arriving again is still recognised.
        assert!(!registry.accept(introduced(&a, &b, "phone")).unwrap());
    }

    #[test]
    fn forged_revocations_are_refused() {
        let (a, b, stranger) = (device(1), device(2), device(9));
        let mut registry = Registry::with_root(VAULT, root(&a)).unwrap();
        registry.accept(introduced(&a, &b, "phone")).unwrap();

        assert_eq!(
            registry.accept_revocation(Revocation::sign(&VAULT, b.id, stranger.id, &stranger.key)),
            Err(SyncError::UnknownDevice(stranger.id))
        );
        // Claims to be from A but signed with another key.
        assert_eq!(
            registry.accept_revocation(Revocation::sign(&VAULT, b.id, a.id, &stranger.key)),
            Err(SyncError::BadSignature)
        );
        assert_eq!(
            registry.accept_revocation(Revocation::sign(&VAULT, stranger.id, a.id, &a.key)),
            Err(SyncError::UnknownDevice(stranger.id))
        );
        assert!(registry.is_active(&b.id));
    }

    #[test]
    fn batches_are_accepted_in_any_order() {
        let (a, b, c, d) = (device(1), device(2), device(3), device(4));
        let records = vec![
            introduced(&c, &d, "d"),
            introduced(&b, &c, "c"),
            introduced(&a, &b, "b"),
        ];
        let revocations = vec![Revocation::sign(&VAULT, b.id, d.id, &d.key)];

        let mut registry = Registry::with_root(VAULT, root(&a)).unwrap();
        assert!(
            registry
                .merge(records.clone(), revocations.clone())
                .unwrap()
        );
        assert_eq!(registry.records().count(), 4);
        assert!(registry.is_revoked(&b.id));
        // Merging the same batch again is a no-op.
        assert!(
            !registry
                .merge(records.clone(), revocations.clone())
                .unwrap()
        );

        // A batch whose chain does not reach a known device is refused.
        let mut fresh = Registry::with_root(VAULT, root(&a)).unwrap();
        assert_eq!(
            fresh.merge(vec![introduced(&c, &d, "d")], vec![]),
            Err(SyncError::UnknownDevice(c.id))
        );

        // Two registries that saw the same records agree, whatever the order.
        let mut other = Registry::with_root(VAULT, root(&a)).unwrap();
        let mut reversed = records;
        reversed.reverse();
        other.merge(reversed, revocations).unwrap();
        assert_eq!(other, registry);
    }

    #[test]
    fn a_trusted_source_may_supply_the_roots() {
        let (a, b) = (device(1), device(2));
        let mut source = Registry::with_root(VAULT, root(&a)).unwrap();
        source.accept(introduced(&a, &b, "phone")).unwrap();
        source
            .accept_revocation(Revocation::sign(&VAULT, a.id, b.id, &b.key))
            .unwrap();

        // As loaded from disk or received in a pairing grant, in any order.
        let mut records: Vec<_> = source.records().cloned().collect();
        records.reverse();
        let rebuilt =
            Registry::from_trusted(VAULT, records, source.revocations().cloned()).unwrap();
        assert_eq!(rebuilt, source);
        // A member introduced by a since-revoked device is still a member.
        assert!(rebuilt.is_active(&b.id));

        // Even a trusted source cannot supply records that do not verify.
        let mut bad = root(&a);
        bad.name = "renamed".into();
        assert!(Registry::from_trusted(VAULT, vec![bad], vec![]).is_err());
    }
}
