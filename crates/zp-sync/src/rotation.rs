//! Vault key rotation as the sync layer sees it (`docs/spec/sync.md` §8).
//!
//! When a device is revoked, a remaining device replaces the vault key of each
//! domain and tells the others with a [`KeyUpdate`]: the new key, wrapped under
//! the key it replaces, signed by the device that rotated. This crate carries
//! updates between devices without being able to open them.

use sha2::{Digest, Sha256};
use zp_crypto::{DeviceId, DeviceSigningKey, DomainId, SignatureBytes, VaultId, WRAPPED_KEY_LEN};

use crate::{Registry, SyncError};

const LABEL_KEY_UPDATE: &[u8] = b"zeropass/v1/key-update\0";

/// The most key updates one sync message may carry.
pub const MAX_KEY_UPDATES: usize = 1024;

/// A new vault key for one domain, wrapped under the key of the generation
/// before it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyUpdate {
    /// The domain whose key was replaced.
    pub domain: DomainId,
    /// The generation of the new key (2 or more).
    pub epoch: u32,
    /// The device that rotated the key.
    pub device_id: DeviceId,
    /// The new key, sealed under a key of generation `epoch - 1`.
    pub wrapped_key: Vec<u8>,
    /// The rotating device's signature over the fields above.
    pub signature: SignatureBytes,
}

impl KeyUpdate {
    fn signing_message(&self, vault_id: &VaultId) -> Vec<u8> {
        let mut message = Vec::with_capacity(LABEL_KEY_UPDATE.len() + 16 + 1 + 4 + 16 + 32);
        message.extend_from_slice(LABEL_KEY_UPDATE);
        message.extend_from_slice(vault_id.as_bytes());
        message.push(self.domain.as_u8());
        message.extend_from_slice(&self.epoch.to_be_bytes());
        message.extend_from_slice(self.device_id.as_bytes());
        message.extend_from_slice(&Sha256::digest(&self.wrapped_key));
        message
    }

    /// Signs an update on behalf of the device that rotated the key.
    pub fn sign(
        vault_id: &VaultId,
        domain: DomainId,
        epoch: u32,
        device_id: DeviceId,
        key: &DeviceSigningKey,
        wrapped_key: Vec<u8>,
    ) -> Self {
        let mut update = Self {
            domain,
            epoch,
            device_id,
            wrapped_key,
            signature: [0; 64],
        };
        update.signature = key.sign(&update.signing_message(vault_id));
        update
    }

    /// Checks the update's shape and its signature against the registry.
    ///
    /// An update signed by a device that has been revoked since is still valid:
    /// it may be the only way from an older key to the current one. What a
    /// revoked device rotated to is never used for writing (`sync.md` §8).
    pub fn verify(&self, vault_id: &VaultId, registry: &Registry) -> Result<(), SyncError> {
        if self.epoch < 2 {
            return Err(SyncError::MalformedKeyUpdate(
                "the first generation is never the result of a rotation",
            ));
        }
        if self.wrapped_key.len() != WRAPPED_KEY_LEN {
            return Err(SyncError::MalformedKeyUpdate(
                "wrong length of the wrapped key",
            ));
        }
        registry
            .sign_pk(&self.device_id)?
            .verify(&self.signing_message(vault_id), &self.signature)
            .map_err(|_| SyncError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceRecord;

    struct Device {
        id: DeviceId,
        key: DeviceSigningKey,
    }

    fn device(n: u8) -> Device {
        Device {
            id: DeviceId::from_bytes([n; 16]),
            key: DeviceSigningKey::generate().unwrap(),
        }
    }

    const VAULT: VaultId = VaultId::from_bytes([7; 16]);

    fn registry(root: &Device) -> Registry {
        let record = DeviceRecord::root(&VAULT, root.id, &root.key, [1; 32], "root").unwrap();
        Registry::with_root(VAULT, record).unwrap()
    }

    fn update(by: &Device) -> KeyUpdate {
        KeyUpdate::sign(
            &VAULT,
            DomainId::Totp,
            2,
            by.id,
            &by.key,
            vec![0xAB; WRAPPED_KEY_LEN],
        )
    }

    #[test]
    fn a_signed_update_verifies_and_every_field_is_covered() {
        let a = device(1);
        let registry = registry(&a);
        let good = update(&a);
        good.verify(&VAULT, &registry).unwrap();

        let changes: [fn(&mut KeyUpdate); 4] = [
            |u| u.domain = DomainId::Password,
            |u| u.epoch = 3,
            |u| u.wrapped_key[0] ^= 1,
            |u| u.signature[0] ^= 1,
        ];
        for change in changes {
            let mut forged = good.clone();
            change(&mut forged);
            assert_eq!(
                forged.verify(&VAULT, &registry),
                Err(SyncError::BadSignature)
            );
        }
        // Not valid for another vault.
        assert_eq!(
            good.verify(&VaultId::from_bytes([8; 16]), &registry),
            Err(SyncError::BadSignature)
        );
    }

    #[test]
    fn strangers_and_malformed_updates_are_refused() {
        let (a, stranger) = (device(1), device(2));
        let registry = registry(&a);
        assert_eq!(
            update(&stranger).verify(&VAULT, &registry),
            Err(SyncError::UnknownDevice(stranger.id))
        );

        let first = KeyUpdate::sign(
            &VAULT,
            DomainId::Password,
            1,
            a.id,
            &a.key,
            vec![0; WRAPPED_KEY_LEN],
        );
        assert!(matches!(
            first.verify(&VAULT, &registry),
            Err(SyncError::MalformedKeyUpdate(_))
        ));
        let short = KeyUpdate::sign(&VAULT, DomainId::Password, 2, a.id, &a.key, vec![0; 72]);
        assert!(matches!(
            short.verify(&VAULT, &registry),
            Err(SyncError::MalformedKeyUpdate(_))
        ));
    }

    #[test]
    fn an_update_by_a_device_revoked_later_stays_valid() {
        let (a, b) = (device(1), device(2));
        let mut registry = registry(&a);
        registry
            .accept(
                DeviceRecord::introduce(
                    &VAULT,
                    a.id,
                    &a.key,
                    b.id,
                    b.key.public_key(),
                    [2; 32],
                    "b",
                )
                .unwrap(),
            )
            .unwrap();
        let by_b = update(&b);
        registry
            .accept_revocation(crate::Revocation::sign(&VAULT, b.id, a.id, &a.key))
            .unwrap();
        by_b.verify(&VAULT, &registry).unwrap();
    }
}
