//! Ops: the immutable, signed versions of items that devices exchange
//! (`docs/spec/sync.md` §2).

use sha2::{Digest, Sha256};
use zp_crypto::{
    DeviceId, DeviceSigningKey, DomainId, ItemId, SignPublicKey, SignatureBytes, VaultId,
};

use crate::SyncError;
use crate::hlc::MAX_STAMP;

const LABEL_OP: &[u8] = b"zeropass/v1/op\0";

/// The encrypted part of a live item version (`docs/spec/crypto.md` §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The item key, wrapped under the domain's vault key.
    pub wrapped_dek: Vec<u8>,
    /// The item content, sealed under the item key.
    pub ciphertext: Vec<u8>,
}

/// The position of a version in the total order that decides which version of an
/// item is current: by clock stamp, then by authoring device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stamp {
    /// The hybrid logical clock stamp.
    pub hlc: u64,
    /// The authoring device, breaking ties between equal clock stamps.
    pub device_id: DeviceId,
}

/// Everything an op says, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpBody {
    /// The device that authored the op.
    pub device_id: DeviceId,
    /// The author's sequence number, starting at 1 without gaps.
    pub seq: u64,
    /// The item this is a version of.
    pub item_id: ItemId,
    /// The key domain of the item.
    pub domain: DomainId,
    /// The clock stamp of the version.
    pub hlc: u64,
    /// The generation of the vault key that wraps the item key.
    pub key_epoch: u32,
    /// The encrypted content, or `None` for a tombstone (a deletion).
    pub payload: Option<Payload>,
}

impl OpBody {
    /// Where this version stands in the merge order.
    pub fn stamp(&self) -> Stamp {
        Stamp {
            hlc: self.hlc,
            device_id: self.device_id,
        }
    }

    /// Checks the rules every op must satisfy on its own.
    pub fn check_shape(&self) -> Result<(), SyncError> {
        if self.seq == 0 {
            return Err(SyncError::MalformedOp("sequence numbers start at 1"));
        }
        if self.hlc > MAX_STAMP {
            return Err(SyncError::MalformedOp("clock stamp out of range"));
        }
        if self.key_epoch == 0 {
            return Err(SyncError::MalformedOp("key epochs start at 1"));
        }
        if let Some(payload) = &self.payload
            && (payload.wrapped_dek.is_empty() || payload.ciphertext.is_empty())
        {
            return Err(SyncError::MalformedOp(
                "a live version needs a key and a ciphertext",
            ));
        }
        Ok(())
    }

    /// The bytes that are signed (`sync.md` §2.2). Variable-length parts enter as
    /// SHA-256 digests, so every field has a fixed position.
    pub fn signing_message(&self, vault_id: &VaultId) -> Vec<u8> {
        let (wrapped_dek, ciphertext): (&[u8], &[u8]) = match &self.payload {
            Some(payload) => (&payload.wrapped_dek, &payload.ciphertext),
            None => (&[], &[]),
        };
        let mut message =
            Vec::with_capacity(LABEL_OP.len() + 16 + 16 + 8 + 16 + 1 + 8 + 4 + 1 + 64);
        message.extend_from_slice(LABEL_OP);
        message.extend_from_slice(vault_id.as_bytes());
        message.extend_from_slice(self.device_id.as_bytes());
        message.extend_from_slice(&self.seq.to_be_bytes());
        message.extend_from_slice(self.item_id.as_bytes());
        message.push(self.domain.as_u8());
        message.extend_from_slice(&self.hlc.to_be_bytes());
        message.extend_from_slice(&self.key_epoch.to_be_bytes());
        message.push(u8::from(self.payload.is_none()));
        message.extend_from_slice(&Sha256::digest(wrapped_dek));
        message.extend_from_slice(&Sha256::digest(ciphertext));
        message
    }

    /// Signs the op with its author's key.
    pub fn sign(self, vault_id: &VaultId, key: &DeviceSigningKey) -> Op {
        let signature = key.sign(&self.signing_message(vault_id));
        Op {
            body: self,
            signature,
        }
    }
}

/// A signed op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    /// What the op says.
    pub body: OpBody,
    /// The author's signature over [`OpBody::signing_message`].
    pub signature: SignatureBytes,
}

impl Op {
    /// Checks the op's shape and its signature against the author's public key.
    ///
    /// This needs no vault key: ops can be verified while the vault is locked.
    pub fn verify(&self, vault_id: &VaultId, author: &SignPublicKey) -> Result<(), SyncError> {
        self.body.check_shape()?;
        author
            .verify(&self.body.signing_message(vault_id), &self.signature)
            .map_err(|_| SyncError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: VaultId = VaultId::from_bytes([1; 16]);

    fn body() -> OpBody {
        OpBody {
            device_id: DeviceId::from_bytes([2; 16]),
            seq: 7,
            item_id: ItemId::from_bytes([3; 16]),
            domain: DomainId::Totp,
            hlc: 0x0102_0304_0506_0708,
            key_epoch: 1,
            payload: Some(Payload {
                wrapped_dek: vec![0xAA; 73],
                ciphertext: vec![0xBB; 120],
            }),
        }
    }

    #[test]
    fn signing_message_layout_matches_the_spec() {
        let message = body().signing_message(&VAULT);
        let mut expected = b"zeropass/v1/op\0".to_vec();
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&7u64.to_be_bytes());
        expected.extend_from_slice(&[3; 16]);
        expected.push(0x02);
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.push(0x00);
        expected.extend_from_slice(&Sha256::digest([0xAA; 73]));
        expected.extend_from_slice(&Sha256::digest([0xBB; 120]));
        assert_eq!(message, expected);

        let tombstone = OpBody {
            payload: None,
            ..body()
        }
        .signing_message(&VAULT);
        assert_eq!(tombstone[expected.len() - 65], 0x01);
        assert_eq!(
            tombstone[expected.len() - 64..expected.len() - 32],
            Sha256::digest([])[..]
        );
    }

    #[test]
    fn a_signed_op_verifies_and_every_field_is_covered() {
        let key = DeviceSigningKey::generate().unwrap();
        let op = body().sign(&VAULT, &key);
        op.verify(&VAULT, &key.public_key()).unwrap();

        let changed: [fn(&mut OpBody); 9] = [
            |b| b.device_id = DeviceId::from_bytes([9; 16]),
            |b| b.seq += 1,
            |b| b.item_id = ItemId::from_bytes([9; 16]),
            |b| b.domain = DomainId::Password,
            |b| b.hlc += 1,
            |b| b.key_epoch += 1,
            |b| b.payload = None,
            |b| b.payload.as_mut().unwrap().wrapped_dek[0] ^= 1,
            |b| b.payload.as_mut().unwrap().ciphertext[0] ^= 1,
        ];
        for change in changed {
            let mut tampered = op.clone();
            change(&mut tampered.body);
            assert_eq!(
                tampered.verify(&VAULT, &key.public_key()).unwrap_err(),
                SyncError::BadSignature
            );
        }

        let other_vault = VaultId::from_bytes([9; 16]);
        assert_eq!(
            op.verify(&other_vault, &key.public_key()),
            Err(SyncError::BadSignature)
        );
        let other_key = DeviceSigningKey::generate().unwrap();
        assert_eq!(
            op.verify(&VAULT, &other_key.public_key()),
            Err(SyncError::BadSignature)
        );
    }

    #[test]
    fn tombstones_are_signed_too() {
        let key = DeviceSigningKey::generate().unwrap();
        let tombstone = OpBody {
            payload: None,
            ..body()
        }
        .sign(&VAULT, &key);
        tombstone.verify(&VAULT, &key.public_key()).unwrap();
        // A tombstone cannot be forged from a live op's signature, or vice versa.
        let forged = Op {
            body: OpBody {
                payload: None,
                ..body()
            },
            ..body().sign(&VAULT, &key)
        };
        assert_eq!(
            forged.verify(&VAULT, &key.public_key()),
            Err(SyncError::BadSignature)
        );
    }

    #[test]
    fn swapping_key_and_ciphertext_changes_the_message() {
        let a = body();
        let mut b = body();
        let payload = b.payload.as_mut().unwrap();
        std::mem::swap(&mut payload.wrapped_dek, &mut payload.ciphertext);
        assert_ne!(a.signing_message(&VAULT), b.signing_message(&VAULT));
    }

    #[test]
    fn malformed_ops_are_rejected_before_the_signature_is_checked() {
        let key = DeviceSigningKey::generate().unwrap();
        type Change = fn(&mut OpBody);
        let cases: [(Change, &str); 5] = [
            (|b| b.seq = 0, "sequence numbers start at 1"),
            (|b| b.hlc = MAX_STAMP + 1, "clock stamp out of range"),
            (|b| b.key_epoch = 0, "key epochs start at 1"),
            (
                |b| b.payload.as_mut().unwrap().ciphertext.clear(),
                "a live version needs a key and a ciphertext",
            ),
            (
                |b| b.payload.as_mut().unwrap().wrapped_dek.clear(),
                "a live version needs a key and a ciphertext",
            ),
        ];
        for (change, reason) in cases {
            let mut malformed = body();
            change(&mut malformed);
            // Even a correctly signed malformed op is refused.
            let op = malformed.sign(&VAULT, &key);
            assert_eq!(
                op.verify(&VAULT, &key.public_key()),
                Err(SyncError::MalformedOp(reason))
            );
        }
    }

    #[test]
    fn stamps_order_by_clock_then_device() {
        let stamp = |hlc, device: u8| Stamp {
            hlc,
            device_id: DeviceId::from_bytes([device; 16]),
        };
        assert!(stamp(1, 9) < stamp(2, 1));
        assert!(stamp(2, 1) < stamp(2, 2));
        assert_eq!(stamp(2, 2), stamp(2, 2));
        assert_eq!(body().stamp(), stamp(0x0102_0304_0506_0708, 2));
    }
}
