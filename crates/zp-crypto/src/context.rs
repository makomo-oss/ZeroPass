//! Identifiers and the associated data (AAD) that binds ciphertexts to their context.
//!
//! Layouts are defined in `docs/spec/crypto.md` §4.1:
//! `AAD = label ‖ 0x00 ‖ fields`, with fixed-length fields per label.

use core::fmt;

use crate::{CryptoError, DomainId, rng};

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; Self::LEN]);

        impl $name {
            /// Length of the identifier in bytes.
            pub const LEN: usize = 16;

            /// Generates a fresh random identifier.
            pub fn generate() -> Result<Self, CryptoError> {
                rng::array().map(Self)
            }

            /// Wraps existing identifier bytes.
            pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
                Self(bytes)
            }

            /// Parses an identifier from a slice of exactly [`Self::LEN`] bytes.
            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                bytes.try_into().ok().map(Self)
            }

            /// The identifier bytes.
            pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }
    };
}

id_type!(
    /// Identifies a vault. Random, assigned when the vault is created.
    VaultId
);
id_type!(
    /// Identifies a device. Random, assigned once per device.
    DeviceId
);
id_type!(
    /// Identifies an item. Random, assigned when the item is created.
    ItemId
);

pub(crate) const LABEL_ITEM: &str = "zeropass/v1/item";

fn aad_with_capacity(label: &str, fields_len: usize) -> Vec<u8> {
    debug_assert!(!label.as_bytes().contains(&0));
    let mut aad = Vec::with_capacity(label.len() + 1 + fields_len);
    aad.extend_from_slice(label.as_bytes());
    aad.push(0x00);
    aad
}

/// The context one version of one item is bound to.
///
/// A ciphertext sealed under one context cannot be opened under another, so it
/// cannot be transplanted to a different vault, domain, item or version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemContext {
    /// The vault the item lives in.
    pub vault_id: VaultId,
    /// The item.
    pub item_id: ItemId,
    /// Hybrid logical clock stamp of this version.
    pub hlc: u64,
    /// The device that wrote this version.
    pub device_id: DeviceId,
}

impl ItemContext {
    /// `label ‖ 0x00 ‖ vault_id ‖ domain ‖ item_id ‖ hlc ‖ device_id`
    pub(crate) fn aad(&self, label: &str, domain: DomainId) -> Vec<u8> {
        let mut aad = aad_with_capacity(label, 16 + 1 + 16 + 8 + 16);
        aad.extend_from_slice(self.vault_id.as_bytes());
        aad.push(domain.as_u8());
        aad.extend_from_slice(self.item_id.as_bytes());
        aad.extend_from_slice(&self.hlc.to_be_bytes());
        aad.extend_from_slice(self.device_id.as_bytes());
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_print_as_hex() {
        let id = ItemId::from_bytes([0xAB; 16]);
        assert_eq!(id.to_string(), "ab".repeat(16));
        assert_eq!(format!("{id:?}"), format!("ItemId({})", "ab".repeat(16)));
        assert_eq!(ItemId::from_slice(id.as_bytes()), Some(id));
        assert_eq!(ItemId::from_slice(&[0u8; 15]), None);
        assert_ne!(ItemId::generate().unwrap(), ItemId::generate().unwrap());
    }

    #[test]
    fn item_aad_layout_matches_the_spec() {
        let ctx = ItemContext {
            vault_id: VaultId::from_bytes([1; 16]),
            item_id: ItemId::from_bytes([2; 16]),
            hlc: 0x0102_0304_0506_0708,
            device_id: DeviceId::from_bytes([3; 16]),
        };
        let aad = ctx.aad(LABEL_ITEM, DomainId::Totp);

        let mut expected = b"zeropass/v1/item\0".to_vec();
        expected.extend_from_slice(&[1; 16]);
        expected.push(0x02);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        expected.extend_from_slice(&[3; 16]);
        assert_eq!(aad, expected);
    }
}
