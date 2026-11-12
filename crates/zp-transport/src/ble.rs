//! Bluetooth LE: the platform-independent parts of `docs/spec/ble.md`.
//!
//! The GATT service has three characteristics: `Tag` (read) tells a central
//! whether the peripheral is one it wants to talk to, `Rx` (write) carries bytes
//! from the central, and `Tx` (notify) carries bytes to it. BLE pairing is not
//! used; the Noise channel on top provides all security.

use sha2::{Digest, Sha256};
use zp_pairing::noise::PSK_LEN;

use crate::discovery::{TAG_LEN, Tag};

/// UUID of the ZeroPass proximity sync service.
pub const SERVICE_UUID: u128 = 0x5a50c0de_0001_4b1d_9c5e_7a65726f7061;
/// UUID of the `Tag` characteristic (read).
pub const TAG_UUID: u128 = 0x5a50c0de_0002_4b1d_9c5e_7a65726f7061;
/// UUID of the `Rx` characteristic (write, central → peripheral).
pub const RX_UUID: u128 = 0x5a50c0de_0003_4b1d_9c5e_7a65726f7061;
/// UUID of the `Tx` characteristic (notify, peripheral → central).
pub const TX_UUID: u128 = 0x5a50c0de_0004_4b1d_9c5e_7a65726f7061;

/// Length of the value of the `Tag` characteristic.
pub const TAG_VALUE_LEN: usize = 2 * TAG_LEN;
/// The payload of a packet when the central did not negotiate a larger MTU.
pub const DEFAULT_PACKET_LEN: usize = 20;
/// A link without traffic is dropped after this long.
pub const IDLE_SECS: u64 = 10;

const LABEL_PAIRING: &[u8] = b"zeropass/v1/ble-pairing\0";

/// The tag a peripheral shows while it waits for a pairing with the one-time
/// secret `psk`: `SHA-256("zeropass/v1/ble-pairing" ‖ 0x00 ‖ psk)[..8]`.
///
/// A central that scanned the QR code computes the same value to pick the right
/// peripheral. The secret cannot be derived from the tag.
pub fn pairing_tag(psk: &[u8; PSK_LEN]) -> Tag {
    let digest = Sha256::new()
        .chain_update(LABEL_PAIRING)
        .chain_update(psk)
        .finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&digest[..TAG_LEN]);
    tag
}

/// The value of the `Tag` characteristic: `sync_tag ‖ pairing_tag`, with zeros
/// for a tag that is not being announced.
pub fn tag_value(sync: Option<Tag>, pairing: Option<Tag>) -> [u8; TAG_VALUE_LEN] {
    let mut value = [0u8; TAG_VALUE_LEN];
    value[..TAG_LEN].copy_from_slice(&sync.unwrap_or_default());
    value[TAG_LEN..].copy_from_slice(&pairing.unwrap_or_default());
    value
}

/// Splits the value of the `Tag` characteristic into `(sync_tag, pairing_tag)`.
/// All zeros means "not announced". Returns `None` for a value of the wrong
/// length.
pub fn parse_tag_value(value: &[u8]) -> Option<(Option<Tag>, Option<Tag>)> {
    let value: &[u8; TAG_VALUE_LEN] = value.try_into().ok()?;
    let tag = |bytes: &[u8]| -> Option<Tag> {
        let tag: Tag = bytes.try_into().ok()?;
        (tag != [0u8; TAG_LEN]).then_some(tag)
    };
    Some((tag(&value[..TAG_LEN]), tag(&value[TAG_LEN..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_share_a_base_and_differ_in_one_field() {
        let uuids = [SERVICE_UUID, TAG_UUID, RX_UUID, TX_UUID];
        for (index, uuid) in uuids.iter().enumerate() {
            // 5a50c0de-000N-4b1d-9c5e-7a65726f7061
            assert_eq!(uuid >> 96, 0x5a50_c0de);
            assert_eq!((uuid >> 80) & 0xffff, index as u128 + 1);
            assert_eq!(uuid & ((1u128 << 80) - 1), 0x4b1d_9c5e_7a65_726f_7061);
        }
    }

    #[test]
    fn pairing_tag_follows_the_formula_and_hides_the_secret() {
        let psk = [0x42; PSK_LEN];
        let mut input = b"zeropass/v1/ble-pairing\0".to_vec();
        input.extend_from_slice(&psk);
        assert_eq!(pairing_tag(&psk)[..], Sha256::digest(&input)[..8]);
        assert_ne!(pairing_tag(&psk), pairing_tag(&[0x43; PSK_LEN]));
        assert!(
            !psk.windows(TAG_LEN)
                .any(|window| window == pairing_tag(&psk))
        );
    }

    #[test]
    fn tag_values_round_trip() {
        let (sync, pairing) = ([1u8; TAG_LEN], [2u8; TAG_LEN]);
        let cases = [
            (Some(sync), Some(pairing)),
            (Some(sync), None),
            (None, Some(pairing)),
            (None, None),
        ];
        for (sync, pairing) in cases {
            let value = tag_value(sync, pairing);
            assert_eq!(value.len(), 16);
            assert_eq!(parse_tag_value(&value), Some((sync, pairing)));
        }
        assert_eq!(tag_value(Some(sync), None)[8..], [0u8; 8]);
        assert_eq!(parse_tag_value(&[0u8; 15]), None);
        assert_eq!(parse_tag_value(&[0u8; 17]), None);
        assert_eq!(parse_tag_value(&[]), None);
    }
}
