//! Anonymous discovery tags.
//!
//! A device that wants to be found announces a short tag instead of its name or
//! identifier. The tag is derived from values only the devices of the same
//! vault know, and changes every [`SLOT_SECS`]:
//!
//! ```text
//! tag = SHA-256("zeropass/v1/discovery" ‖ 0x00 ‖ vault_id ‖ noise_pk ‖ slot(8))[..8]
//! slot = unix_seconds / 900
//! ```
//!
//! Neither the vault identifier nor a device's channel public key is ever sent
//! in the clear (the sync handshake keeps both hidden), so an observer on the
//! network or in radio range cannot compute tags, cannot tell which vault a tag
//! belongs to, and cannot link the tags of two slots to the same device. A
//! device of the same vault recomputes the tags of the devices in its registry
//! and recognises its peers.

use sha2::{Digest, Sha256};
use zp_crypto::VaultId;
use zp_sync::{ChannelPublicKey, DeviceRecord, Registry};

/// Length of a discovery tag in bytes.
pub const TAG_LEN: usize = 8;
/// How long a tag stays the same: 15 minutes.
pub const SLOT_SECS: u64 = 900;

const LABEL: &[u8] = b"zeropass/v1/discovery\0";

/// A discovery tag.
pub type Tag = [u8; TAG_LEN];

/// The time slot containing `unix_secs`.
pub const fn slot_of(unix_secs: u64) -> u64 {
    unix_secs / SLOT_SECS
}

/// The tag of the device owning `noise_pk` in `vault_id` during `slot`.
pub fn tag_for(vault_id: &VaultId, noise_pk: &ChannelPublicKey, slot: u64) -> Tag {
    let digest = Sha256::new()
        .chain_update(LABEL)
        .chain_update(vault_id.as_bytes())
        .chain_update(noise_pk)
        .chain_update(slot.to_be_bytes())
        .finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&digest[..TAG_LEN]);
    tag
}

/// Finds the active device of `registry` that announces `tag` around
/// `unix_secs`. The neighbouring slots are accepted too, so that devices whose
/// clocks disagree by a few minutes, or that announce across a slot boundary,
/// still find each other.
pub fn identify<'a>(registry: &'a Registry, tag: &Tag, unix_secs: u64) -> Option<&'a DeviceRecord> {
    let slot = slot_of(unix_secs);
    let slots = [slot, slot.saturating_sub(1), slot.saturating_add(1)];
    let vault_id = registry.vault_id();
    registry.active().find(|record| {
        slots
            .iter()
            .any(|&slot| tag_for(&vault_id, &record.noise_pk, slot) == *tag)
    })
}

#[cfg(test)]
mod tests {
    use zp_sync::{MemoryLog, OpLog};

    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn tags_follow_the_formula_and_rotate() {
        let vault = VaultId::from_bytes([1; 16]);
        let key = [2u8; 32];
        let slot = slot_of(NOW);
        assert_eq!(slot, NOW / 900);

        let mut input = b"zeropass/v1/discovery\0".to_vec();
        input.extend_from_slice(&[1; 16]);
        input.extend_from_slice(&[2; 32]);
        input.extend_from_slice(&slot.to_be_bytes());
        assert_eq!(tag_for(&vault, &key, slot)[..], Sha256::digest(&input)[..8]);

        // A different slot, device or vault gives an unrelated tag.
        let tag = tag_for(&vault, &key, slot);
        assert_ne!(tag, tag_for(&vault, &key, slot + 1));
        assert_ne!(tag, tag_for(&vault, &[3; 32], slot));
        assert_ne!(tag, tag_for(&VaultId::from_bytes([9; 16]), &key, slot));
        // Stable within a slot.
        assert_eq!(slot_of(slot * 900), slot_of(slot * 900 + 899));
    }

    #[test]
    fn members_recognise_each_other_and_nobody_else() {
        let mut a = MemoryLog::new_vault("a", [1; 32]).unwrap();
        let b = MemoryLog::join(&mut a, "b", [2; 32]).unwrap();
        let registry = a.registry().unwrap();
        let vault = a.vault_id();

        let tag_b = tag_for(&vault, &[2; 32], slot_of(NOW));
        assert_eq!(
            identify(&registry, &tag_b, NOW).unwrap().device_id,
            b.device_id()
        );
        // Also when the clocks are a slot apart, in either direction.
        assert!(identify(&registry, &tag_b, NOW + SLOT_SECS).is_some());
        assert!(identify(&registry, &tag_b, NOW - SLOT_SECS).is_some());
        // But not two slots later.
        assert!(identify(&registry, &tag_b, NOW + 2 * SLOT_SECS + 1).is_none());

        // A device of another vault, or an unknown key, is not recognised.
        let stranger = tag_for(&VaultId::from_bytes([9; 16]), &[2; 32], slot_of(NOW));
        assert!(identify(&registry, &stranger, NOW).is_none());
        assert!(identify(&registry, &tag_for(&vault, &[7; 32], slot_of(NOW)), NOW).is_none());

        // A revoked device is ignored.
        a.revoke(b.device_id()).unwrap();
        assert!(identify(&a.registry().unwrap(), &tag_b, NOW).is_none());
    }
}
