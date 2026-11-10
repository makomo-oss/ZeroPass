//! Fuzzes envelope parsing and opening.
//!
//! Arbitrary bytes must never panic and must never authenticate; and whatever is
//! sealed must open again to the same bytes.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use zp_crypto::{
    DeviceId, ItemContext, ItemId, ItemKey, Password, Totp, VaultId, VaultKey,
};

struct Keys {
    item: ItemKey<Password>,
    vault: VaultKey<Totp>,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| Keys {
    item: ItemKey::generate().expect("OS randomness"),
    vault: VaultKey::generate().expect("OS randomness"),
});

const CTX: ItemContext = ItemContext {
    vault_id: VaultId::from_bytes([1; 16]),
    item_id: ItemId::from_bytes([2; 16]),
    hlc: 3,
    device_id: DeviceId::from_bytes([4; 16]),
};

fuzz_target!(|data: &[u8]| {
    // 1. Attacker-controlled bytes in place of an envelope.
    assert!(KEYS.item.open_item(&CTX, data).is_err());
    assert!(KEYS.vault.unwrap_item_key(&CTX, data).is_err());

    // 2. Attacker-controlled plaintext round-trips.
    let sealed = KEYS.item.seal_item(&CTX, data).expect("sealing cannot fail");
    let opened = KEYS.item.open_item(&CTX, &sealed).expect("own envelope opens");
    assert_eq!(opened.as_slice(), data);

    // 3. A valid envelope with attacker-chosen corruption never opens.
    if let Some((&selector, _)) = data.split_first() {
        let mut corrupted = sealed.clone();
        let index = usize::from(selector) % corrupted.len();
        corrupted[index] ^= 0x01;
        assert!(KEYS.item.open_item(&CTX, &corrupted).is_err());
        corrupted.truncate(index);
        assert!(KEYS.item.open_item(&CTX, &corrupted).is_err());
    }
});
