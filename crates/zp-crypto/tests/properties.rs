//! Property tests of the envelope and key wrapping, through the public API.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use proptest::collection::vec;
use proptest::prelude::*;
use subtle::ConstantTimeEq;
use zp_crypto::{
    DeviceId, ENVELOPE_OVERHEAD, ItemContext, ItemId, ItemKey, Passkey, Password, Totp, VaultId,
    VaultKey, WRAPPED_KEY_LEN,
};

fn context() -> impl Strategy<Value = ItemContext> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<u64>(),
        any::<[u8; 16]>(),
    )
        .prop_map(|(vault, item, hlc, device)| ItemContext {
            vault_id: VaultId::from_bytes(vault),
            item_id: ItemId::from_bytes(item),
            hlc,
            device_id: DeviceId::from_bytes(device),
        })
}

proptest! {
    #[test]
    fn sealing_then_opening_returns_the_plaintext(
        plaintext in vec(any::<u8>(), 0..4096),
        ctx in context(),
    ) {
        let key = ItemKey::<Password>::generate().unwrap();
        let sealed = key.seal_item(&ctx, &plaintext).unwrap();
        prop_assert_eq!(sealed.len(), plaintext.len() + ENVELOPE_OVERHEAD);
        let opened = key.open_item(&ctx, &sealed).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn any_bit_flip_is_rejected(
        plaintext in vec(any::<u8>(), 0..512),
        ctx in context(),
        position in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let key = ItemKey::<Totp>::generate().unwrap();
        let mut sealed = key.seal_item(&ctx, &plaintext).unwrap();
        let index = position.index(sealed.len());
        sealed[index] ^= 1 << bit;
        prop_assert!(key.open_item(&ctx, &sealed).is_err());
    }

    #[test]
    fn truncation_and_extension_are_rejected(
        plaintext in vec(any::<u8>(), 0..512),
        ctx in context(),
        cut in any::<prop::sample::Index>(),
        extra in vec(any::<u8>(), 1..32),
    ) {
        let key = ItemKey::<Password>::generate().unwrap();
        let sealed = key.seal_item(&ctx, &plaintext).unwrap();
        let truncated = &sealed[..cut.index(sealed.len())];
        prop_assert!(key.open_item(&ctx, truncated).is_err());
        let mut extended = sealed.clone();
        extended.extend_from_slice(&extra);
        prop_assert!(key.open_item(&ctx, &extended).is_err());
    }

    #[test]
    fn a_different_context_or_key_is_rejected(
        plaintext in vec(any::<u8>(), 0..256),
        ctx in context(),
        other in context(),
    ) {
        prop_assume!(ctx != other);
        let key = ItemKey::<Password>::generate().unwrap();
        let sealed = key.seal_item(&ctx, &plaintext).unwrap();
        prop_assert!(key.open_item(&other, &sealed).is_err());
        let other_key = ItemKey::<Password>::generate().unwrap();
        prop_assert!(other_key.open_item(&ctx, &sealed).is_err());
    }

    #[test]
    fn arbitrary_bytes_never_open_and_never_panic(
        data in vec(any::<u8>(), 0..1024),
        ctx in context(),
    ) {
        let key = ItemKey::<Passkey>::generate().unwrap();
        prop_assert!(key.open_item(&ctx, &data).is_err());
        let vault_key = VaultKey::<Passkey>::generate().unwrap();
        prop_assert!(vault_key.unwrap_item_key(&ctx, &data).is_err());
    }

    #[test]
    fn wrapped_item_keys_round_trip(ctx in context()) {
        let vault_key = VaultKey::<Totp>::generate().unwrap();
        let item_key = ItemKey::<Totp>::generate().unwrap();
        let wrapped = vault_key.wrap_item_key(&item_key, &ctx).unwrap();
        prop_assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
        let unwrapped = vault_key.unwrap_item_key(&ctx, &wrapped).unwrap();
        prop_assert!(bool::from(item_key.ct_eq(&unwrapped)));
    }
}
