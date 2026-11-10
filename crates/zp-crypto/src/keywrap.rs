//! Wrapping keys with keys (`docs/spec/crypto.md` §3, §4.1, §8).
//!
//! * A vault key wraps the item keys of its own domain.
//! * A key-encryption key wraps the vault key of its own domain into a key slot.
//!
//! Both rules are carried by the types. In particular the master password yields a
//! [`PasswordKek`], which is fixed to the password domain, so it can wrap `VK-P`:
//!
//! ```
//! use zp_crypto::{KdfParams, Password, VaultId, VaultKey, derive_password_kek};
//!
//! # let params = KdfParams::new(64, 1, 1).unwrap();
//! let kek = derive_password_kek("a long master password", &[7; 16], &params).unwrap();
//! let vault_id = VaultId::generate().unwrap();
//!
//! let vk_p = VaultKey::<Password>::generate().unwrap();
//! let slot = vk_p.wrap(&kek, &vault_id).unwrap();
//! let _vk_p = VaultKey::<Password>::unwrap(&kek, &vault_id, &slot).unwrap();
//! ```
//!
//! but it can never wrap or unwrap the TOTP (or passkey) vault key:
//!
//! ```compile_fail,E0308
//! use zp_crypto::{KdfParams, Totp, VaultId, VaultKey, derive_password_kek};
//!
//! # let params = KdfParams::new(64, 1, 1).unwrap();
//! let kek = derive_password_kek("a long master password", &[7; 16], &params).unwrap();
//! let vault_id = VaultId::generate().unwrap();
//!
//! let vk_t = VaultKey::<Totp>::generate().unwrap();
//! let slot = vk_t.wrap(&kek, &vault_id).unwrap(); // error[E0308]: mismatched types
//! ```
//!
//! ```compile_fail,E0308
//! use zp_crypto::{KdfParams, Totp, VaultId, VaultKey, derive_password_kek};
//!
//! # let params = KdfParams::new(64, 1, 1).unwrap();
//! let kek = derive_password_kek("a long master password", &[7; 16], &params).unwrap();
//! let vault_id = VaultId::generate().unwrap();
//!
//! let stolen_slot = [0u8; 73];
//! let _ = VaultKey::<Totp>::unwrap(&kek, &vault_id, &stolen_slot); // error[E0308]
//! ```

use core::fmt;

use zeroize::Zeroize;

use crate::context::{ItemContext, LABEL_DEK_WRAP, vault_key_aad};
use crate::envelope::{ENVELOPE_OVERHEAD, open, seal};
use crate::kdf::hkdf_sha256;
use crate::mem::SecretBytes;
use crate::secret::{ItemKey, KEY_LEN, RecoveryKek, Role, SecretKey, VaultKey, Wrap};
use crate::{CryptoError, Domain, VaultId, rng};

/// Length of a wrapped 32-byte key: the key plus the envelope overhead.
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + ENVELOPE_OVERHEAD;

const INFO_KEK_RECOVERY: &[u8] = b"zeropass/v1/kek/recovery";

/// Opens an envelope that must contain exactly one key.
fn open_key<D: Domain, R: Role>(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    wrapped: &[u8],
) -> Result<SecretKey<D, R>, CryptoError> {
    let plain = open(key, aad, wrapped)?;
    let plain: &[u8; KEY_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::MalformedEnvelope)?;
    SecretKey::from_fn(|out| {
        out.copy_from_slice(plain);
        Ok(())
    })
}

impl<D: Domain> VaultKey<D> {
    /// Wraps this vault key into a key slot under a key-encryption key of the same
    /// domain. The slot is bound to `vault_id`, the domain and the slot kind.
    pub fn wrap<R: Wrap>(
        &self,
        kek: &SecretKey<D, R>,
        vault_id: &VaultId,
    ) -> Result<Vec<u8>, CryptoError> {
        seal(
            kek.expose(),
            &vault_key_aad(R::SLOT_LABEL, vault_id, D::ID),
            self.expose(),
        )
    }

    /// Recovers a vault key from a key slot.
    ///
    /// Fails with [`CryptoError::Decrypt`] unless the key-encryption key, vault,
    /// domain and slot kind all match those used to wrap it.
    pub fn unwrap<R: Wrap>(
        kek: &SecretKey<D, R>,
        vault_id: &VaultId,
        slot: &[u8],
    ) -> Result<Self, CryptoError> {
        open_key(
            kek.expose(),
            &vault_key_aad(R::SLOT_LABEL, vault_id, D::ID),
            slot,
        )
    }

    /// Wraps the key of one item version, binding it to that version's context.
    pub fn wrap_item_key(
        &self,
        item_key: &ItemKey<D>,
        ctx: &ItemContext,
    ) -> Result<Vec<u8>, CryptoError> {
        seal(
            self.expose(),
            &ctx.aad(LABEL_DEK_WRAP, D::ID),
            item_key.expose(),
        )
    }

    /// Recovers the key of one item version.
    pub fn unwrap_item_key(
        &self,
        ctx: &ItemContext,
        wrapped: &[u8],
    ) -> Result<ItemKey<D>, CryptoError> {
        open_key(self.expose(), &ctx.aad(LABEL_DEK_WRAP, D::ID), wrapped)
    }
}

/// The recovery key `RK`: 32 random bytes the user keeps on paper.
///
/// It is never stored. From it, one independent key-encryption key per domain is
/// derived with HKDF, so that recovery slots of different domains (and vaults) are
/// cryptographically separated.
pub struct RecoveryKey(SecretBytes);

impl RecoveryKey {
    /// Generates a fresh recovery key.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = SecretBytes::zeroed(true);
        rng::fill(bytes.expose_mut())?;
        Ok(Self(bytes))
    }

    /// Derives `KEK-R-D`:
    /// `HKDF-SHA256(salt = vault_id, ikm = RK, info = "zeropass/v1/kek/recovery" ‖ 0x00 ‖ domain)`.
    pub fn kek<D: Domain>(&self, vault_id: &VaultId) -> Result<RecoveryKek<D>, CryptoError> {
        let mut info = [0u8; INFO_KEK_RECOVERY.len() + 2];
        info[..INFO_KEK_RECOVERY.len()].copy_from_slice(INFO_KEK_RECOVERY);
        info[INFO_KEK_RECOVERY.len() + 1] = D::ID.as_u8();
        RecoveryKek::from_fn(|out| hkdf_sha256(vault_id.as_bytes(), self.0.expose(), &info, out))
    }
}

impl Zeroize for RecoveryKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::*;
    use crate::secret::PasswordKek;
    use crate::{DeviceId, ItemId, Passkey, Password, Totp};

    fn key<D: Domain, R: Role>(byte: u8) -> SecretKey<D, R> {
        SecretKey::from_fn(|b| -> Result<(), ()> {
            b.fill(byte);
            Ok(())
        })
        .unwrap()
    }

    fn same<D: Domain, R: Role>(a: &SecretKey<D, R>, b: &SecretKey<D, R>) -> bool {
        a.ct_eq(b).into()
    }

    const VAULT: VaultId = VaultId::from_bytes([1; 16]);
    const OTHER_VAULT: VaultId = VaultId::from_bytes([2; 16]);

    fn ctx() -> ItemContext {
        ItemContext {
            vault_id: VAULT,
            item_id: ItemId::from_bytes([3; 16]),
            hlc: 7,
            device_id: DeviceId::from_bytes([4; 16]),
        }
    }

    #[test]
    fn vault_keys_are_independent_random_values() {
        let p = VaultKey::<Password>::generate().unwrap();
        let t = VaultKey::<Totp>::generate().unwrap();
        let k = VaultKey::<Passkey>::generate().unwrap();
        assert_ne!(p.expose(), t.expose());
        assert_ne!(p.expose(), k.expose());
        assert_ne!(t.expose(), k.expose());
    }

    #[test]
    fn password_slot_round_trips() {
        let kek: PasswordKek = key(0x10);
        let vk = VaultKey::<Password>::generate().unwrap();
        let slot = vk.wrap(&kek, &VAULT).unwrap();
        assert_eq!(slot.len(), WRAPPED_KEY_LEN);
        assert!(same(&vk, &VaultKey::unwrap(&kek, &VAULT, &slot).unwrap()));
    }

    #[test]
    fn slot_rejects_wrong_kek_vault_or_tampering() {
        let kek: PasswordKek = key(0x10);
        let vk = VaultKey::<Password>::generate().unwrap();
        let slot = vk.wrap(&kek, &VAULT).unwrap();

        let wrong: PasswordKek = key(0x11);
        assert_eq!(
            VaultKey::unwrap(&wrong, &VAULT, &slot).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            VaultKey::unwrap(&kek, &OTHER_VAULT, &slot).unwrap_err(),
            CryptoError::Decrypt
        );

        let mut tampered = slot.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            VaultKey::unwrap(&kek, &VAULT, &tampered).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    /// Even if an attacker who knows the master password could somehow feed `KEK-P`
    /// bytes into another domain or slot kind, the AAD separation makes it fail.
    #[test]
    fn password_kek_bytes_cannot_open_other_domains_or_slot_kinds() {
        let vk_t = VaultKey::<Totp>::generate().unwrap();
        // The TOTP vault key as it would be stored in a recovery slot whose KEK
        // happens to have the same bytes as KEK-P.
        let kek_r_t: RecoveryKek<Totp> = key(0x10);
        let slot_t = vk_t.wrap(&kek_r_t, &VAULT).unwrap();

        let kek_p: PasswordKek = key(0x10);
        assert_eq!(kek_p.expose(), kek_r_t.expose());
        // Opened as a password slot of the password domain: rejected.
        assert_eq!(
            VaultKey::<Password>::unwrap(&kek_p, &VAULT, &slot_t).unwrap_err(),
            CryptoError::Decrypt
        );
        // Same bytes, recovery slot kind, but another domain: rejected.
        let kek_r_p: RecoveryKek<Password> = key(0x10);
        assert_eq!(
            VaultKey::<Password>::unwrap(&kek_r_p, &VAULT, &slot_t).unwrap_err(),
            CryptoError::Decrypt
        );
        // The matching key, kind and domain still work.
        assert!(same(
            &vk_t,
            &VaultKey::unwrap(&kek_r_t, &VAULT, &slot_t).unwrap()
        ));
    }

    #[test]
    fn a_slot_must_contain_exactly_one_key() {
        let kek: PasswordKek = key(0x10);
        let aad = vault_key_aad(
            <crate::role::PasswordKek as Wrap>::SLOT_LABEL,
            &VAULT,
            crate::DomainId::Password,
        );
        for len in [0, 31, 33] {
            let slot = seal(kek.expose(), &aad, &vec![0xAA; len]).unwrap();
            assert_eq!(
                VaultKey::<Password>::unwrap(&kek, &VAULT, &slot).unwrap_err(),
                CryptoError::MalformedEnvelope
            );
        }
    }

    #[test]
    fn item_key_round_trips_and_is_bound_to_its_context() {
        let vk = VaultKey::<Totp>::generate().unwrap();
        let dek = ItemKey::<Totp>::generate().unwrap();
        let wrapped = vk.wrap_item_key(&dek, &ctx()).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
        assert!(same(&dek, &vk.unwrap_item_key(&ctx(), &wrapped).unwrap()));

        let other = ItemContext { hlc: 8, ..ctx() };
        assert_eq!(
            vk.unwrap_item_key(&other, &wrapped).unwrap_err(),
            CryptoError::Decrypt
        );
        let other_vk = VaultKey::<Totp>::generate().unwrap();
        assert_eq!(
            other_vk.unwrap_item_key(&ctx(), &wrapped).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    /// Knowing `VK-P` gives no access to TOTP item keys, even in the hypothetical
    /// case where both vault keys had identical bytes.
    #[test]
    fn password_vault_key_cannot_unwrap_totp_item_keys() {
        let vk_t: VaultKey<Totp> = key(0x20);
        let dek = ItemKey::<Totp>::generate().unwrap();
        let wrapped = vk_t.wrap_item_key(&dek, &ctx()).unwrap();

        let vk_p: VaultKey<Password> = key(0x20);
        assert_eq!(
            vk_p.unwrap_item_key(&ctx(), &wrapped).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn wrapped_item_key_is_not_an_item_ciphertext() {
        // The dek-wrap and item labels differ, so one cannot be passed off as the other.
        let shared_bytes = 0x30;
        let vk: VaultKey<Password> = key(shared_bytes);
        let dek: ItemKey<Password> = key(0x31);
        let wrapped = vk.wrap_item_key(&dek, &ctx()).unwrap();
        let as_item_key: ItemKey<Password> = key(shared_bytes);
        assert_eq!(
            as_item_key.open_item(&ctx(), &wrapped).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn recovery_keks_are_separated_by_domain_and_vault() {
        let rk = RecoveryKey::generate().unwrap();
        let p = rk.kek::<Password>(&VAULT).unwrap();
        let t = rk.kek::<Totp>(&VAULT).unwrap();
        let k = rk.kek::<Passkey>(&VAULT).unwrap();
        assert_ne!(p.expose(), t.expose());
        assert_ne!(p.expose(), k.expose());
        assert_ne!(t.expose(), k.expose());
        assert_ne!(
            p.expose(),
            rk.0.expose(),
            "the recovery key is never used directly"
        );

        assert!(same(&t, &rk.kek::<Totp>(&VAULT).unwrap()));
        assert!(!same(&t, &rk.kek::<Totp>(&OTHER_VAULT).unwrap()));
        assert!(!same(
            &t,
            &RecoveryKey::generate()
                .unwrap()
                .kek::<Totp>(&VAULT)
                .unwrap()
        ));
    }

    #[test]
    fn recovery_kek_matches_the_spec_formula() {
        let mut rk = RecoveryKey::generate().unwrap();
        rk.0.expose_mut().fill(0x42);
        let mut expected = [0u8; 32];
        hkdf_sha256(
            &[1; 16],
            &[0x42; 32],
            b"zeropass/v1/kek/recovery\x00\x02",
            &mut expected,
        )
        .unwrap();
        assert_eq!(rk.kek::<Totp>(&VAULT).unwrap().expose(), &expected);
    }

    #[test]
    fn recovery_slot_round_trips_per_domain() {
        let rk = RecoveryKey::generate().unwrap();
        let vk_t = VaultKey::<Totp>::generate().unwrap();
        let slot = vk_t.wrap(&rk.kek(&VAULT).unwrap(), &VAULT).unwrap();
        assert!(same(
            &vk_t,
            &VaultKey::unwrap(&rk.kek(&VAULT).unwrap(), &VAULT, &slot).unwrap()
        ));

        let other = RecoveryKey::generate().unwrap();
        assert_eq!(
            VaultKey::<Totp>::unwrap(&other.kek(&VAULT).unwrap(), &VAULT, &slot).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn recovery_key_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", RecoveryKey::generate().unwrap()),
            "RecoveryKey(<redacted>)"
        );
    }
}
