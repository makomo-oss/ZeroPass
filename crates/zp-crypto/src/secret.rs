//! Typed secret keys.
//!
//! Every key carries two compile-time markers: the [`Domain`] it belongs to and its
//! [`Role`] in the key hierarchy. Mixing them up is a type error, which is how the
//! "password keys can never open TOTP data" rule of `docs/spec/crypto.md` §3 is
//! enforced at build time:
//!
//! ```
//! use zp_crypto::{Password, VaultKey};
//!
//! fn needs_password_key(_: &VaultKey<Password>) {}
//!
//! let key = VaultKey::<Password>::generate().unwrap();
//! needs_password_key(&key);
//! ```
//!
//! A key of another domain is rejected:
//!
//! ```compile_fail,E0308
//! use zp_crypto::{Password, Totp, VaultKey};
//!
//! fn needs_totp_key(_: &VaultKey<Totp>) {}
//!
//! let key = VaultKey::<Password>::generate().unwrap();
//! needs_totp_key(&key); // error[E0308]: mismatched types
//! ```
//!
//! and so is a key of another role:
//!
//! ```compile_fail,E0308
//! use zp_crypto::{ItemKey, Password, VaultKey};
//!
//! fn needs_vault_key(_: &VaultKey<Password>) {}
//!
//! let key = ItemKey::<Password>::generate().unwrap();
//! needs_vault_key(&key); // error[E0308]: mismatched types
//! ```
//!
//! Keys cannot be copied:
//!
//! ```compile_fail,E0599
//! use zp_crypto::{Password, VaultKey};
//!
//! let key = VaultKey::<Password>::generate().unwrap();
//! let _copy = key.clone(); // error[E0599]: no method named `clone`
//! ```

use core::fmt;
use core::marker::PhantomData;

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::mem::SecretBytes;
use crate::{CryptoError, Domain, rng};

/// Length in bytes of every symmetric key.
pub const KEY_LEN: usize = 32;

mod sealed {
    pub trait Sealed {}
}

/// Compile-time marker for a key's role in the hierarchy. Sealed.
pub trait Role: sealed::Sealed + 'static {
    /// Name used in redacted debug output.
    const NAME: &'static str;
    /// Whether keys of this role are long-lived and therefore kept on a locked page.
    const PINNED: bool;
}

/// Marker for roles whose keys are created from fresh randomness.
pub trait Generate: Role {}

/// Marker for key-encryption roles: keys that wrap a vault key into a key slot.
pub trait Wrap: Role {
    /// The AAD label of the key slot kind this role writes (`crypto.md` §4.1).
    const SLOT_LABEL: &'static str;
}

/// Role markers.
pub mod role {
    use super::{Generate, Role, Wrap, sealed};

    /// A vault key (`VK-D`): wraps the item keys of one domain.
    #[derive(Debug)]
    pub enum Vault {}
    /// An item key (`DEK`): encrypts one version of one item.
    #[derive(Debug)]
    pub enum Item {}
    /// The key-encryption key derived from the master password (`KEK-P`).
    #[derive(Debug)]
    pub enum PasswordKek {}
    /// A key-encryption key derived from the recovery key (`KEK-R-D`).
    #[derive(Debug)]
    pub enum RecoveryKek {}

    impl sealed::Sealed for Vault {}
    impl sealed::Sealed for Item {}
    impl sealed::Sealed for PasswordKek {}
    impl sealed::Sealed for RecoveryKek {}

    impl Role for Vault {
        const NAME: &'static str = "VaultKey";
        const PINNED: bool = true;
    }
    impl Role for Item {
        const NAME: &'static str = "ItemKey";
        // Item keys live for the duration of a single seal/open call.
        const PINNED: bool = false;
    }
    impl Role for PasswordKek {
        const NAME: &'static str = "PasswordKek";
        const PINNED: bool = true;
    }
    impl Role for RecoveryKek {
        const NAME: &'static str = "RecoveryKek";
        const PINNED: bool = true;
    }

    impl Generate for Vault {}
    impl Generate for Item {}

    impl Wrap for PasswordKek {
        const SLOT_LABEL: &'static str = "zeropass/v1/vk-wrap/password";
    }
    impl Wrap for RecoveryKek {
        const SLOT_LABEL: &'static str = "zeropass/v1/vk-wrap/recovery";
    }
}

/// A 32-byte secret key bound to a [`Domain`] and a [`Role`].
///
/// The bytes are wiped when the key is dropped. Keys are neither `Clone` nor
/// serialisable, and their `Debug` output is redacted.
pub struct SecretKey<D: Domain, R: Role> {
    bytes: SecretBytes,
    _marker: PhantomData<fn() -> (D, R)>,
}

/// The vault key `VK-D` of domain `D`.
pub type VaultKey<D> = SecretKey<D, role::Vault>;
/// The key of one item version in domain `D`.
pub type ItemKey<D> = SecretKey<D, role::Item>;
/// `KEK-P`, derived from the master password.
///
/// It exists for the password domain only: nothing derived from the master
/// password can wrap or unwrap the TOTP or passkey vault keys.
pub type PasswordKek = SecretKey<crate::Password, role::PasswordKek>;
/// `KEK-R-D`, derived from the recovery key for domain `D`.
pub type RecoveryKek<D> = SecretKey<D, role::RecoveryKek>;

impl<D: Domain, R: Role> SecretKey<D, R> {
    /// Builds a key by letting `fill` write the key material in place, so that no
    /// intermediate copy of the secret is left behind by this constructor.
    pub(crate) fn from_fn<E>(
        fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut bytes = SecretBytes::zeroed(R::PINNED);
        fill(bytes.expose_mut())?;
        Ok(Self {
            bytes,
            _marker: PhantomData,
        })
    }

    /// Borrows the raw key material. Crate-private on purpose.
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.bytes.expose()
    }

    /// Whether the key material is pinned in physical memory (never swapped out).
    ///
    /// Pinning is best effort: `false` for short-lived roles and whenever the
    /// operating system refuses the lock.
    pub fn is_page_locked(&self) -> bool {
        self.bytes.is_page_locked()
    }
}

impl<D: Domain, R: Generate> SecretKey<D, R> {
    /// Generates a fresh random key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        Self::from_fn(|bytes| rng::fill(bytes))
    }
}

impl<D: Domain, R: Role> Zeroize for SecretKey<D, R> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<D: Domain, R: Role> ConstantTimeEq for SecretKey<D, R> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.expose().ct_eq(other.expose())
    }
}

impl<D: Domain, R: Role> fmt::Debug for SecretKey<D, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}<{:?}>(<redacted>)", R::NAME, D::ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Passkey, Password, Totp};

    fn filled<D: Domain, R: Role>(byte: u8) -> SecretKey<D, R> {
        SecretKey::from_fn(|b| -> Result<(), ()> {
            b.fill(byte);
            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn generated_keys_are_random() {
        let a = VaultKey::<Password>::generate().unwrap();
        let b = VaultKey::<Password>::generate().unwrap();
        assert!(!bool::from(a.ct_eq(&b)));
        assert_ne!(a.expose(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn constant_time_eq_matches_contents() {
        let a: ItemKey<Totp> = filled(7);
        let b: ItemKey<Totp> = filled(7);
        let c: ItemKey<Totp> = filled(8);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn zeroize_wipes_the_key() {
        let mut key = VaultKey::<Passkey>::generate().unwrap();
        key.zeroize();
        assert_eq!(key.expose(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn debug_output_is_redacted() {
        let key: VaultKey<Totp> = filled(0xAB);
        let shown = format!("{key:?}");
        assert_eq!(shown, "VaultKey<Totp>(<redacted>)");
    }

    #[test]
    fn failed_construction_propagates_the_error() {
        let result = VaultKey::<Password>::from_fn(|_| Err("boom"));
        assert_eq!(result.unwrap_err(), "boom");
    }

    #[test]
    fn only_long_lived_roles_are_pinned() {
        assert!(!ItemKey::<Password>::generate().unwrap().is_page_locked());
        // Pinning is best effort, so only assert it where it is known to be allowed.
        if cfg!(any(windows, target_os = "macos")) {
            assert!(VaultKey::<Password>::generate().unwrap().is_page_locked());
        }
    }

    #[test]
    fn keys_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VaultKey<Password>>();
        assert_send_sync::<PasswordKek>();
    }
}
