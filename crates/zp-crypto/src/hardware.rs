//! Hardware key stores (`docs/spec/crypto.md` §7).
//!
//! The TOTP and passkey vault keys are wrapped only by a key that lives in the
//! platform's secure hardware and demands user verification (biometrics, or the
//! device PIN the OS treats as equivalent) for every unwrap. [`HardwareKeyStore`]
//! abstracts over the platforms; [`InsecureSoftwareKeyStore`] is a stand-in for
//! tests and development that offers no such protection.
//!
//! Only the hardware-bound domains can use a store. The password domain cannot:
//!
//! ```compile_fail,E0277
//! use zp_crypto::{InsecureSoftwareKeyStore, Password, VaultId, VaultKey};
//!
//! let store = InsecureSoftwareKeyStore::generate().unwrap();
//! let vault_id = VaultId::generate().unwrap();
//! let vk_p = VaultKey::<Password>::generate().unwrap();
//! vk_p.wrap_with_hardware(&store, &vault_id); // error[E0277]: `Password: HardwareBound`
//! ```

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use zeroize::{Zeroize, Zeroizing};

use crate::context::vault_key_aad;
use crate::envelope::{open, seal};
use crate::mem::SecretBytes;
use crate::secret::{KEY_LEN, VaultKey};
use crate::{CryptoError, Domain, Passkey, Totp, VaultId, rng};

const LABEL_VK_WRAP_HARDWARE: &str = "zeropass/v1/vk-wrap/hardware";

/// Why a hardware key store operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HardwareKeyError {
    /// No usable hardware key store on this device (for example, no TPM or no
    /// enrolled biometrics).
    #[error("no hardware key store is available: {0}")]
    Unavailable(String),
    /// The user dismissed or failed the verification prompt.
    #[error("user verification was cancelled or failed")]
    UserCancelled,
    /// The blob was produced by a different kind of store.
    #[error("the key slot belongs to a different hardware key store")]
    WrongStore,
    /// The blob is malformed, was modified, or belongs to another context or key.
    #[error("the hardware-wrapped key could not be opened")]
    Decrypt,
    /// The platform API reported an error.
    #[error("hardware key store error: {0}")]
    Platform(String),
}

/// A platform key store that wraps secrets under a hardware-protected key.
///
/// Implementations must:
/// * require user verification on **every** [`unwrap`](Self::unwrap);
/// * bind each blob to `context`, so a blob wrapped for one vault or domain cannot
///   be unwrapped for another;
/// * start each blob with their one-byte implementation identifier.
pub trait HardwareKeyStore {
    /// Wraps `secret`, bound to `context`. May prompt the user.
    fn wrap(&self, context: &[u8], secret: &[u8]) -> Result<Vec<u8>, HardwareKeyError>;

    /// Unwraps a blob produced by [`wrap`](Self::wrap) with the same `context`.
    /// Always prompts the user.
    fn unwrap(&self, context: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError>;
}

/// Marker for the domains whose vault key is protected by a hardware key store.
pub trait HardwareBound: Domain {}
impl HardwareBound for Totp {}
impl HardwareBound for Passkey {}

impl<D: HardwareBound> VaultKey<D> {
    /// Wraps this vault key into a hardware key slot bound to `vault_id` and `D`.
    pub fn wrap_with_hardware(
        &self,
        store: &dyn HardwareKeyStore,
        vault_id: &VaultId,
    ) -> Result<Vec<u8>, CryptoError> {
        let context = vault_key_aad(LABEL_VK_WRAP_HARDWARE, vault_id, D::ID);
        Ok(store.wrap(&context, self.expose())?)
    }

    /// Recovers a vault key from a hardware key slot. Prompts for user verification.
    pub fn unwrap_with_hardware(
        store: &dyn HardwareKeyStore,
        vault_id: &VaultId,
        slot: &[u8],
    ) -> Result<Self, CryptoError> {
        let context = vault_key_aad(LABEL_VK_WRAP_HARDWARE, vault_id, D::ID);
        let secret = store.unwrap(&context, slot)?;
        let secret: &[u8; KEY_LEN] = secret
            .as_slice()
            .try_into()
            .map_err(|_| HardwareKeyError::Decrypt)?;
        Self::from_fn(|out| {
            out.copy_from_slice(secret);
            Ok(())
        })
    }
}

/// A software-only key store for **tests and development**.
///
/// It keeps its wrapping key in process memory, performs no user verification and
/// is exactly as strong as wherever the caller persists [`Self::key_bytes`]. Using
/// it for real data defeats the separation between the master password and the
/// TOTP / passkey domains.
///
/// Blob format: `0x01 ‖ envelope(key, aad = context)`.
pub struct InsecureSoftwareKeyStore {
    key: SecretBytes,
    user_present: AtomicBool,
}

impl InsecureSoftwareKeyStore {
    /// Implementation identifier, the first byte of every blob.
    pub const ID: u8 = 0x01;

    /// Creates a store with a fresh random key.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = SecretBytes::zeroed(true);
        rng::fill(key.expose_mut())?;
        Ok(Self {
            key,
            user_present: AtomicBool::new(true),
        })
    }

    /// Recreates a store from a previously exported key.
    pub fn from_key_bytes(key: &[u8; KEY_LEN]) -> Self {
        let mut bytes = SecretBytes::zeroed(true);
        bytes.expose_mut().copy_from_slice(key);
        Self {
            key: bytes,
            user_present: AtomicBool::new(true),
        }
    }

    /// Exports the store's key so a development tool can persist it.
    pub fn key_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(*self.key.expose())
    }

    /// Simulates the verification prompt: while `false`, every unwrap fails with
    /// [`HardwareKeyError::UserCancelled`], as if the user dismissed it.
    pub fn set_user_present(&self, present: bool) {
        self.user_present.store(present, Ordering::SeqCst);
    }
}

impl HardwareKeyStore for InsecureSoftwareKeyStore {
    fn wrap(&self, context: &[u8], secret: &[u8]) -> Result<Vec<u8>, HardwareKeyError> {
        let envelope = seal(self.key.expose(), context, secret)
            .map_err(|e| HardwareKeyError::Platform(e.to_string()))?;
        let mut blob = Vec::with_capacity(1 + envelope.len());
        blob.push(Self::ID);
        blob.extend_from_slice(&envelope);
        Ok(blob)
    }

    fn unwrap(&self, context: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
        let (&id, envelope) = blob.split_first().ok_or(HardwareKeyError::Decrypt)?;
        if id != Self::ID {
            return Err(HardwareKeyError::WrongStore);
        }
        if !self.user_present.load(Ordering::SeqCst) {
            return Err(HardwareKeyError::UserCancelled);
        }
        open(self.key.expose(), context, envelope).map_err(|_| HardwareKeyError::Decrypt)
    }
}

impl Zeroize for InsecureSoftwareKeyStore {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl fmt::Debug for InsecureSoftwareKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InsecureSoftwareKeyStore(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::*;

    const VAULT: VaultId = VaultId::from_bytes([1; 16]);
    const OTHER_VAULT: VaultId = VaultId::from_bytes([2; 16]);

    fn hw(e: HardwareKeyError) -> CryptoError {
        CryptoError::HardwareKey(e)
    }

    #[test]
    fn totp_vault_key_round_trips_through_the_trait() {
        let store = InsecureSoftwareKeyStore::generate().unwrap();
        let store: &dyn HardwareKeyStore = &store;
        let vk = VaultKey::<Totp>::generate().unwrap();

        let slot = vk.wrap_with_hardware(store, &VAULT).unwrap();
        assert_eq!(slot[0], InsecureSoftwareKeyStore::ID);
        let back = VaultKey::<Totp>::unwrap_with_hardware(store, &VAULT, &slot).unwrap();
        assert!(bool::from(vk.ct_eq(&back)));
    }

    #[test]
    fn slot_is_bound_to_vault_and_domain() {
        let store = InsecureSoftwareKeyStore::generate().unwrap();
        let vk = VaultKey::<Totp>::generate().unwrap();
        let slot = vk.wrap_with_hardware(&store, &VAULT).unwrap();

        assert_eq!(
            VaultKey::<Totp>::unwrap_with_hardware(&store, &OTHER_VAULT, &slot).unwrap_err(),
            hw(HardwareKeyError::Decrypt)
        );
        assert_eq!(
            VaultKey::<Passkey>::unwrap_with_hardware(&store, &VAULT, &slot).unwrap_err(),
            hw(HardwareKeyError::Decrypt)
        );
    }

    #[test]
    fn another_devices_store_cannot_open_the_slot() {
        let store = InsecureSoftwareKeyStore::generate().unwrap();
        let slot = VaultKey::<Totp>::generate()
            .unwrap()
            .wrap_with_hardware(&store, &VAULT);
        let other = InsecureSoftwareKeyStore::generate().unwrap();
        assert_eq!(
            VaultKey::<Totp>::unwrap_with_hardware(&other, &VAULT, &slot.unwrap()).unwrap_err(),
            hw(HardwareKeyError::Decrypt)
        );
    }

    #[test]
    fn unwrap_requires_user_presence_every_time() {
        let store = InsecureSoftwareKeyStore::generate().unwrap();
        let vk = VaultKey::<Passkey>::generate().unwrap();
        let slot = vk.wrap_with_hardware(&store, &VAULT).unwrap();

        store.set_user_present(false);
        assert_eq!(
            VaultKey::<Passkey>::unwrap_with_hardware(&store, &VAULT, &slot).unwrap_err(),
            hw(HardwareKeyError::UserCancelled)
        );
        store.set_user_present(true);
        assert!(VaultKey::<Passkey>::unwrap_with_hardware(&store, &VAULT, &slot).is_ok());
    }

    #[test]
    fn malformed_and_foreign_blobs_are_rejected() {
        let store = InsecureSoftwareKeyStore::generate().unwrap();
        let unwrap =
            |blob: &[u8]| VaultKey::<Totp>::unwrap_with_hardware(&store, &VAULT, blob).unwrap_err();
        assert_eq!(unwrap(&[]), hw(HardwareKeyError::Decrypt));
        assert_eq!(
            unwrap(&[InsecureSoftwareKeyStore::ID]),
            hw(HardwareKeyError::Decrypt)
        );
        assert_eq!(unwrap(&[0x02; 80]), hw(HardwareKeyError::WrongStore));

        // A blob that authenticates but does not hold exactly one key.
        let context = vault_key_aad(LABEL_VK_WRAP_HARDWARE, &VAULT, crate::DomainId::Totp);
        let short = store.wrap(&context, &[0xAA; 31]).unwrap();
        assert_eq!(unwrap(&short), hw(HardwareKeyError::Decrypt));
    }

    #[test]
    fn store_can_be_recreated_from_its_exported_key() {
        let store = InsecureSoftwareKeyStore::generate().unwrap();
        let vk = VaultKey::<Totp>::generate().unwrap();
        let slot = vk.wrap_with_hardware(&store, &VAULT).unwrap();

        let reopened = InsecureSoftwareKeyStore::from_key_bytes(&store.key_bytes());
        let back = VaultKey::<Totp>::unwrap_with_hardware(&reopened, &VAULT, &slot).unwrap();
        assert!(bool::from(vk.ct_eq(&back)));
        assert_eq!(
            format!("{reopened:?}"),
            "InsecureSoftwareKeyStore(<redacted>)"
        );
    }
}
