//! A hardware key store built on a signing-only hardware key
//! (`docs/spec/crypto.md` §7.1).
//!
//! Platform credentials such as Windows Hello can sign but not encrypt. With a
//! *deterministic* signature scheme the signature over a random challenge is a
//! secret only the hardware can reproduce, so it can seed a wrapping key:
//!
//! ```text
//! blob      = id ‖ challenge(32) ‖ envelope
//! signature = hardware_sign(challenge)            (user verification happens here)
//! KEK-HW    = HKDF-SHA256(salt = challenge, ikm = signature, info = "zeropass/v1/kek/hardware")
//! envelope  = seal(KEK-HW, aad = context, secret)
//! ```

use zeroize::Zeroizing;

use crate::envelope::{open, seal};
use crate::hardware::{HardwareKeyError, HardwareKeyStore};
use crate::kdf::hkdf_sha256;
use crate::rng;
use crate::secret::KEY_LEN;

const INFO_KEK_HARDWARE: &[u8] = b"zeropass/v1/kek/hardware";
/// Length of the random challenge stored in each blob.
const CHALLENGE_LEN: usize = 32;

/// A hardware-held signing key that verifies the user for every signature.
///
/// The signature scheme **must be deterministic** (for example RSASSA-PKCS1-v1_5):
/// signing the same challenge twice must give the same bytes, otherwise wrapped
/// secrets cannot be recovered. Implementations must check this when the key is
/// created or opened, and must not expose a randomised scheme such as ECDSA.
pub trait UserVerifyingSigner {
    /// Signs `challenge` after verifying the user (biometrics or device PIN).
    fn sign(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError>;
}

/// A [`HardwareKeyStore`] that derives its wrapping keys from signatures of a
/// [`UserVerifyingSigner`].
#[derive(Debug)]
pub struct SignatureKeyStore<S> {
    signer: S,
    id: u8,
}

impl<S: UserVerifyingSigner> SignatureKeyStore<S> {
    /// Wraps `signer`. `implementation_id` is the first byte of every blob and
    /// identifies the platform (`crypto.md` §7).
    pub fn new(signer: S, implementation_id: u8) -> Self {
        Self {
            signer,
            id: implementation_id,
        }
    }

    fn kek(&self, challenge: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, HardwareKeyError> {
        let signature = self.signer.sign(challenge)?;
        if signature.is_empty() {
            return Err(HardwareKeyError::Platform(
                "the hardware returned an empty signature".into(),
            ));
        }
        let mut kek = Zeroizing::new([0u8; KEY_LEN]);
        hkdf_sha256(challenge, &signature, INFO_KEK_HARDWARE, kek.as_mut_slice())
            .map_err(|error| HardwareKeyError::Platform(error.to_string()))?;
        Ok(kek)
    }
}

impl<S: UserVerifyingSigner> HardwareKeyStore for SignatureKeyStore<S> {
    fn wrap(&self, context: &[u8], secret: &[u8]) -> Result<Vec<u8>, HardwareKeyError> {
        let challenge: [u8; CHALLENGE_LEN] =
            rng::array().map_err(|error| HardwareKeyError::Platform(error.to_string()))?;
        let kek = self.kek(&challenge)?;
        let envelope = seal(&kek, context, secret)
            .map_err(|error| HardwareKeyError::Platform(error.to_string()))?;

        let mut blob = Vec::with_capacity(1 + CHALLENGE_LEN + envelope.len());
        blob.push(self.id);
        blob.extend_from_slice(&challenge);
        blob.extend_from_slice(&envelope);
        Ok(blob)
    }

    fn unwrap(&self, context: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
        let (&id, rest) = blob.split_first().ok_or(HardwareKeyError::Decrypt)?;
        if id != self.id {
            return Err(HardwareKeyError::WrongStore);
        }
        if rest.len() < CHALLENGE_LEN {
            return Err(HardwareKeyError::Decrypt);
        }
        let (challenge, envelope) = rest.split_at(CHALLENGE_LEN);
        let kek = self.kek(challenge)?;
        open(&kek, context, envelope).map_err(|_| HardwareKeyError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use subtle::ConstantTimeEq;

    use super::*;
    use crate::{CryptoError, Passkey, Totp, VaultId, VaultKey};

    /// A deterministic stand-in for a hardware signing key.
    struct FakeSigner {
        key: [u8; 32],
        user_present: Cell<bool>,
        prompts: Cell<u32>,
        randomised: bool,
    }

    impl FakeSigner {
        fn new(key: u8) -> Self {
            Self {
                key: [key; 32],
                user_present: Cell::new(true),
                prompts: Cell::new(0),
                randomised: false,
            }
        }
    }

    impl UserVerifyingSigner for &FakeSigner {
        fn sign(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
            self.prompts.set(self.prompts.get() + 1);
            if !self.user_present.get() {
                return Err(HardwareKeyError::UserCancelled);
            }
            let mut signature = Zeroizing::new(vec![0u8; 64]);
            hkdf_sha256(&self.key, challenge, b"fake signature", &mut signature).unwrap();
            if self.randomised {
                // A different signature on every call, as a randomised scheme
                // gives. Derived from the call counter rather than from random
                // bytes, so that two calls can never happen to agree.
                signature[0] ^= (self.prompts.get() % 255) as u8 + 1;
            }
            Ok(signature)
        }
    }

    const ID: u8 = 0x02;
    const VAULT: VaultId = VaultId::from_bytes([1; 16]);

    fn hw(error: HardwareKeyError) -> CryptoError {
        CryptoError::HardwareKey(error)
    }

    #[test]
    fn vault_key_round_trips_and_every_use_prompts() {
        let signer = FakeSigner::new(7);
        let store = SignatureKeyStore::new(&signer, ID);
        let vk = VaultKey::<Totp>::generate().unwrap();

        let slot = vk.wrap_with_hardware(&store, &VAULT).unwrap();
        assert_eq!(slot[0], ID);
        assert_eq!(signer.prompts.get(), 1);

        for expected_prompts in [2, 3] {
            let back = VaultKey::<Totp>::unwrap_with_hardware(&store, &VAULT, &slot).unwrap();
            assert!(bool::from(vk.ct_eq(&back)));
            assert_eq!(signer.prompts.get(), expected_prompts);
        }
    }

    #[test]
    fn each_wrap_uses_a_fresh_challenge() {
        let signer = FakeSigner::new(7);
        let store = SignatureKeyStore::new(&signer, ID);
        let vk = VaultKey::<Totp>::generate().unwrap();
        let a = vk.wrap_with_hardware(&store, &VAULT).unwrap();
        let b = vk.wrap_with_hardware(&store, &VAULT).unwrap();
        assert_ne!(a[1..33], b[1..33]);
    }

    #[test]
    fn a_declined_prompt_reveals_nothing() {
        let signer = FakeSigner::new(7);
        let store = SignatureKeyStore::new(&signer, ID);
        let slot = VaultKey::<Totp>::generate()
            .unwrap()
            .wrap_with_hardware(&store, &VAULT)
            .unwrap();

        signer.user_present.set(false);
        assert_eq!(
            VaultKey::<Totp>::unwrap_with_hardware(&store, &VAULT, &slot).unwrap_err(),
            hw(HardwareKeyError::UserCancelled)
        );
        assert_eq!(
            VaultKey::<Totp>::generate()
                .unwrap()
                .wrap_with_hardware(&store, &VAULT)
                .unwrap_err(),
            hw(HardwareKeyError::UserCancelled)
        );
    }

    #[test]
    fn slots_are_bound_to_the_key_the_context_and_the_store_kind() {
        let signer = FakeSigner::new(7);
        let store = SignatureKeyStore::new(&signer, ID);
        let slot = VaultKey::<Totp>::generate()
            .unwrap()
            .wrap_with_hardware(&store, &VAULT)
            .unwrap();
        let unwrap_err = |store: &dyn HardwareKeyStore, vault: &VaultId, slot: &[u8]| {
            VaultKey::<Totp>::unwrap_with_hardware(store, vault, slot).unwrap_err()
        };

        // Another device's hardware key.
        let other_signer = FakeSigner::new(8);
        let other = SignatureKeyStore::new(&other_signer, ID);
        assert_eq!(
            unwrap_err(&other, &VAULT, &slot),
            hw(HardwareKeyError::Decrypt)
        );
        // Another vault or domain.
        assert_eq!(
            unwrap_err(&store, &VaultId::from_bytes([2; 16]), &slot),
            hw(HardwareKeyError::Decrypt)
        );
        assert_eq!(
            VaultKey::<Passkey>::unwrap_with_hardware(&store, &VAULT, &slot).unwrap_err(),
            hw(HardwareKeyError::Decrypt)
        );
        // A modified challenge or ciphertext.
        for index in [1, 32, 40, slot.len() - 1] {
            let mut tampered = slot.clone();
            tampered[index] ^= 1;
            assert_eq!(
                unwrap_err(&store, &VAULT, &tampered),
                hw(HardwareKeyError::Decrypt)
            );
        }
        // Blobs of another implementation, and truncated blobs.
        let mut foreign = slot.clone();
        foreign[0] = 0x01;
        assert_eq!(
            unwrap_err(&store, &VAULT, &foreign),
            hw(HardwareKeyError::WrongStore)
        );
        assert_eq!(
            unwrap_err(&store, &VAULT, &[]),
            hw(HardwareKeyError::Decrypt)
        );
        assert_eq!(
            unwrap_err(&store, &VAULT, &slot[..20]),
            hw(HardwareKeyError::Decrypt)
        );
    }

    #[test]
    fn a_randomised_signature_scheme_cannot_recover_the_key() {
        // This is why implementations must refuse non-deterministic keys up front.
        let mut signer = FakeSigner::new(7);
        signer.randomised = true;
        let store = SignatureKeyStore::new(&signer, ID);
        let slot = VaultKey::<Totp>::generate()
            .unwrap()
            .wrap_with_hardware(&store, &VAULT)
            .unwrap();
        assert_eq!(
            VaultKey::<Totp>::unwrap_with_hardware(&store, &VAULT, &slot).unwrap_err(),
            hw(HardwareKeyError::Decrypt)
        );
    }

    #[test]
    fn the_wrapping_key_follows_the_spec_formula() {
        let signer = FakeSigner::new(7);
        let store = SignatureKeyStore::new(&signer, ID);
        let challenge = [0x33u8; CHALLENGE_LEN];
        let signature = (&signer).sign(&challenge).unwrap();
        let mut expected = [0u8; 32];
        hkdf_sha256(
            &challenge,
            &signature,
            b"zeropass/v1/kek/hardware",
            &mut expected,
        )
        .unwrap();
        assert_eq!(store.kek(&challenge).unwrap().as_slice(), expected);
    }
}
