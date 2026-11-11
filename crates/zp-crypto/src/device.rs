//! Per-device keys (`docs/spec/sync.md` §2, `docs/spec/pairing.md` §1).
//!
//! * The **signing key** (Ed25519) signs the ops a device authors and the device
//!   records it introduces. It is stored wrapped under the vault key of each
//!   domain, so a locked device cannot sign.
//! * The **channel key** (X25519) is the device's static key in the Noise
//!   handshakes. It must work while the vault is locked, so it is not wrapped.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::context::vault_key_aad_with_device;
use crate::envelope::{open, seal};
use crate::secret::{KEY_LEN, VaultKey};
use crate::{CryptoError, DeviceId, Domain, VaultId, rng};

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an Ed25519 or X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

const LABEL_DEVICE_KEY: &str = "zeropass/v1/device-key";

/// An Ed25519 signature.
pub type SignatureBytes = [u8; SIGNATURE_LEN];

/// A device's Ed25519 public key, used to verify what it signed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignPublicKey([u8; PUBLIC_KEY_LEN]);

impl SignPublicKey {
    /// Wraps public key bytes. Validity is checked when verifying.
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The public key bytes.
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Verifies `signature` over `message`.
    ///
    /// Uses strict verification: malleable signatures and small-order keys are
    /// rejected, so a signature identifies exactly one message and key.
    pub fn verify(&self, message: &[u8], signature: &SignatureBytes) -> Result<(), CryptoError> {
        VerifyingKey::from_bytes(&self.0)
            .and_then(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl fmt::Debug for SignPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignPublicKey(")?;
        self.0
            .iter()
            .take(4)
            .try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str("…)")
    }
}

/// A device's Ed25519 signing key.
pub struct DeviceSigningKey(SigningKey);

impl DeviceSigningKey {
    /// Generates a fresh signing key.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed = Zeroizing::new(rng::array::<KEY_LEN>()?);
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// The matching public key.
    pub fn public_key(&self) -> SignPublicKey {
        SignPublicKey(self.0.verifying_key().to_bytes())
    }

    /// Signs `message`. Ed25519 signatures are deterministic.
    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        self.0.sign(message).to_bytes()
    }

    /// Wraps the key under the vault key of domain `D`, bound to the vault, the
    /// domain and the device.
    pub fn wrap<D: Domain>(
        &self,
        vault_key: &VaultKey<D>,
        vault_id: &VaultId,
        device_id: &DeviceId,
    ) -> Result<Vec<u8>, CryptoError> {
        let seed = Zeroizing::new(self.0.to_bytes());
        let aad = vault_key_aad_with_device(LABEL_DEVICE_KEY, vault_id, D::ID, device_id);
        seal(vault_key.expose(), &aad, seed.as_slice())
    }

    /// Recovers the key from a blob produced by [`Self::wrap`] with the same
    /// vault key, vault, domain and device.
    pub fn unwrap<D: Domain>(
        vault_key: &VaultKey<D>,
        vault_id: &VaultId,
        device_id: &DeviceId,
        blob: &[u8],
    ) -> Result<Self, CryptoError> {
        let aad = vault_key_aad_with_device(LABEL_DEVICE_KEY, vault_id, D::ID, device_id);
        let seed = open(vault_key.expose(), &aad, blob)?;
        let seed: &[u8; KEY_LEN] = seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedEnvelope)?;
        Ok(Self(SigningKey::from_bytes(seed)))
    }
}

impl fmt::Debug for DeviceSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceSigningKey({:?})", self.public_key())
    }
}

/// A device's X25519 key pair for the Noise handshakes.
pub struct ChannelKey {
    secret: Zeroizing<[u8; KEY_LEN]>,
    public: [u8; PUBLIC_KEY_LEN],
}

impl ChannelKey {
    /// Generates a fresh key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self::from_secret_bytes(&Zeroizing::new(rng::array()?)))
    }

    /// Rebuilds the key pair from stored secret bytes.
    pub fn from_secret_bytes(secret: &[u8; KEY_LEN]) -> Self {
        let scalar = x25519_dalek::StaticSecret::from(*secret);
        Self {
            public: x25519_dalek::PublicKey::from(&scalar).to_bytes(),
            secret: Zeroizing::new(scalar.to_bytes()),
        }
    }

    /// The secret key bytes, for storage and for the Noise implementation.
    pub fn secret_bytes(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }

    /// The public key bytes.
    pub fn public_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }
}

impl fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Password, Totp};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.1, test 2 (one-byte message).
    #[test]
    fn ed25519_matches_rfc_8032() {
        let seed: [u8; 32] =
            hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .try_into()
                .unwrap();
        let key = DeviceSigningKey(SigningKey::from_bytes(&seed));
        assert_eq!(
            key.public_key().as_bytes().to_vec(),
            hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        );
        let signature = key.sign(&[0x72]);
        assert_eq!(
            signature.to_vec(),
            hex(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            )
        );
        key.public_key().verify(&[0x72], &signature).unwrap();
    }

    /// RFC 7748 §6.1 (Alice's key pair).
    #[test]
    fn x25519_matches_rfc_7748() {
        let secret: [u8; 32] =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .try_into()
                .unwrap();
        let key = ChannelKey::from_secret_bytes(&secret);
        assert_eq!(
            key.public_bytes().to_vec(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        let again = ChannelKey::from_secret_bytes(key.secret_bytes());
        assert_eq!(again.public_bytes(), key.public_bytes());
    }

    #[test]
    fn signatures_bind_message_and_key() {
        let key = DeviceSigningKey::generate().unwrap();
        let other = DeviceSigningKey::generate().unwrap();
        let signature = key.sign(b"message");

        key.public_key().verify(b"message", &signature).unwrap();
        assert_eq!(
            key.public_key().verify(b"massage", &signature).unwrap_err(),
            CryptoError::BadSignature
        );
        assert!(other.public_key().verify(b"message", &signature).is_err());
        let mut tampered = signature;
        tampered[10] ^= 1;
        assert!(key.public_key().verify(b"message", &tampered).is_err());
        // Garbage in place of a public key is rejected, not a panic.
        assert!(
            SignPublicKey::from_bytes([0xFF; 32])
                .verify(b"message", &signature)
                .is_err()
        );
        assert!(
            SignPublicKey::from_bytes([0; 32])
                .verify(b"message", &signature)
                .is_err()
        );
    }

    const VAULT: VaultId = VaultId::from_bytes([1; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([2; 16]);

    #[test]
    fn signing_key_round_trips_through_a_vault_key() {
        let key = DeviceSigningKey::generate().unwrap();
        let vk = VaultKey::<Password>::generate().unwrap();
        let blob = key.wrap(&vk, &VAULT, &DEVICE).unwrap();
        let back = DeviceSigningKey::unwrap(&vk, &VAULT, &DEVICE, &blob).unwrap();
        assert_eq!(back.public_key(), key.public_key());
        assert_eq!(back.sign(b"m"), key.sign(b"m"));
    }

    #[test]
    fn wrapped_signing_key_is_bound_to_its_context() {
        let key = DeviceSigningKey::generate().unwrap();
        let vk = VaultKey::<Password>::generate().unwrap();
        let blob = key.wrap(&vk, &VAULT, &DEVICE).unwrap();

        let other_vk = VaultKey::<Password>::generate().unwrap();
        let other_vault = VaultId::from_bytes([9; 16]);
        let other_device = DeviceId::from_bytes([9; 16]);
        assert!(DeviceSigningKey::unwrap(&other_vk, &VAULT, &DEVICE, &blob).is_err());
        assert!(DeviceSigningKey::unwrap(&vk, &other_vault, &DEVICE, &blob).is_err());
        assert!(DeviceSigningKey::unwrap(&vk, &VAULT, &other_device, &blob).is_err());

        // Same key bytes in another domain: the domain is part of the binding.
        let vk_t = VaultKey::<Totp>::generate().unwrap();
        let blob_t = key.wrap(&vk_t, &VAULT, &DEVICE).unwrap();
        assert_ne!(blob, blob_t);
        assert!(DeviceSigningKey::unwrap(&vk_t, &VAULT, &DEVICE, &blob).is_err());
        assert!(DeviceSigningKey::unwrap(&vk_t, &VAULT, &DEVICE, &blob_t).is_ok());
    }

    #[test]
    fn debug_output_shows_no_secret() {
        let key = DeviceSigningKey::generate().unwrap();
        let shown = format!("{key:?}");
        assert!(shown.starts_with("DeviceSigningKey(SignPublicKey("));
        assert_eq!(
            format!("{:?}", ChannelKey::generate().unwrap()),
            "ChannelKey(<redacted>)"
        );
    }
}
