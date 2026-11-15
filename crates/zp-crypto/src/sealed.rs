//! Sealing a secret to one process of this device (`docs/spec/ipc.md` §13.3).
//!
//! The processes of the vault daemon hand each other a few secrets: a vault
//! key that moves to the process that will hold it, or the hardware
//! signature that unwraps one. The message may pass through a process that
//! must not learn the secret, so the sender seals it to a key pair that the
//! receiver made for this one message:
//!
//! ```text
//! sealed  = ephemeral_pk(32) ‖ envelope
//! shared  = X25519(ephemeral_sk, receiver_pk)
//! key     = HKDF-SHA256(salt = ephemeral_pk ‖ receiver_pk, ikm = shared,
//!                       info = "zeropass/v1/local-seal")
//! envelope = the version 1 AEAD envelope under `key`, with the caller's
//!            context as associated data
//! ```
//!
//! This keeps the secret from a process that only carries the message. It
//! does not authenticate the sender, and a carrier that replaced the
//! receiver's public key with its own could read the secret: it protects
//! against a process whose memory is read, not against one that is taken over.

use zeroize::Zeroizing;

use crate::envelope::{open, seal};
use crate::kdf::hkdf_sha256;
use crate::secret::KEY_LEN;
use crate::{CryptoError, PUBLIC_KEY_LEN, rng};

const INFO_LOCAL_SEAL: &[u8] = b"zeropass/v1/local-seal";

fn message_key(
    shared: &x25519_dalek::SharedSecret,
    ephemeral: &[u8; PUBLIC_KEY_LEN],
    receiver: &[u8; PUBLIC_KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    // An all-zero result means the other side sent a point of small order.
    if !shared.was_contributory() {
        return Err(CryptoError::Decrypt);
    }
    let mut salt = [0u8; 2 * PUBLIC_KEY_LEN];
    salt[..PUBLIC_KEY_LEN].copy_from_slice(ephemeral);
    salt[PUBLIC_KEY_LEN..].copy_from_slice(receiver);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf_sha256(
        &salt,
        shared.as_bytes(),
        INFO_LOCAL_SEAL,
        key.as_mut_slice(),
    )?;
    Ok(key)
}

/// Seals `secret` so that only the holder of the [`SealingKey`] behind
/// `receiver` can open it, and only with the same `context`.
pub fn seal_to(
    receiver: &[u8; PUBLIC_KEY_LEN],
    context: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral = x25519_dalek::StaticSecret::from(*Zeroizing::new(rng::array()?));
    let ephemeral_pk = x25519_dalek::PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&x25519_dalek::PublicKey::from(*receiver));
    let key = message_key(&shared, &ephemeral_pk, receiver)?;
    let envelope = seal(&key, context, secret)?;
    let mut sealed = Vec::with_capacity(PUBLIC_KEY_LEN + envelope.len());
    sealed.extend_from_slice(&ephemeral_pk);
    sealed.extend_from_slice(&envelope);
    Ok(sealed)
}

/// A key pair that receives sealed secrets. Make one per message, or per
/// process: it is never stored.
pub struct SealingKey {
    secret: x25519_dalek::StaticSecret,
    public: [u8; PUBLIC_KEY_LEN],
}

impl SealingKey {
    /// Generates a fresh key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let secret = x25519_dalek::StaticSecret::from(*Zeroizing::new(rng::array()?));
        Ok(Self {
            public: x25519_dalek::PublicKey::from(&secret).to_bytes(),
            secret,
        })
    }

    /// The public key to give to the sender.
    pub fn public_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// Opens what [`seal_to`] made for this key with the same `context`.
    pub fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let Some((ephemeral, envelope)) = sealed.split_at_checked(PUBLIC_KEY_LEN) else {
            return Err(CryptoError::MalformedEnvelope);
        };
        let ephemeral: [u8; PUBLIC_KEY_LEN] = ephemeral
            .try_into()
            .map_err(|_| CryptoError::MalformedEnvelope)?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral));
        let key = message_key(&shared, &ephemeral, &self.public)?;
        open(&key, context, envelope)
    }
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_secret_opens_only_for_its_receiver_and_context() {
        let receiver = SealingKey::generate().unwrap();
        let sealed = seal_to(receiver.public_bytes(), b"context", b"the secret").unwrap();
        assert_eq!(
            receiver.open(b"context", &sealed).unwrap().as_slice(),
            b"the secret"
        );
        assert_eq!(
            receiver.open(b"another context", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
        let other = SealingKey::generate().unwrap();
        assert_eq!(
            other.open(b"context", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(format!("{receiver:?}"), "SealingKey(<redacted>)");
    }

    #[test]
    fn sealing_twice_gives_different_bytes_and_hides_the_secret() {
        let receiver = SealingKey::generate().unwrap();
        let secret = [0x5A; 64];
        let a = seal_to(receiver.public_bytes(), b"", &secret).unwrap();
        let b = seal_to(receiver.public_bytes(), b"", &secret).unwrap();
        assert_ne!(a, b);
        assert!(!a.windows(8).any(|window| window == &secret[..8]));
    }

    #[test]
    fn tampering_and_truncation_are_rejected() {
        let receiver = SealingKey::generate().unwrap();
        let sealed = seal_to(receiver.public_bytes(), b"context", b"the secret").unwrap();
        for index in [0, PUBLIC_KEY_LEN, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert!(receiver.open(b"context", &changed).is_err(), "byte {index}");
        }
        assert_eq!(
            receiver.open(b"context", &sealed[..10]).unwrap_err(),
            CryptoError::MalformedEnvelope
        );
        assert!(receiver.open(b"context", &sealed[..40]).is_err());
    }

    #[test]
    fn a_point_of_small_order_is_refused() {
        // The all-zero public key gives an all-zero shared secret.
        assert_eq!(
            seal_to(&[0; PUBLIC_KEY_LEN], b"", b"secret").unwrap_err(),
            CryptoError::Decrypt
        );
        let receiver = SealingKey::generate().unwrap();
        let mut forged = vec![0u8; PUBLIC_KEY_LEN];
        forged.extend_from_slice(&[1; 60]);
        assert_eq!(
            receiver.open(b"", &forged).unwrap_err(),
            CryptoError::Decrypt
        );
    }
}
