//! The version 1 AEAD envelope (`docs/spec/crypto.md` §4):
//!
//! ```text
//! envelope = version(1) ‖ nonce(24) ‖ ciphertext ‖ tag(16)
//! ```
//!
//! XChaCha20-Poly1305 with a fresh random nonce per seal. The associated data is
//! not stored; callers rebuild it from context.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use crate::context::{ItemContext, LABEL_ITEM};
use crate::secret::{ItemKey, KEY_LEN};
use crate::{CryptoError, Domain, rng};

/// The only envelope version this implementation reads and writes.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// Length of the XChaCha20 nonce.
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Bytes an envelope adds to its plaintext.
pub const ENVELOPE_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    // The cipher zeroizes its copy of the key on drop (`zeroize` feature).
    XChaCha20Poly1305::new(key.into())
}

/// Seals `plaintext` with a caller-supplied nonce. Only tests may choose the nonce.
fn seal_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::with_capacity(ENVELOPE_OVERHEAD + plaintext.len());
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(plaintext);
    let body = &mut out[1 + NONCE_LEN..];
    match cipher(key).encrypt_inout_detached(&XNonce::from(*nonce), aad, body.into()) {
        Ok(tag) => {
            out.extend_from_slice(&tag);
            Ok(out)
        }
        Err(_) => {
            out.zeroize();
            Err(CryptoError::Encrypt)
        }
    }
}

/// Seals `plaintext` under `key`, binding it to `aad`.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_with_nonce(key, &rng::array()?, aad, plaintext)
}

/// Opens an envelope sealed under `key` and `aad`.
///
/// Every authentication failure (wrong key, wrong AAD, modified bytes) yields the
/// same [`CryptoError::Decrypt`].
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (&version, rest) = envelope
        .split_first()
        .ok_or(CryptoError::MalformedEnvelope)?;
    if version != ENVELOPE_VERSION {
        return Err(CryptoError::UnsupportedEnvelopeVersion(version));
    }
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::MalformedEnvelope);
    }
    let (nonce, rest) = rest.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::MalformedEnvelope)?;
    let tag = Tag::try_from(tag).map_err(|_| CryptoError::MalformedEnvelope)?;

    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    cipher(key)
        .decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &tag)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(buffer)
}

impl<D: Domain> ItemKey<D> {
    /// Encrypts the serialised content of one item version.
    pub fn seal_item(&self, ctx: &ItemContext, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        seal(self.expose(), &ctx.aad(LABEL_ITEM, D::ID), plaintext)
    }

    /// Decrypts the content of one item version.
    ///
    /// Fails unless `ctx` and the domain `D` are exactly those used to seal it.
    pub fn open_item(
        &self,
        ctx: &ItemContext,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        open(self.expose(), &ctx.aad(LABEL_ITEM, D::ID), envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, ItemId, Passkey, Password, Totp, VaultId};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    #[test]
    fn matches_the_xchacha20_poly1305_test_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let ciphertext = hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e",
        );
        let tag = hex("c0875924c1c7987947deafd8780acf49");

        let envelope = seal_with_nonce(&key, &nonce, &aad, plaintext).unwrap();

        let mut expected = vec![ENVELOPE_VERSION];
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&ciphertext);
        expected.extend_from_slice(&tag);
        assert_eq!(envelope, expected);
        assert_eq!(open(&key, &aad, &envelope).unwrap().as_slice(), plaintext);
    }

    const KEY: [u8; 32] = [0x11; 32];

    #[test]
    fn round_trips_including_empty_plaintext() {
        for plaintext in [&b""[..], b"x", &[0xEE; 1000]] {
            let envelope = seal(&KEY, b"aad", plaintext).unwrap();
            assert_eq!(envelope.len(), plaintext.len() + ENVELOPE_OVERHEAD);
            assert_eq!(open(&KEY, b"aad", &envelope).unwrap().as_slice(), plaintext);
        }
    }

    #[test]
    fn nonces_are_fresh_for_every_seal() {
        let a = seal(&KEY, b"", b"same").unwrap();
        let b = seal(&KEY, b"", b"same").unwrap();
        assert_ne!(a[1..1 + NONCE_LEN], b[1..1 + NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn any_single_bit_flip_is_rejected() {
        let envelope = seal(&KEY, b"aad", b"attack at dawn").unwrap();
        for byte in 1..envelope.len() {
            for bit in 0..8 {
                let mut tampered = envelope.clone();
                tampered[byte] ^= 1 << bit;
                assert_eq!(
                    open(&KEY, b"aad", &tampered).unwrap_err(),
                    CryptoError::Decrypt,
                    "flip at byte {byte} bit {bit} was accepted"
                );
            }
        }
    }

    #[test]
    fn wrong_key_or_aad_is_rejected_indistinguishably() {
        let envelope = seal(&KEY, b"aad", b"secret").unwrap();
        assert_eq!(
            open(&[0x12; 32], b"aad", &envelope).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            open(&KEY, b"aae", &envelope).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            open(&KEY, b"", &envelope).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        assert_eq!(
            open(&KEY, b"", &[]).unwrap_err(),
            CryptoError::MalformedEnvelope
        );
        let too_short = vec![ENVELOPE_VERSION; ENVELOPE_OVERHEAD - 1];
        assert_eq!(
            open(&KEY, b"", &too_short).unwrap_err(),
            CryptoError::MalformedEnvelope
        );

        let mut envelope = seal(&KEY, b"", b"secret").unwrap();
        envelope.truncate(envelope.len() - 1);
        assert_eq!(
            open(&KEY, b"", &envelope).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn unknown_versions_are_rejected() {
        let mut envelope = seal(&KEY, b"", b"secret").unwrap();
        for version in [0x00, 0x02, 0xFF] {
            envelope[0] = version;
            assert_eq!(
                open(&KEY, b"", &envelope).unwrap_err(),
                CryptoError::UnsupportedEnvelopeVersion(version)
            );
        }
    }

    fn ctx() -> ItemContext {
        ItemContext {
            vault_id: VaultId::from_bytes([1; 16]),
            item_id: ItemId::from_bytes([2; 16]),
            hlc: 42,
            device_id: DeviceId::from_bytes([3; 16]),
        }
    }

    fn fixed_key<D: Domain>() -> ItemKey<D> {
        ItemKey::from_fn(|b| -> Result<(), ()> {
            b.fill(0x33);
            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn item_round_trips_under_its_context() {
        let key = ItemKey::<Password>::generate().unwrap();
        let sealed = key.seal_item(&ctx(), b"login").unwrap();
        assert_eq!(key.open_item(&ctx(), &sealed).unwrap().as_slice(), b"login");
    }

    #[test]
    fn item_is_bound_to_every_context_field() {
        let key = ItemKey::<Password>::generate().unwrap();
        let sealed = key.seal_item(&ctx(), b"login").unwrap();

        let other_contexts = [
            ItemContext {
                vault_id: VaultId::from_bytes([9; 16]),
                ..ctx()
            },
            ItemContext {
                item_id: ItemId::from_bytes([9; 16]),
                ..ctx()
            },
            ItemContext { hlc: 43, ..ctx() },
            ItemContext {
                device_id: DeviceId::from_bytes([9; 16]),
                ..ctx()
            },
        ];
        for other in other_contexts {
            assert_eq!(
                key.open_item(&other, &sealed).unwrap_err(),
                CryptoError::Decrypt
            );
        }
    }

    #[test]
    fn item_is_bound_to_its_domain_even_with_identical_key_bytes() {
        let sealed = fixed_key::<Password>().seal_item(&ctx(), b"login").unwrap();
        assert!(fixed_key::<Password>().open_item(&ctx(), &sealed).is_ok());
        assert_eq!(
            fixed_key::<Totp>().open_item(&ctx(), &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            fixed_key::<Passkey>()
                .open_item(&ctx(), &sealed)
                .unwrap_err(),
            CryptoError::Decrypt
        );
    }
}
