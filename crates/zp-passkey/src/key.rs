//! Credential key pairs: ES256 (ECDSA on P-256 with SHA-256) and EdDSA
//! (Ed25519), the two algorithms ZeroPass creates passkeys with (ADR-0010).
//!
//! A private key exists in memory only as a [`CredentialKey`], which wipes it
//! when dropped, and is stored as PKCS #8 DER inside the vault's encrypted
//! passkey items. ECDSA signatures use the deterministic nonce of RFC 6979, so
//! signing needs no randomness and the W3C test vectors can be reproduced.

use core::fmt;

use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use zeroize::Zeroizing;

use crate::PasskeyError;
use crate::cbor::Cbor;

/// A signature algorithm, by its COSE identifier (IANA "COSE Algorithms").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ECDSA with SHA-256 on the P-256 curve (COSE `-7`). WebAuthn's
    /// mandatory algorithm.
    Es256,
    /// EdDSA on Ed25519 (COSE `-8`).
    EdDsa,
}

/// SubjectPublicKeyInfo of a P-256 key, up to the uncompressed point
/// (RFC 5480): id-ecPublicKey, prime256v1, a BIT STRING of 66 bytes.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// SubjectPublicKeyInfo of an Ed25519 key, up to the key (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// COSE key parameters (RFC 9052, RFC 9053).
mod cose {
    pub(super) const KTY: i64 = 1;
    pub(super) const ALG: i64 = 3;
    pub(super) const CRV: i64 = -1;
    pub(super) const X: i64 = -2;
    pub(super) const Y: i64 = -3;
    pub(super) const KTY_OKP: i64 = 1;
    pub(super) const KTY_EC2: i64 = 2;
    pub(super) const CRV_P256: i64 = 1;
    pub(super) const CRV_ED25519: i64 = 6;
}

impl Algorithm {
    /// The COSE identifier.
    pub const fn cose(self) -> i32 {
        match self {
            Algorithm::Es256 => -7,
            Algorithm::EdDsa => -8,
        }
    }

    /// The algorithm with that COSE identifier, if ZeroPass supports it.
    pub const fn from_cose(id: i32) -> Option<Self> {
        match id {
            -7 => Some(Algorithm::Es256),
            -8 => Some(Algorithm::EdDsa),
            _ => None,
        }
    }

    /// The algorithm to create a credential with: the first of `preferred`
    /// (the relying party's `pubKeyCredParams`, most preferred first) that
    /// ZeroPass supports. With no preference at all, ES256: WebAuthn's
    /// default list is ES256 and RS256.
    pub fn choose(preferred: &[i32]) -> Option<Self> {
        if preferred.is_empty() {
            return Some(Algorithm::Es256);
        }
        preferred.iter().copied().find_map(Self::from_cose)
    }

    /// The name used in messages.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Es256 => "ES256",
            Algorithm::EdDsa => "EdDSA",
        }
    }
}

enum Secret {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

/// The private key of a passkey. Wiped from memory when dropped; never
/// printed.
pub struct CredentialKey(Secret);

impl fmt::Debug for CredentialKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialKey({}, <redacted>)", self.algorithm().name())
    }
}

/// Fills a buffer from the operating system's random number generator.
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, PasskeyError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|_| PasskeyError::Random)?;
    Ok(bytes)
}

impl CredentialKey {
    /// A new random key pair.
    pub fn generate(algorithm: Algorithm) -> Result<Self, PasskeyError> {
        match algorithm {
            Algorithm::Es256 => {
                // A random scalar is out of range (zero, or not below the
                // group order) with a probability of about 2^-32; draw again.
                for _ in 0..8 {
                    let scalar = random::<32>()?;
                    if let Ok(key) = p256::ecdsa::SigningKey::from_slice(scalar.as_slice()) {
                        return Ok(Self(Secret::Es256(key)));
                    }
                }
                Err(PasskeyError::Random)
            }
            Algorithm::EdDsa => {
                let seed = random::<32>()?;
                Ok(Self(Secret::EdDsa(ed25519_dalek::SigningKey::from_bytes(
                    &seed,
                ))))
            }
        }
    }

    /// A key from its raw form: the 32-byte scalar of a P-256 key, or the
    /// 32-byte seed of an Ed25519 key (as test vectors give them).
    pub fn from_raw(algorithm: Algorithm, raw: &[u8]) -> Result<Self, PasskeyError> {
        match algorithm {
            Algorithm::Es256 => p256::ecdsa::SigningKey::from_slice(raw)
                .map(|key| Self(Secret::Es256(key)))
                .map_err(|_| PasskeyError::MalformedKey),
            Algorithm::EdDsa => {
                let seed: &[u8; 32] = raw.try_into().map_err(|_| PasskeyError::MalformedKey)?;
                Ok(Self(Secret::EdDsa(ed25519_dalek::SigningKey::from_bytes(
                    seed,
                ))))
            }
        }
    }

    /// A key stored as PKCS #8 DER, which must be of `algorithm`.
    pub fn from_pkcs8(algorithm: Algorithm, der: &[u8]) -> Result<Self, PasskeyError> {
        match algorithm {
            Algorithm::Es256 => {
                <p256::ecdsa::SigningKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_der(der)
                    .map(|key| Self(Secret::Es256(key)))
            }
            Algorithm::EdDsa => {
                ed25519_dalek::SigningKey::from_pkcs8_der(der).map(|key| Self(Secret::EdDsa(key)))
            }
        }
        .map_err(|_| PasskeyError::MalformedKey)
    }

    /// The key as PKCS #8 DER, the form it is stored in.
    pub fn to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, PasskeyError> {
        let document = match &self.0 {
            Secret::Es256(key) => p256::pkcs8::EncodePrivateKey::to_pkcs8_der(key),
            Secret::EdDsa(key) => key.to_pkcs8_der(),
        }
        .map_err(|_| PasskeyError::MalformedKey)?;
        // The document wipes itself; so does the copy.
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }

    /// The algorithm of this key.
    pub fn algorithm(&self) -> Algorithm {
        match self.0 {
            Secret::Es256(_) => Algorithm::Es256,
            Secret::EdDsa(_) => Algorithm::EdDsa,
        }
    }

    /// The public half.
    pub fn public_key(&self) -> PublicKey {
        match &self.0 {
            Secret::Es256(key) => PublicKey::Es256(*key.verifying_key()),
            Secret::EdDsa(key) => PublicKey::EdDsa(key.verifying_key()),
        }
    }

    /// Signs `message` as WebAuthn expects: an ASN.1 DER `Ecdsa-Sig-Value`
    /// for ES256 (SHA-256, RFC 6979 nonce), the 64-byte signature for EdDSA.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.0 {
            Secret::Es256(key) => {
                let signature: p256::ecdsa::DerSignature = key.sign(message);
                signature.as_bytes().to_vec()
            }
            Secret::EdDsa(key) => {
                let signature: ed25519_dalek::Signature = key.sign(message);
                signature.to_bytes().to_vec()
            }
        }
    }
}

/// The public key of a passkey, as a relying party receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// A P-256 point.
    Es256(p256::ecdsa::VerifyingKey),
    /// An Ed25519 key.
    EdDsa(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// The algorithm the key is for.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            PublicKey::Es256(_) => Algorithm::Es256,
            PublicKey::EdDsa(_) => Algorithm::EdDsa,
        }
    }

    /// The key as a COSE_Key (RFC 9052 §7), with its parameters in the
    /// canonical order of CTAP2, as it appears in the authenticator data.
    pub fn to_cose(&self) -> Vec<u8> {
        let mut cbor = Cbor::new();
        match self {
            PublicKey::Es256(key) => {
                let point = key.to_sec1_point(false);
                // 0x04 ‖ x ‖ y.
                let (x, y) = point.as_bytes()[1..].split_at(32);
                cbor.map(5)
                    .int(cose::KTY)
                    .int(cose::KTY_EC2)
                    .int(cose::ALG)
                    .int(Algorithm::Es256.cose().into())
                    .int(cose::CRV)
                    .int(cose::CRV_P256)
                    .int(cose::X)
                    .bytes(x)
                    .int(cose::Y)
                    .bytes(y);
            }
            PublicKey::EdDsa(key) => {
                cbor.map(4)
                    .int(cose::KTY)
                    .int(cose::KTY_OKP)
                    .int(cose::ALG)
                    .int(Algorithm::EdDsa.cose().into())
                    .int(cose::CRV)
                    .int(cose::CRV_ED25519)
                    .int(cose::X)
                    .bytes(key.as_bytes());
            }
        }
        cbor.finish()
    }

    /// The key as DER SubjectPublicKeyInfo, what the browser's
    /// `AuthenticatorAttestationResponse.getPublicKey()` returns.
    pub fn to_spki(&self) -> Vec<u8> {
        match self {
            PublicKey::Es256(key) => {
                let mut der = P256_SPKI_PREFIX.to_vec();
                der.extend_from_slice(key.to_sec1_point(false).as_bytes());
                der
            }
            PublicKey::EdDsa(key) => {
                let mut der = ED25519_SPKI_PREFIX.to_vec();
                der.extend_from_slice(key.as_bytes());
                der
            }
        }
    }

    /// Reads a key written by [`Self::to_spki`].
    pub fn from_spki(der: &[u8]) -> Result<Self, PasskeyError> {
        if let Some(point) = der.strip_prefix(P256_SPKI_PREFIX.as_slice()) {
            return p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map(PublicKey::Es256)
                .map_err(|_| PasskeyError::MalformedKey);
        }
        if let Some(key) = der.strip_prefix(ED25519_SPKI_PREFIX.as_slice()) {
            let key: &[u8; 32] = key.try_into().map_err(|_| PasskeyError::MalformedKey)?;
            return ed25519_dalek::VerifyingKey::from_bytes(key)
                .map(PublicKey::EdDsa)
                .map_err(|_| PasskeyError::MalformedKey);
        }
        Err(PasskeyError::MalformedKey)
    }

    /// Whether `signature`, in the form [`CredentialKey::sign`] makes, is a
    /// valid signature of `message` by this key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            PublicKey::Es256(key) => p256::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
            PublicKey::EdDsa(key) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify_strict(message, &signature).is_ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    const BOTH: [Algorithm; 2] = [Algorithm::Es256, Algorithm::EdDsa];

    #[test]
    fn the_first_supported_algorithm_of_the_relying_party_is_chosen() {
        assert_eq!(Algorithm::choose(&[]), Some(Algorithm::Es256));
        assert_eq!(Algorithm::choose(&[-8, -7, -257]), Some(Algorithm::EdDsa));
        assert_eq!(Algorithm::choose(&[-257, -7, -8]), Some(Algorithm::Es256));
        // RS256, ES384, ML-DSA: none of them.
        assert_eq!(Algorithm::choose(&[-257, -35, -48]), None);
        for algorithm in BOTH {
            assert_eq!(Algorithm::from_cose(algorithm.cose()), Some(algorithm));
        }
    }

    #[test]
    fn keys_sign_and_survive_their_stored_form() {
        for algorithm in BOTH {
            let key = CredentialKey::generate(algorithm).unwrap();
            assert_eq!(key.algorithm(), algorithm);
            let stored = key.to_pkcs8().unwrap();
            let back = CredentialKey::from_pkcs8(algorithm, &stored).unwrap();
            assert_eq!(back.public_key(), key.public_key());

            let message = b"authenticator data and client data hash";
            let signature = back.sign(message);
            let public = key.public_key();
            assert!(public.verify(message, &signature));
            assert!(!public.verify(b"another message", &signature));
            let mut forged = signature.clone();
            let last = forged.len() - 1;
            forged[last] ^= 1;
            assert!(!public.verify(message, &forged));

            // The relying party's form of the public key reads back.
            assert_eq!(PublicKey::from_spki(&public.to_spki()).unwrap(), public);
            // A key of one algorithm is not read as the other.
            let other = if algorithm == Algorithm::Es256 {
                Algorithm::EdDsa
            } else {
                Algorithm::Es256
            };
            assert!(matches!(
                CredentialKey::from_pkcs8(other, &stored),
                Err(PasskeyError::MalformedKey)
            ));
        }
        assert!(matches!(
            CredentialKey::from_pkcs8(Algorithm::Es256, b"not a key"),
            Err(PasskeyError::MalformedKey)
        ));
        assert!(PublicKey::from_spki(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn each_new_key_is_different() {
        for algorithm in BOTH {
            let a = CredentialKey::generate(algorithm).unwrap().public_key();
            let b = CredentialKey::generate(algorithm).unwrap().public_key();
            assert_ne!(a, b);
        }
    }

    /// The credential public key of the W3C test vector "ES256 Credential
    /// with No Attestation" (Web Authentication Level 3, §16.2), as it
    /// appears in that vector's attestation object.
    #[test]
    fn a_p256_public_key_is_written_as_the_w3c_vector_has_it() {
        let key = CredentialKey::from_raw(
            Algorithm::Es256,
            &unhex("6e68e7a58484a3264f66b77f5d6dc5bc36a47085b615c9727ab334e8c369c2ee"),
        )
        .unwrap();
        assert_eq!(
            hex(&key.public_key().to_cose()),
            "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
        );
        let spki = key.public_key().to_spki();
        assert_eq!(spki.len(), 91);
        assert!(hex(&spki).ends_with("04afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"));
    }

    #[test]
    fn an_ed25519_public_key_is_a_cose_okp_key() {
        let key = CredentialKey::from_raw(Algorithm::EdDsa, &[7; 32]).unwrap();
        let cose = key.public_key().to_cose();
        assert_eq!(hex(&cose[..10]), "a4010103272006215820");
        assert_eq!(&cose[10..], key.public_key().to_spki()[12..].to_vec());
        assert_eq!(cose.len(), 42);
    }

    #[test]
    fn a_key_never_prints_its_secret() {
        let key = CredentialKey::from_raw(Algorithm::EdDsa, &[0x42; 32]).unwrap();
        let printed = format!("{key:?}");
        assert_eq!(printed, "CredentialKey(EdDSA, <redacted>)");
        assert!(CredentialKey::from_raw(Algorithm::EdDsa, &[1; 31]).is_err());
        assert!(CredentialKey::from_raw(Algorithm::Es256, &[0; 32]).is_err());
    }
}
