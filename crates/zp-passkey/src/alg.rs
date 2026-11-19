//! Supported WebAuthn signature algorithms, key generation, COSE / SPKI public
//! key encoding, and raw signing (`docs/spec/passkey.md` §2.1, ADR-0010).

use core::fmt;

use ciborium::Value;
use ed25519_dalek::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _,
};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use zeroize::Zeroizing;

use crate::PasskeyError;

/// COSE algorithm identifier for ECDSA w/ SHA-256 over P-256.
pub const COSE_ALG_ES256: i32 = -7;

/// COSE algorithm identifier for EdDSA (Ed25519).
pub const COSE_ALG_EDDSA: i32 = -8;

/// Supported WebAuthn / COSE signature algorithms (ADR-0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ECDSA with SHA-256 on NIST P-256 (COSE `-7`).
    Es256,
    /// EdDSA on Ed25519 (COSE `-8`).
    EdDsa,
}

impl Algorithm {
    /// Parses a COSE algorithm identifier.
    pub const fn from_cose(alg: i32) -> Option<Self> {
        match alg {
            COSE_ALG_ES256 => Some(Self::Es256),
            COSE_ALG_EDDSA => Some(Self::EdDsa),
            _ => None,
        }
    }

    /// The COSE algorithm identifier.
    pub const fn cose_id(self) -> i32 {
        match self {
            Self::Es256 => COSE_ALG_ES256,
            Self::EdDsa => COSE_ALG_EDDSA,
        }
    }

    /// Picks the first supported algorithm from the relying party's preference
    /// list (`pubKeyCredParams`).
    pub fn select(preferred: &[i32]) -> Result<Self, PasskeyError> {
        preferred
            .iter()
            .copied()
            .find_map(Self::from_cose)
            .ok_or(PasskeyError::UnsupportedAlgorithm)
    }
}

/// Public representations of a passkey's verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyMaterial {
    /// Canonical CBOR-encoded COSE_Key (for `attestedCredentialData`).
    pub cose_key: Vec<u8>,
    /// SubjectPublicKeyInfo DER (for WebAuthn L3 `getPublicKey()`).
    pub spki_der: Vec<u8>,
}

/// A freshly generated passkey key pair. Private key bytes are wiped on drop
/// and hidden from `Debug`.
pub struct GeneratedKeyPair {
    /// Selected algorithm.
    pub algorithm: Algorithm,
    /// Private key in PKCS #8 DER format.
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
    /// Encoded public key material.
    pub public_key: PublicKeyMaterial,
}

impl fmt::Debug for GeneratedKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedKeyPair")
            .field("algorithm", &self.algorithm)
            .field("private_key_pkcs8", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Generates a new passkey key pair using the OS CSPRNG (`getrandom`).
pub fn generate_keypair(algorithm: Algorithm) -> Result<GeneratedKeyPair, PasskeyError> {
    match algorithm {
        Algorithm::Es256 => {
            // Rejection sampling from 32 OS-random bytes until a valid non-zero
            // scalar < n is obtained (succeeds on the first attempt with
            // probability > 1 - 2^-32).
            let secret = loop {
                let mut raw = Zeroizing::new([0u8; 32]);
                getrandom::fill(raw.as_mut()).map_err(|_| PasskeyError::Rng)?;
                if let Ok(key) = p256::SecretKey::from_slice(raw.as_slice()) {
                    break key;
                }
            };
            let signing = p256::ecdsa::SigningKey::from(&secret);
            let verifying = signing.verifying_key();
            let pkcs8 = signing
                .to_pkcs8_der()
                .map_err(|_| PasskeyError::MalformedKey)?;
            let public_key = p256_public_material(verifying)?;
            Ok(GeneratedKeyPair {
                algorithm,
                private_key_pkcs8: Zeroizing::new(pkcs8.as_bytes().to_vec()),
                public_key,
            })
        }
        Algorithm::EdDsa => {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut()).map_err(|_| PasskeyError::Rng)?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            let verifying = signing.verifying_key();
            let pkcs8 = signing
                .to_pkcs8_der()
                .map_err(|_| PasskeyError::MalformedKey)?;
            let public_key = ed25519_public_material(&verifying)?;
            Ok(GeneratedKeyPair {
                algorithm,
                private_key_pkcs8: Zeroizing::new(pkcs8.as_bytes().to_vec()),
                public_key,
            })
        }
    }
}

/// Derives the public key representations from a stored PKCS #8 DER private key.
pub fn public_key_from_pkcs8(
    algorithm: Algorithm,
    pkcs8_der: &[u8],
) -> Result<PublicKeyMaterial, PasskeyError> {
    match algorithm {
        Algorithm::Es256 => {
            let signing = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|_| PasskeyError::MalformedKey)?;
            p256_public_material(signing.verifying_key())
        }
        Algorithm::EdDsa => {
            let signing = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|_| PasskeyError::MalformedKey)?;
            ed25519_public_material(&signing.verifying_key())
        }
    }
}

/// Signs `data` with a stored PKCS #8 DER private key.
///
/// - `Es256`: signs `SHA-256(data)` with P-256 ECDSA, low-S normalized, encoded
///   as ASN.1 DER (the WebAuthn wire format).
/// - `EdDsa`: signs `data` with Ed25519 (raw 64-byte signature).
#[allow(dead_code, reason = "used by getAssertion in P5-03")]
pub(crate) fn sign_raw(
    algorithm: Algorithm,
    pkcs8_der: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, PasskeyError> {
    match algorithm {
        Algorithm::Es256 => {
            let signing = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|_| PasskeyError::MalformedKey)?;
            let signature: p256::ecdsa::Signature = signing.sign(data);
            let normalized = signature.normalize_s();
            Ok(normalized.to_der().as_bytes().to_vec())
        }
        Algorithm::EdDsa => {
            let signing = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|_| PasskeyError::MalformedKey)?;
            let signature: ed25519_dalek::Signature = signing.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
    }
}

/// Verifies `signature` over `data` against a SubjectPublicKeyInfo DER public key.
pub fn verify_raw(
    algorithm: Algorithm,
    spki_der: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), PasskeyError> {
    match algorithm {
        Algorithm::Es256 => {
            let verifying = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                .map_err(|_| PasskeyError::MalformedKey)?;
            let der = p256::ecdsa::DerSignature::from_bytes(signature)
                .map_err(|_| PasskeyError::InvalidSignature)?;
            verifying
                .verify(data, &der)
                .map_err(|_| PasskeyError::InvalidSignature)
        }
        Algorithm::EdDsa => {
            let verifying = ed25519_dalek::VerifyingKey::from_public_key_der(spki_der)
                .map_err(|_| PasskeyError::MalformedKey)?;
            let sig = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|_| PasskeyError::InvalidSignature)?;
            verifying
                .verify(data, &sig)
                .map_err(|_| PasskeyError::InvalidSignature)
        }
    }
}

/// Encodes a P-256 verifying key as canonical COSE_Key CBOR and SPKI DER.
fn p256_public_material(
    verifying: &p256::ecdsa::VerifyingKey,
) -> Result<PublicKeyMaterial, PasskeyError> {
    let encoded = verifying.to_sec1_point(false);
    let x = encoded.x().ok_or(PasskeyError::MalformedKey)?;
    let y = encoded.y().ok_or(PasskeyError::MalformedKey)?;
    // CTAP2 canonical CBOR key order: 1 (0x01), 3 (0x03), -1 (0x20), -2 (0x21), -3 (0x22).
    let cose_map = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (
            Value::Integer(3.into()),
            Value::Integer(COSE_ALG_ES256.into()),
        ), // alg: ES256 (-7)
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())), // x (32 bytes)
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())), // y (32 bytes)
    ]);
    let cose_key = encode_cbor(&cose_map)?;
    let spki = verifying
        .to_public_key_der()
        .map_err(|_| PasskeyError::MalformedKey)?;
    Ok(PublicKeyMaterial {
        cose_key,
        spki_der: spki.as_bytes().to_vec(),
    })
}

/// Encodes an Ed25519 verifying key as canonical COSE_Key CBOR and SPKI DER.
fn ed25519_public_material(
    verifying: &ed25519_dalek::VerifyingKey,
) -> Result<PublicKeyMaterial, PasskeyError> {
    // CTAP2 canonical CBOR key order: 1 (0x01), 3 (0x03), -1 (0x20), -2 (0x21).
    let cose_map = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())), // kty: OKP
        (
            Value::Integer(3.into()),
            Value::Integer(COSE_ALG_EDDSA.into()),
        ), // alg: EdDSA (-8)
        (Value::Integer((-1).into()), Value::Integer(6.into())), // crv: Ed25519
        (
            Value::Integer((-2).into()),
            Value::Bytes(verifying.as_bytes().to_vec()),
        ), // x (32 bytes)
    ]);
    let cose_key = encode_cbor(&cose_map)?;
    let spki = verifying
        .to_public_key_der()
        .map_err(|_| PasskeyError::MalformedKey)?;
    Ok(PublicKeyMaterial {
        cose_key,
        spki_der: spki.as_bytes().to_vec(),
    })
}

/// Encodes a `ciborium::Value` into CBOR bytes.
pub(crate) fn encode_cbor(value: &Value) -> Result<Vec<u8>, PasskeyError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|_| PasskeyError::Cbor)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may panic on setup errors")]

    use super::*;

    #[test]
    fn algorithm_selection_honours_rp_preference_and_rejects_unsupported() {
        assert_eq!(Algorithm::select(&[-7, -8]).unwrap(), Algorithm::Es256);
        assert_eq!(
            Algorithm::select(&[-257, -8, -7]).unwrap(),
            Algorithm::EdDsa
        );
        assert!(matches!(
            Algorithm::select(&[-257, -37]),
            Err(PasskeyError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            Algorithm::select(&[]),
            Err(PasskeyError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn es256_and_eddsa_keypairs_round_trip_sign_and_verify() {
        for alg in [Algorithm::Es256, Algorithm::EdDsa] {
            let pair = generate_keypair(alg).unwrap();
            let derived = public_key_from_pkcs8(alg, &pair.private_key_pkcs8).unwrap();
            assert_eq!(derived, pair.public_key);

            // Debug must never reveal private key bytes.
            let rendered = format!("{pair:?}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
            assert!(
                !rendered.contains(&format!("{:?}", &pair.private_key_pkcs8[..8])),
                "{rendered}"
            );

            let message = b"webauthn-authenticator-data-plus-client-data-hash";
            let sig = sign_raw(alg, &pair.private_key_pkcs8, message).unwrap();
            verify_raw(alg, &pair.public_key.spki_der, message, &sig).unwrap();

            // Tampering with the message or signature must fail verification.
            let mut tampered_msg = message.to_vec();
            tampered_msg[0] ^= 0x01;
            assert!(matches!(
                verify_raw(alg, &pair.public_key.spki_der, &tampered_msg, &sig),
                Err(PasskeyError::InvalidSignature)
            ));
            let mut tampered_sig = sig.clone();
            let last = tampered_sig.len() - 1;
            tampered_sig[last] ^= 0x01;
            assert!(matches!(
                verify_raw(alg, &pair.public_key.spki_der, message, &tampered_sig),
                Err(PasskeyError::InvalidSignature)
            ));

            if alg == Algorithm::EdDsa {
                assert_eq!(sig.len(), 64);
            } else {
                // ASN.1 DER SEQUENCE starts with 0x30.
                assert_eq!(sig[0], 0x30);
            }
        }
    }

    #[test]
    fn cose_keys_follow_ctap2_canonical_cbor_order() {
        let es = generate_keypair(Algorithm::Es256).unwrap();
        // Map of 5 entries: 0xA5, then keys 1 (0x01), 3 (0x03), -1 (0x20), -2 (0x21), -3 (0x22).
        assert_eq!(es.public_key.cose_key[0], 0xA5);
        let decoded: Value = ciborium::from_reader(es.public_key.cose_key.as_slice()).unwrap();
        let Value::Map(entries) = decoded else {
            panic!("not a CBOR map");
        };
        let keys: Vec<i128> = entries
            .iter()
            .map(|(k, _)| i128::from(k.as_integer().unwrap()))
            .collect();
        assert_eq!(keys, [1, 3, -1, -2, -3]);
        assert_eq!(entries[3].1.as_bytes().unwrap().len(), 32);
        assert_eq!(entries[4].1.as_bytes().unwrap().len(), 32);

        let ed = generate_keypair(Algorithm::EdDsa).unwrap();
        assert_eq!(ed.public_key.cose_key[0], 0xA4);
        let decoded: Value = ciborium::from_reader(ed.public_key.cose_key.as_slice()).unwrap();
        let Value::Map(entries) = decoded else {
            panic!("not a CBOR map");
        };
        let keys: Vec<i128> = entries
            .iter()
            .map(|(k, _)| i128::from(k.as_integer().unwrap()))
            .collect();
        assert_eq!(keys, [1, 3, -1, -2]);
        assert_eq!(entries[3].1.as_bytes().unwrap().len(), 32);
    }

    #[test]
    fn malformed_pkcs8_and_mismatched_algorithm_are_rejected() {
        let es = generate_keypair(Algorithm::Es256).unwrap();
        assert!(matches!(
            public_key_from_pkcs8(Algorithm::EdDsa, &es.private_key_pkcs8),
            Err(PasskeyError::MalformedKey)
        ));
        assert!(matches!(
            public_key_from_pkcs8(Algorithm::Es256, b"not-der"),
            Err(PasskeyError::MalformedKey)
        ));
    }
}
