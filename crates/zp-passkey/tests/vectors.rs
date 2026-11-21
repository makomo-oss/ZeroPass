//! The W3C test vectors of Web Authentication Level 3, §16
//! (`tests/vectors/webauthn-l3.txt`): with the vector's key, credential
//! identifier, AAGUID and flags, the authenticator data, the attestation
//! object and the signature come out byte for byte as published (ECDSA with
//! RFC 6979 nonces and Ed25519 are deterministic), and so does the client
//! data where the vector has no extra members.

#![allow(clippy::unwrap_used, reason = "test code may panic")]

use std::collections::BTreeMap;

use zp_passkey::authenticator::{
    Attested, attestation_object, authenticator_data, flags, rp_id_hash, sign, verify,
};
use zp_passkey::client::{Ceremony, client_data_json};
use zp_passkey::{Algorithm, CredentialKey};

const RP_ID: &str = "example.org";
const ORIGIN: &str = "https://example.org";
const TOP_ORIGIN: &str = "https://example.com";

struct Vector {
    name: String,
    values: BTreeMap<String, String>,
}

impl Vector {
    fn text(&self, key: &str) -> &str {
        self.values
            .get(key)
            .unwrap_or_else(|| panic!("{}: no {key}", self.name))
    }

    fn bytes(&self, key: &str) -> Vec<u8> {
        unhex(self.text(key))
    }

    fn algorithm(&self) -> Algorithm {
        match self.text("algorithm") {
            "ES256" => Algorithm::Es256,
            "EdDSA" => Algorithm::EdDsa,
            other => panic!("{other}"),
        }
    }

    fn key(&self) -> CredentialKey {
        let raw = self
            .values
            .get("credential_private_key")
            .or_else(|| self.values.get("private_key"))
            .unwrap();
        CredentialKey::from_raw(self.algorithm(), &unhex(raw)).unwrap()
    }

    /// Whether the generator added `extraData` to the client data, which a
    /// client does not; only the others are compared.
    fn plain_client_data(&self, prefix: &str) -> bool {
        u8::from_str_radix(self.text(&format!("{prefix}client_data_gen_flags")), 16).unwrap() & 1
            == 0
    }

    /// Whether the client data names a top origin (the "topOrigin" vector).
    fn top_origin(&self) -> Option<&'static str> {
        self.name.ends_with("topOrigin").then_some(TOP_ORIGIN)
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "{text}");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn vectors() -> Vec<Vector> {
    let file = include_str!("vectors/webauthn-l3.txt");
    let mut vectors: Vec<Vector> = Vec::new();
    for line in file.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            vectors.push(Vector {
                name: name.to_owned(),
                values: BTreeMap::new(),
            });
            continue;
        }
        let (key, value) = line.split_once(" = ").unwrap();
        vectors
            .last_mut()
            .unwrap()
            .values
            .insert(key.to_owned(), value.to_owned());
    }
    assert_eq!(vectors.len(), 5);
    vectors
}

/// The authenticator data inside a vector's attestation object, and its flags.
fn attested_flags(vector: &Vector) -> u8 {
    let object = vector.bytes("attestationObject");
    let hash = rp_id_hash(RP_ID);
    let at = object
        .windows(32)
        .position(|window| window == hash)
        .unwrap_or_else(|| panic!("{}: no RP ID hash", vector.name));
    object[at + 32]
}

#[test]
fn registrations_are_reproduced_byte_for_byte() {
    for vector in vectors() {
        let key = vector.key();
        let cose = key.public_key().to_cose();
        let aaguid: [u8; 16] = vector.bytes("aaguid").try_into().unwrap();
        let credential_id = vector.bytes("credential_id");
        let bits = attested_flags(&vector);
        assert_eq!(
            bits & (flags::UP | flags::AT),
            flags::UP | flags::AT,
            "{}",
            vector.name
        );
        let data = authenticator_data(
            RP_ID,
            bits,
            0,
            Some(Attested {
                aaguid: &aaguid,
                credential_id: &credential_id,
                public_key: &cose,
            }),
        );
        let object = vector.bytes("attestationObject");
        if vector.name.starts_with("none.") {
            assert_eq!(attestation_object(&data), object, "{}", vector.name);
        } else {
            // Packed attestation: the statement is not ZeroPass's to make,
            // but the authenticator data in it is.
            assert!(
                object.windows(data.len()).any(|window| window == data),
                "{}",
                vector.name
            );
        }
        if vector.plain_client_data("") {
            let json = client_data_json(
                Ceremony::Create,
                &vector.bytes("challenge"),
                ORIGIN,
                vector.top_origin(),
            );
            assert_eq!(json, vector.bytes("clientDataJSON"), "{}", vector.name);
        }
    }
}

#[test]
fn assertions_are_reproduced_byte_for_byte() {
    let mut compared_client_data = 0;
    for vector in vectors() {
        let key = vector.key();
        let expected = vector.bytes("assert.authenticatorData");
        let data = authenticator_data(RP_ID, expected[32], 0, None);
        assert_eq!(data, expected, "{}", vector.name);
        assert_eq!(&data[33..], [0; 4], "the counter is 0");

        let client_data = vector.bytes("assert.clientDataJSON");
        let signature = sign(&key, &data, &client_data);
        assert_eq!(
            signature,
            vector.bytes("assert.signature"),
            "{}",
            vector.name
        );
        let spki = key.public_key().to_spki();
        assert!(verify(&spki, &data, &client_data, &signature));
        assert!(!verify(&spki, &data, b"{}", &signature));

        if vector.plain_client_data("assert.") {
            let json = client_data_json(
                Ceremony::Get,
                &vector.bytes("assert.challenge"),
                ORIGIN,
                vector.top_origin(),
            );
            assert_eq!(json, client_data, "{}", vector.name);
            compared_client_data += 1;
        }
    }
    assert!(compared_client_data >= 2);
}
