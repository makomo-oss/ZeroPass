//! WebAuthn Level 2/3 conformance test vectors (`docs/spec/passkey.md` §4,
//! ADR-0010, P5-03).
//!
//! Verifies byte-exact `rpIdHash`, `clientDataJSON`, CTAP2 canonical CBOR
//! `COSE_Key`, `authenticatorData`, `"none"` `attestationObject`, low-S ASN.1
//! DER ES256 signatures, Ed25519 signatures, `signCount == 0`, and RP-side
//! verification against RFC 6979 (P-256) and RFC 8032 (Ed25519) test keys.

#![allow(clippy::unwrap_used, reason = "test vectors may panic on failure")]

use ciborium::Value;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use p256::ecdsa::signature::Verifier as _;
use zp_crypto::InsecureSoftwareKeyStore;
use zp_passkey::{
    AAGUID, ASSERTION_AUTH_DATA_LEN, Algorithm, COSE_ALG_EDDSA, COSE_ALG_ES256, CeremonyType,
    FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV, FLAGS_GET_ASSERTION, FLAGS_MAKE_CREDENTIAL,
    GetAssertionRequest, MakeCredentialRequest, PasskeyError, base64url_encode,
    build_assertion_auth_data, build_client_data_json, build_none_attestation_object,
    build_registration_auth_data, get_assertion, make_credential, public_key_from_pkcs8,
    rp_id_hash, verify_assertion,
};
use zp_vault::model::PasskeyCredential;
use zp_vault::{CreateOptions, KdfChoice, Vault};

const MASTER_PASSWORD: &str = "correct horse battery staple";

fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(clean.len() % 2, 0);
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vectors.zpvault");
    let hw = InsecureSoftwareKeyStore::generate().unwrap();
    let vault = Vault::create(
        &path,
        MASTER_PASSWORD,
        Some(&hw),
        CreateOptions {
            kdf: KdfChoice::Fixed(zp_crypto::KdfParams::MINIMUM),
            ..CreateOptions::default()
        },
    )
    .unwrap();
    (dir, vault)
}

/// Parses an `attestationObject`, verifies `"none"` format and canonical CBOR
/// map order, and returns `(auth_data, credential_id, cose_key_bytes)`.
fn parse_and_check_attestation(attestation_object: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let value: Value = ciborium::from_reader(attestation_object).unwrap();
    let Value::Map(entries) = value else {
        panic!("attestationObject is not a CBOR map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(k, _)| k.as_text().expect("text key"))
        .collect();
    // CTAP2 canonical CBOR order: length 3 ("fmt"), 7 ("attStmt"), 8 ("authData").
    assert_eq!(keys, ["fmt", "attStmt", "authData"]);
    assert_eq!(entries[0].1.as_text(), Some("none"));
    assert_eq!(entries[1].1.as_map().unwrap().len(), 0);
    let auth_data = entries[2].1.as_bytes().unwrap().clone();

    assert!(auth_data.len() > ASSERTION_AUTH_DATA_LEN + 18);
    assert_eq!(auth_data[32], FLAGS_MAKE_CREDENTIAL);
    assert_eq!(
        auth_data[32] & (FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT),
        FLAGS_MAKE_CREDENTIAL
    );
    assert_eq!(&auth_data[33..37], &[0, 0, 0, 0]);
    assert_eq!(&auth_data[37..53], &AAGUID);
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_id = auth_data[55..55 + cred_len].to_vec();
    let cose_key = auth_data[55 + cred_len..].to_vec();
    (auth_data, cred_id, cose_key)
}

#[test]
fn known_rpid_hash_and_client_data_json_vectors() {
    // W3C WebAuthn canonical example: SHA-256("example.com").
    assert_eq!(
        rp_id_hash("example.com").as_slice(),
        hex("a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947").as_slice()
    );

    // Base64url without padding across all remainder lengths and URL-safe alphabet (- and _).
    assert_eq!(base64url_encode(b""), "");
    assert_eq!(base64url_encode(b"f"), "Zg");
    assert_eq!(base64url_encode(b"fo"), "Zm8");
    assert_eq!(base64url_encode(b"foo"), "Zm9v");
    assert_eq!(base64url_encode(&[0xfb, 0xff, 0xfe]), "-__-");

    let challenge: Vec<u8> = (0u8..32).collect();
    let (json, hash) = build_client_data_json(
        CeremonyType::Create,
        &challenge,
        "https://webauthn.io",
        false,
    );
    assert_eq!(
        std::str::from_utf8(&json).unwrap(),
        r#"{"type":"webauthn.create","challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","origin":"https://webauthn.io","crossOrigin":false}"#
    );
    assert_eq!(hash.len(), 32);

    let (get_json, get_hash) =
        build_client_data_json(CeremonyType::Get, &challenge, "https://webauthn.io", false);
    assert!(
        std::str::from_utf8(&get_json)
            .unwrap()
            .starts_with(r#"{"type":"webauthn.get","#)
    );
    assert_ne!(hash, get_hash);
}

#[test]
fn rfc8032_ed25519_vector_matches_exact_cose_authdata_attestation_and_assertion() {
    // RFC 8032 §7.1 TEST 1 secret seed and expected public key.
    let seed: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .unwrap();
    let expected_pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pkcs8 = signing.to_pkcs8_der().unwrap();
    let pub_mat = public_key_from_pkcs8(Algorithm::EdDsa, pkcs8.as_bytes()).unwrap();

    // Exact CTAP2 canonical CBOR COSE_Key:
    // A4 (map 4), 01 01 (kty=OKP), 03 27 (alg=-8), 20 06 (crv=Ed25519), 21 58 20 <32B pub>
    let mut expected_cose = hex("a4 01 01 03 27 20 06 21 58 20");
    expected_cose.extend_from_slice(&expected_pub);
    assert_eq!(pub_mat.cose_key, expected_cose);

    // Exact registration authenticatorData (32 + 1 + 4 + 16 + 2 + 32 + 42 = 129 bytes).
    let cred_id = vec![0xAB; 32];
    let auth_data =
        build_registration_auth_data("example.com", &cred_id, &pub_mat.cose_key).unwrap();
    let mut expected_auth_data = Vec::new();
    expected_auth_data.extend_from_slice(&hex(
        "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947",
    ));
    expected_auth_data.push(0x5D); // UP | UV | BE | BS | AT
    expected_auth_data.extend_from_slice(&[0, 0, 0, 0]); // signCount = 0
    expected_auth_data.extend_from_slice(&AAGUID);
    expected_auth_data.extend_from_slice(&32u16.to_be_bytes());
    expected_auth_data.extend_from_slice(&cred_id);
    expected_auth_data.extend_from_slice(&expected_cose);
    assert_eq!(auth_data, expected_auth_data);
    assert_eq!(auth_data.len(), 129);

    // Exact CBOR attestationObject (fmt="none", attStmt={}, authData=bstr(129 = 0x81)).
    let attestation = build_none_attestation_object(&auth_data).unwrap();
    let mut expected_attestation =
        hex("a3 63 666d74 64 6e6f6e65 67 61747453746d74 a0 68 6175746844617461 58 81");
    expected_attestation.extend_from_slice(&expected_auth_data);
    assert_eq!(attestation, expected_attestation);

    // Store the deterministic RFC 8032 key in VK-K and run get_assertion.
    let (_dir, mut vault) = open_vault();
    vault
        .insert(PasskeyCredential {
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            user_handle: b"rfc8032-user".to_vec(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            credential_id: cred_id.clone(),
            private_key: pkcs8.as_bytes().to_vec(),
            cose_algorithm: COSE_ALG_EDDSA,
        })
        .unwrap();

    let (_json, client_data_hash) = build_client_data_json(
        CeremonyType::Get,
        b"test-challenge",
        "https://example.com",
        false,
    );
    let assertion = get_assertion(
        &mut vault,
        &GetAssertionRequest {
            rp_id: "example.com".into(),
            client_data_hash,
            allow_credential_ids: vec![cred_id.clone()],
            credential_id: None,
        },
    )
    .unwrap();

    assert_eq!(assertion.credential_id, cred_id);
    assert_eq!(assertion.user_handle, b"rfc8032-user");
    assert_eq!(
        assertion.authenticator_data,
        build_assertion_auth_data("example.com")
    );
    assert_eq!(assertion.authenticator_data[32], FLAGS_GET_ASSERTION);
    assert_eq!(&assertion.authenticator_data[33..37], &[0, 0, 0, 0]);
    assert_eq!(assertion.signature.len(), 64);

    // Independently verify with ed25519-dalek from raw RFC 8032 public key.
    let mut signed = Vec::with_capacity(ASSERTION_AUTH_DATA_LEN + 32);
    signed.extend_from_slice(&assertion.authenticator_data);
    signed.extend_from_slice(&client_data_hash);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&expected_pub.try_into().unwrap()).unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&assertion.signature).unwrap();
    vk.verify_strict(&signed, &sig).unwrap();
}

#[test]
fn rfc6979_p256_vector_matches_exact_cose_and_produces_low_s_der_assertion() {
    // RFC 6979 §A.2.5 NIST P-256 test private key and expected public coordinates.
    let d = hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let expected_x = hex("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    let expected_y = hex("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");

    let secret = p256::SecretKey::from_slice(&d).unwrap();
    let signing = p256::ecdsa::SigningKey::from(&secret);
    let pkcs8 = signing.to_pkcs8_der().unwrap();
    let pub_mat = public_key_from_pkcs8(Algorithm::Es256, pkcs8.as_bytes()).unwrap();

    // Exact CTAP2 canonical CBOR COSE_Key (77 bytes):
    // A5 (map 5), 01 02 (kty=EC2), 03 26 (alg=-7), 20 01 (crv=P-256), 21 58 20 <x>, 22 58 20 <y>
    let mut expected_cose = hex("a5 01 02 03 26 20 01 21 58 20");
    expected_cose.extend_from_slice(&expected_x);
    expected_cose.extend_from_slice(&hex("22 58 20"));
    expected_cose.extend_from_slice(&expected_y);
    assert_eq!(pub_mat.cose_key, expected_cose);
    assert_eq!(pub_mat.cose_key.len(), 77);

    let (_dir, mut vault) = open_vault();
    let cred_id = vec![0xCD; 32];
    vault
        .insert(PasskeyCredential {
            rp_id: "webauthn.io".into(),
            rp_name: "webauthn.io".into(),
            user_handle: b"rfc6979-user".to_vec(),
            user_name: "bob".into(),
            user_display_name: "Bob".into(),
            credential_id: cred_id.clone(),
            private_key: pkcs8.as_bytes().to_vec(),
            cose_algorithm: COSE_ALG_ES256,
        })
        .unwrap();

    let (_json, client_data_hash) = build_client_data_json(
        CeremonyType::Get,
        b"challenge-p256",
        "https://webauthn.io",
        false,
    );
    let assertion = get_assertion(
        &mut vault,
        &GetAssertionRequest {
            rp_id: "webauthn.io".into(),
            client_data_hash,
            allow_credential_ids: Vec::new(),
            credential_id: None,
        },
    )
    .unwrap();

    // Must be valid ASN.1 DER and low-S normalized.
    let der = p256::ecdsa::DerSignature::from_bytes(&assertion.signature).unwrap();
    let sig = p256::ecdsa::Signature::from_der(der.as_bytes()).unwrap();
    assert_eq!(sig, sig.normalize_s(), "ES256 signature must be low-S");

    // Reconstruct verifying key independently from expected (x, y) SEC1 uncompressed point.
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&expected_x);
    sec1.extend_from_slice(&expected_y);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let mut signed = Vec::with_capacity(ASSERTION_AUTH_DATA_LEN + 32);
    signed.extend_from_slice(&assertion.authenticator_data);
    signed.extend_from_slice(&client_data_hash);
    vk.verify(&signed, &der).unwrap();

    verify_assertion(
        "webauthn.io",
        Algorithm::Es256,
        &pub_mat.spki_der,
        &client_data_hash,
        &assertion.authenticator_data,
        &assertion.signature,
    )
    .unwrap();
}

#[test]
fn full_make_credential_and_get_assertion_round_trip_for_es256_and_eddsa() {
    let (_dir, mut vault) = open_vault();
    for (alg, rp_id, handle) in [
        (Algorithm::Es256, "es256.example", b"u-es256".as_slice()),
        (Algorithm::EdDsa, "eddsa.example", b"u-eddsa".as_slice()),
    ] {
        let (_, reg_hash) = build_client_data_json(
            CeremonyType::Create,
            b"reg-challenge",
            &format!("https://{rp_id}"),
            false,
        );
        let reg = make_credential(
            &mut vault,
            &MakeCredentialRequest {
                rp_id: rp_id.into(),
                rp_name: "Demo".into(),
                user_handle: handle.to_vec(),
                user_name: "alice".into(),
                user_display_name: "Alice".into(),
                algorithms: vec![alg.cose_id()],
                exclude_credential_ids: Vec::new(),
                client_data_hash: reg_hash,
            },
        )
        .unwrap();

        assert_eq!(reg.algorithm, alg);
        let (auth_data, cred_id, cose_key) = parse_and_check_attestation(&reg.attestation_object);
        assert_eq!(auth_data, reg.authenticator_data);
        assert_eq!(auth_data[..32], rp_id_hash(rp_id));
        assert_eq!(cred_id, reg.credential_id);
        assert_eq!(cose_key, reg.public_key.cose_key);

        // Multiple assertions all succeed and keep signCount == 0 (ADR-0010).
        for round in 0u8..3 {
            let (_, auth_hash) = build_client_data_json(
                CeremonyType::Get,
                &[round; 32],
                &format!("https://{rp_id}"),
                false,
            );
            let assertion = get_assertion(
                &mut vault,
                &GetAssertionRequest {
                    rp_id: rp_id.into(),
                    client_data_hash: auth_hash,
                    allow_credential_ids: Vec::new(),
                    credential_id: None,
                },
            )
            .unwrap();
            assert_eq!(assertion.credential_id, reg.credential_id);
            assert_eq!(assertion.user_handle, handle);
            assert_eq!(&assertion.authenticator_data[33..37], &[0, 0, 0, 0]);
            verify_assertion(
                rp_id,
                alg,
                &reg.public_key.spki_der,
                &auth_hash,
                &assertion.authenticator_data,
                &assertion.signature,
            )
            .unwrap();

            // Tampering with clientDataHash or RP ID fails verification.
            let mut wrong_hash = auth_hash;
            wrong_hash[0] ^= 0x80;
            assert!(matches!(
                verify_assertion(
                    rp_id,
                    alg,
                    &reg.public_key.spki_der,
                    &wrong_hash,
                    &assertion.authenticator_data,
                    &assertion.signature,
                ),
                Err(PasskeyError::InvalidSignature)
            ));
            assert!(matches!(
                verify_assertion(
                    "other.example",
                    alg,
                    &reg.public_key.spki_der,
                    &auth_hash,
                    &assertion.authenticator_data,
                    &assertion.signature,
                ),
                Err(PasskeyError::InvalidSignature)
            ));
        }
    }
}

#[test]
fn assertion_selection_allow_list_cross_rp_and_replacement_edge_cases() {
    let (_dir, mut vault) = open_vault();
    let reg = |vault: &mut Vault, rp: &str, handle: &[u8], name: &str| {
        make_credential(
            vault,
            &MakeCredentialRequest {
                rp_id: rp.into(),
                rp_name: rp.into(),
                user_handle: handle.to_vec(),
                user_name: name.into(),
                user_display_name: name.into(),
                algorithms: vec![COSE_ALG_ES256],
                exclude_credential_ids: Vec::new(),
                client_data_hash: [1u8; 32],
            },
        )
        .unwrap()
    };

    let alice = reg(&mut vault, "multi.example", b"alice", "alice");
    let bob = reg(&mut vault, "multi.example", b"bob", "bob");
    let hash = [2u8; 32];

    // Cross-RP lookup fails even if the credential ID is known.
    assert!(matches!(
        get_assertion(
            &mut vault,
            &GetAssertionRequest {
                rp_id: "other.example".into(),
                client_data_hash: hash,
                allow_credential_ids: Vec::new(),
                credential_id: Some(alice.credential_id.clone()),
            },
        ),
        Err(PasskeyError::CredentialNotFound)
    ));

    // Multiple matching credentials with no selection yields MultipleCredentials.
    assert!(matches!(
        get_assertion(
            &mut vault,
            &GetAssertionRequest {
                rp_id: "multi.example".into(),
                client_data_hash: hash,
                allow_credential_ids: Vec::new(),
                credential_id: None,
            },
        ),
        Err(PasskeyError::MultipleCredentials)
    ));

    // Selecting bob explicitly signs with bob's key.
    let bob_assert = get_assertion(
        &mut vault,
        &GetAssertionRequest {
            rp_id: "multi.example".into(),
            client_data_hash: hash,
            allow_credential_ids: Vec::new(),
            credential_id: Some(bob.credential_id.clone()),
        },
    )
    .unwrap();
    assert_eq!(bob_assert.user_handle, b"bob");
    verify_assertion(
        "multi.example",
        Algorithm::Es256,
        &bob.public_key.spki_der,
        &hash,
        &bob_assert.authenticator_data,
        &bob_assert.signature,
    )
    .unwrap();

    // Selecting alice when allowCredentials only allows bob must fail.
    assert!(matches!(
        get_assertion(
            &mut vault,
            &GetAssertionRequest {
                rp_id: "multi.example".into(),
                client_data_hash: hash,
                allow_credential_ids: vec![bob.credential_id.clone()],
                credential_id: Some(alice.credential_id.clone()),
            },
        ),
        Err(PasskeyError::CredentialNotFound)
    ));

    // allowCredentials narrowing to alice allows auto-selection.
    let alice_assert = get_assertion(
        &mut vault,
        &GetAssertionRequest {
            rp_id: "multi.example".into(),
            client_data_hash: hash,
            allow_credential_ids: vec![alice.credential_id.clone()],
            credential_id: None,
        },
    )
    .unwrap();
    assert_eq!(alice_assert.user_handle, b"alice");

    // Re-registering alice replaces her credential; old ID no longer works.
    let alice_v2 = reg(&mut vault, "multi.example", b"alice", "alice-v2");
    assert_eq!(alice_v2.item_id, alice.item_id);
    assert!(matches!(
        get_assertion(
            &mut vault,
            &GetAssertionRequest {
                rp_id: "multi.example".into(),
                client_data_hash: hash,
                allow_credential_ids: Vec::new(),
                credential_id: Some(alice.credential_id),
            },
        ),
        Err(PasskeyError::CredentialNotFound)
    ));
    let alice_v2_assert = get_assertion(
        &mut vault,
        &GetAssertionRequest {
            rp_id: "multi.example".into(),
            client_data_hash: hash,
            allow_credential_ids: Vec::new(),
            credential_id: Some(alice_v2.credential_id),
        },
    )
    .unwrap();
    verify_assertion(
        "multi.example",
        Algorithm::Es256,
        &alice_v2.public_key.spki_der,
        &hash,
        &alice_v2_assert.authenticator_data,
        &alice_v2_assert.signature,
    )
    .unwrap();
}
