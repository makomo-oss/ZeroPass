//! Registration and authentication against a real vault file, checked as a
//! relying party would check them.

#![allow(clippy::unwrap_used, reason = "test code may panic")]

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams};
use zp_passkey::authenticator::{flags, rp_id_hash, verify};
use zp_passkey::{
    AAGUID, Algorithm, CreateRequest, GetOutcome, GetRequest, PasskeyError, Registration,
    get_assertion, make_credential,
};
use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError};

const PASSWORD: &str = "correct horse battery staple";
const ORIGIN: &str = "https://login.example.com";

fn vault(dir: &tempfile::TempDir) -> (Vault, InsecureSoftwareKeyStore) {
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: None,
    };
    let vault = Vault::create(
        &dir.path().join("vault.zpvault"),
        PASSWORD,
        Some(&hardware),
        options,
    )
    .unwrap();
    (vault, hardware)
}

fn create<'a>(user: &'a [u8], name: &'a str, algorithms: &'a [i32]) -> CreateRequest<'a> {
    CreateRequest {
        origin: ORIGIN,
        top_origin: "",
        rp_id: "example.com",
        rp_name: "Example",
        user_handle: user,
        user_name: name,
        user_display_name: name,
        challenge: b"a challenge of the relying party",
        algorithms,
        exclude: &[],
    }
}

fn get<'a>(challenge: &'a [u8], allow: &'a [Vec<u8>]) -> GetRequest<'a> {
    GetRequest {
        origin: ORIGIN,
        top_origin: "",
        rp_id: "example.com",
        challenge,
        allow,
        chosen: None,
    }
}

/// What a relying party checks of a registration (WebAuthn §7.1, the parts
/// that concern the authenticator and the client).
fn check_registration(registration: &Registration, challenge: &[u8]) {
    let client_data = String::from_utf8(registration.client_data_json.clone()).unwrap();
    assert!(client_data.starts_with(r#"{"type":"webauthn.create","challenge":""#));
    assert!(
        client_data.ends_with(r#"","origin":"https://login.example.com","crossOrigin":false}"#)
    );
    assert!(client_data.contains(&zp_passkey::client::base64url(challenge)));

    let data = &registration.authenticator_data;
    assert_eq!(&data[..32], rp_id_hash("example.com"));
    let bits = data[32];
    assert_eq!(
        bits,
        flags::UP | flags::UV | flags::BE | flags::AT,
        "one device: not backed up"
    );
    assert_eq!(&data[33..37], [0; 4], "the counter is 0");
    assert_eq!(&data[37..53], AAGUID);
    let length = usize::from(u16::from_be_bytes([data[53], data[54]]));
    assert_eq!(
        &data[55..55 + length],
        registration.credential_id.as_slice()
    );
    assert!(data.len() > 55 + length, "the public key follows");

    // {"fmt": "none", "attStmt": {}, "authData": <data>}.
    let object = &registration.attestation_object;
    assert!(object.starts_with(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData"));
    assert!(object.ends_with(data));
}

#[test]
fn a_credential_is_made_and_signs_for_its_relying_party() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = vault(&dir);
    let challenge = b"a challenge of the relying party";
    for (algorithms, expected) in [
        (&[-7][..], Algorithm::Es256),
        (&[-8, -7][..], Algorithm::EdDsa),
    ] {
        let user = [expected.cose() as u8; 8];
        let registration =
            make_credential(&mut vault, &create(&user, "alice", algorithms)).unwrap();
        assert_eq!(registration.algorithm, expected);
        check_registration(&registration, challenge);

        let allow = [registration.credential_id.clone()];
        let GetOutcome::Signed(assertion) =
            get_assertion(&mut vault, &get(b"sign in, please", &allow)).unwrap()
        else {
            panic!("one credential: no choice");
        };
        assert_eq!(assertion.credential_id, registration.credential_id);
        assert_eq!(assertion.user_handle, user);
        assert_eq!(
            &assertion.authenticator_data[..32],
            rp_id_hash("example.com")
        );
        assert_eq!(
            assertion.authenticator_data[32],
            flags::UP | flags::UV | flags::BE
        );
        assert_eq!(assertion.authenticator_data.len(), 37);
        let client_data = String::from_utf8(assertion.client_data_json.clone()).unwrap();
        assert!(client_data.starts_with(r#"{"type":"webauthn.get""#));
        assert!(verify(
            &registration.public_key,
            &assertion.authenticator_data,
            &assertion.client_data_json,
            &assertion.signature
        ));
        // The signature covers the client data.
        assert!(!verify(
            &registration.public_key,
            &assertion.authenticator_data,
            br#"{"type":"webauthn.get","challenge":"AA","origin":"https://login.example.com","crossOrigin":false}"#,
            &assertion.signature
        ));
    }
}

#[test]
fn several_accounts_let_the_user_choose() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = vault(&dir);
    let bob = make_credential(&mut vault, &create(b"bob", "bob", &[])).unwrap();
    let alice = make_credential(&mut vault, &create(b"alice", "alice", &[])).unwrap();

    let GetOutcome::Choose(choices) = get_assertion(&mut vault, &get(b"challenge", &[])).unwrap()
    else {
        panic!("two accounts: a choice");
    };
    let names: Vec<&str> = choices
        .iter()
        .map(|choice| choice.user_name.as_str())
        .collect();
    assert_eq!(names, ["alice", "bob"]);
    assert_eq!(choices[1].credential_id, bob.credential_id);

    let picked = GetRequest {
        chosen: Some(&bob.credential_id),
        ..get(b"challenge", &[])
    };
    let GetOutcome::Signed(assertion) = get_assertion(&mut vault, &picked).unwrap() else {
        panic!("picked");
    };
    assert_eq!(assertion.user_handle, b"bob");
    assert!(verify(
        &bob.public_key,
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature
    ));
    // The relying party's list narrows it down to one: no choice.
    let allow = [alice.credential_id.clone()];
    assert!(matches!(
        get_assertion(&mut vault, &get(b"challenge", &allow)).unwrap(),
        GetOutcome::Signed(assertion) if assertion.user_handle == b"alice"
    ));
    // A pick outside the list is no credential.
    let outside = GetRequest {
        chosen: Some(&bob.credential_id),
        ..get(b"challenge", &allow)
    };
    assert!(matches!(
        get_assertion(&mut vault, &outside),
        Err(PasskeyError::NoCredential)
    ));
}

#[test]
fn excluded_credentials_and_other_sites_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = vault(&dir);
    let alice = make_credential(&mut vault, &create(b"alice", "alice", &[])).unwrap();
    let exclude = [alice.credential_id.clone()];
    let again = CreateRequest {
        exclude: &exclude,
        ..create(b"alice-2", "alice", &[])
    };
    assert!(matches!(
        make_credential(&mut vault, &again),
        Err(PasskeyError::Excluded)
    ));

    // A phishing page: its own relying party has no credential, and it may
    // not name the one it imitates.
    let phishing = GetRequest {
        origin: "https://example.com.evil.net",
        rp_id: "",
        ..get(b"challenge", &[])
    };
    assert!(matches!(
        get_assertion(&mut vault, &phishing),
        Err(PasskeyError::NoCredential)
    ));
    let impersonating = GetRequest {
        origin: "https://example.com.evil.net",
        ..get(b"challenge", &[])
    };
    assert!(matches!(
        get_assertion(&mut vault, &impersonating),
        Err(PasskeyError::BadRelyingParty)
    ));
    // A frame of another site, an insecure page.
    let framed = GetRequest {
        top_origin: "https://evil.net",
        ..get(b"challenge", &[])
    };
    assert!(matches!(
        get_assertion(&mut vault, &framed),
        Err(PasskeyError::CrossSite)
    ));
    let insecure = GetRequest {
        origin: "http://login.example.com",
        ..get(b"challenge", &[])
    };
    assert!(matches!(
        get_assertion(&mut vault, &insecure),
        Err(PasskeyError::BadRelyingParty)
    ));
    // No supported algorithm.
    assert!(matches!(
        make_credential(&mut vault, &create(b"carol", "carol", &[-257])),
        Err(PasskeyError::UnsupportedAlgorithm)
    ));
    // A frame of the same site is fine, and says so in the client data.
    let same_site = GetRequest {
        top_origin: "https://www.example.com",
        ..get(b"challenge", &[])
    };
    let GetOutcome::Signed(assertion) = get_assertion(&mut vault, &same_site).unwrap() else {
        panic!("one credential");
    };
    assert!(
        String::from_utf8(assertion.client_data_json)
            .unwrap()
            .ends_with(r#""crossOrigin":true,"topOrigin":"https://www.example.com"}"#)
    );
}

#[test]
fn a_locked_passkey_domain_makes_and_signs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, hardware) = vault(&dir);
    make_credential(&mut vault, &create(b"alice", "alice", &[])).unwrap();
    vault.lock(DomainId::Passkey);
    let locked = |error: Option<PasskeyError>| {
        matches!(
            error,
            Some(PasskeyError::Vault(VaultError::Locked(DomainId::Passkey)))
        )
    };
    assert!(locked(
        get_assertion(&mut vault, &get(b"challenge", &[])).err()
    ));
    assert!(locked(
        make_credential(&mut vault, &create(b"bob", "bob", &[])).err()
    ));
    vault
        .unlock_hardware::<zp_crypto::Passkey>(&hardware)
        .unwrap();
    assert!(get_assertion(&mut vault, &get(b"challenge", &[])).is_ok());
}
