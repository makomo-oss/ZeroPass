//! Passkeys kept in a real vault file: in the passkey domain only, found by
//! relying party, replaced per account, and never on disk in the clear.

#![allow(clippy::unwrap_used, reason = "test code may panic")]

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams, Passkey};
use zp_passkey::{Account, Algorithm, PasskeyError, find, key_of, new_credential, save};
use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError};

const PASSWORD: &str = "correct horse battery staple";

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    hardware: InsecureSoftwareKeyStore,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            path: dir.path().join("vault.zpvault"),
            _dir: dir,
            hardware: InsecureSoftwareKeyStore::generate().unwrap(),
        }
    }

    fn create(&self) -> Vault {
        let options = CreateOptions {
            kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
            clock: None,
            device_name: None,
        };
        Vault::create(&self.path, PASSWORD, Some(&self.hardware), options).unwrap()
    }
}

fn account<'a>(rp_id: &'a str, user_handle: &'a [u8], user_name: &'a str) -> Account<'a> {
    Account {
        rp_id,
        rp_name: "Example",
        user_handle,
        user_name,
        user_display_name: "Alice Example",
    }
}

#[test]
fn credentials_are_kept_per_relying_party_and_account() {
    let fixture = Fixture::new();
    let mut vault = fixture.create();

    let (first, key) =
        new_credential(&account("example.com", b"alice", "alice"), Algorithm::Es256).unwrap();
    assert_eq!(first.credential_id.len(), 16);
    assert_eq!(first.cose_algorithm, -7);
    let first_id = first.credential_id.clone();
    let item = save(&mut vault, first).unwrap();
    assert_eq!(vault.item_domain(item).unwrap(), Some(DomainId::Passkey));

    let (bob, _) =
        new_credential(&account("example.com", b"bob", "bob"), Algorithm::EdDsa).unwrap();
    let bob_id = bob.credential_id.clone();
    save(&mut vault, bob).unwrap();
    let (elsewhere, _) = new_credential(
        &account("other.example", b"alice", "alice"),
        Algorithm::Es256,
    )
    .unwrap();
    save(&mut vault, elsewhere).unwrap();

    // Discoverable: all of the relying party's, by account name.
    let found = find(&mut vault, "example.com", &[]).unwrap();
    let names: Vec<&str> = found.iter().map(|(_, c)| c.user_name.as_str()).collect();
    assert_eq!(names, ["alice", "bob"]);
    // The stored key is the one that was made.
    let stored = key_of(&found[0].1).unwrap();
    assert_eq!(stored.public_key(), key.public_key());
    // Narrowed to the identifiers the relying party allows.
    let allowed = find(
        &mut vault,
        "example.com",
        &[bob_id.clone(), b"unknown".to_vec()],
    )
    .unwrap();
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0].1.credential_id, bob_id);
    // Another relying party's credential is never offered, even by identifier.
    assert!(find(&mut vault, "example.net", &[]).unwrap().is_empty());
    assert!(
        find(&mut vault, "other.example", std::slice::from_ref(&first_id))
            .unwrap()
            .is_empty()
    );

    // A new credential for the same account replaces the old one.
    let (again, _) =
        new_credential(&account("example.com", b"alice", "alice"), Algorithm::EdDsa).unwrap();
    let again_id = again.credential_id.clone();
    assert_eq!(save(&mut vault, again).unwrap(), item);
    let found = find(&mut vault, "example.com", &[]).unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.iter().any(|(_, c)| c.credential_id == again_id));
    assert!(!found.iter().any(|(_, c)| c.credential_id == first_id));
}

#[test]
fn the_passkey_domain_must_be_unlocked_and_the_password_does_not_open_it() {
    let fixture = Fixture::new();
    let mut vault = fixture.create();
    let (credential, _) =
        new_credential(&account("example.com", b"alice", "alice"), Algorithm::Es256).unwrap();
    save(&mut vault, credential).unwrap();

    vault.lock_all();
    vault.unlock_password(PASSWORD).unwrap();
    let locked = |error: Option<PasskeyError>| {
        matches!(
            error,
            Some(PasskeyError::Vault(VaultError::Locked(DomainId::Passkey)))
        )
    };
    assert!(locked(find(&mut vault, "example.com", &[]).err()));
    let (other, _) =
        new_credential(&account("example.com", b"bob", "bob"), Algorithm::Es256).unwrap();
    assert!(locked(save(&mut vault, other).err()));

    vault.unlock_hardware::<Passkey>(&fixture.hardware).unwrap();
    assert_eq!(find(&mut vault, "example.com", &[]).unwrap().len(), 1);
}

#[test]
fn private_keys_are_never_on_disk_in_the_clear() {
    let fixture = Fixture::new();
    let mut vault = fixture.create();
    let mut secrets = Vec::new();
    for algorithm in [Algorithm::Es256, Algorithm::EdDsa] {
        let (credential, key) = new_credential(
            &account("example.com", algorithm.name().as_bytes(), "alice"),
            algorithm,
        )
        .unwrap();
        secrets.push(credential.private_key.clone());
        secrets.push(key.public_key().to_spki());
        secrets.push(credential.credential_id.clone());
        save(&mut vault, credential).unwrap();
    }
    drop(vault);
    let mut bytes = std::fs::read(&fixture.path).unwrap();
    for suffix in ["-wal", "-journal"] {
        let mut name = fixture.path.clone().into_os_string();
        name.push(suffix);
        if let Ok(more) = std::fs::read(name) {
            bytes.extend(more);
        }
    }
    for secret in &secrets {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_slice()),
            "a secret is in the vault file"
        );
    }
    for clear in ["example.com", "alice"] {
        assert!(
            !bytes
                .windows(clear.len())
                .any(|window| window == clear.as_bytes()),
            "{clear} is in the vault file"
        );
    }
}

#[test]
fn malformed_accounts_are_refused() {
    for handle in [&[][..], &[1; 65][..]] {
        assert!(matches!(
            new_credential(&account("example.com", handle, "alice"), Algorithm::Es256),
            Err(PasskeyError::Invalid(_))
        ));
    }
}
