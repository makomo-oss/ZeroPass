//! Encrypted export: every item of every domain into one file, sealed under a
//! passphrase, and back into another vault.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams, Passkey, Password, Totp};
use zp_vault::export::{ExportError, MAGIC};
use zp_vault::model::{Content, Login, PasskeyCredential, SecureNote, TotpEntry};
use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError};

const PASSWORD: &str = "correct horse battery staple";
const PASSPHRASE: &str = "an export passphrase of some length";

fn options() -> CreateOptions {
    CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: None,
    }
}

fn vault(dir: &tempfile::TempDir, name: &str, hardware: &InsecureSoftwareKeyStore) -> Vault {
    Vault::create(&dir.path().join(name), PASSWORD, Some(hardware), options()).unwrap()
}

fn passkey() -> PasskeyCredential {
    PasskeyCredential {
        rp_id: "example.com".into(),
        rp_name: "Example".into(),
        user_handle: vec![1, 2, 3],
        user_name: "alice".into(),
        user_display_name: "Alice".into(),
        credential_id: vec![9; 16],
        private_key: vec![7; 48],
        cose_algorithm: -7,
    }
}

#[test]
fn everything_comes_back_in_another_vault_with_its_links() {
    let dir = tempfile::tempdir().unwrap();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut source = vault(&dir, "source.zpvault", &hardware);
    let bank = source
        .insert(Login::new("Bank", "alice", "hunter2-hunter2").with_url("https://bank.example.com"))
        .unwrap();
    source
        .insert(SecureNote::new("Wi-Fi", "purple monkey dishwasher"))
        .unwrap();
    source
        .insert(TotpEntry::new("Bank", "alice", vec![5; 20]).for_login(bank))
        .unwrap();
    source.insert(passkey()).unwrap();

    let (file, exported) = source
        .export_encrypted(PASSPHRASE, &KdfParams::MINIMUM)
        .unwrap();
    assert_eq!(
        (
            exported.logins,
            exported.notes,
            exported.totp,
            exported.passkeys
        ),
        (1, 1, 1, 1)
    );
    assert!(file.starts_with(MAGIC));
    // Nothing of the items is readable in the file.
    for secret in [
        &b"hunter2"[..],
        b"purple monkey",
        b"bank.example.com",
        b"Wi-Fi",
    ] {
        assert!(!file.windows(secret.len()).any(|window| window == secret));
    }

    let mut target = vault(&dir, "target.zpvault", &hardware);
    let imported = target.import_encrypted(&file, PASSPHRASE).unwrap();
    assert_eq!(imported, exported);
    let logins = target.list::<Password>().unwrap();
    let new_bank = logins
        .iter()
        .find_map(|(id, content)| match content {
            Content::Login(login) if login.title == "Bank" => Some(*id),
            _ => None,
        })
        .unwrap();
    assert_ne!(new_bank, bank, "imported items are new items");
    let totp = target.list::<Totp>().unwrap();
    let Some((_, Content::Totp(entry))) = totp.first() else {
        panic!("no TOTP entry");
    };
    assert_eq!(entry.secret, vec![5; 20]);
    assert_eq!(
        entry.login(),
        Some(new_bank),
        "the entry is tied to the new login"
    );
    assert_eq!(target.list::<Passkey>().unwrap().len(), 1);
}

#[test]
fn a_wrong_passphrase_a_changed_file_or_a_short_passphrase_fail() {
    let dir = tempfile::tempdir().unwrap();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut source = vault(&dir, "source.zpvault", &hardware);
    source
        .insert(Login::new("Bank", "alice", "hunter2-hunter2"))
        .unwrap();
    assert!(matches!(
        source.export_encrypted("too short", &KdfParams::MINIMUM),
        Err(ExportError::WeakPassphrase)
    ));
    let (file, _) = source
        .export_encrypted(PASSPHRASE, &KdfParams::MINIMUM)
        .unwrap();

    let mut target = vault(&dir, "target.zpvault", &hardware);
    assert!(matches!(
        target.import_encrypted(&file, "another passphrase entirely"),
        Err(ExportError::WrongPassphrase)
    ));
    for at in [MAGIC.len() + 2, file.len() - 1] {
        let mut changed = file.clone();
        changed[at] ^= 1;
        assert!(
            target.import_encrypted(&changed, PASSPHRASE).is_err(),
            "byte {at}"
        );
    }
    assert!(matches!(
        target.import_encrypted(b"not an export at all, just text", PASSPHRASE),
        Err(ExportError::NotAnExport)
    ));
    // Nothing was added by the failed attempts.
    assert!(target.list::<Password>().unwrap().is_empty());
}

#[test]
fn a_locked_domain_stops_an_export() {
    let dir = tempfile::tempdir().unwrap();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut source = vault(&dir, "source.zpvault", &hardware);
    source.lock(DomainId::Totp);
    assert!(matches!(
        source.export_encrypted(PASSPHRASE, &KdfParams::MINIMUM),
        Err(ExportError::Vault(VaultError::Locked(DomainId::Totp)))
    ));
}
