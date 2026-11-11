//! Recovery kit: restoring a vault on a new device from a backup of the vault
//! file and the recovery key.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};

use zp_crypto::{
    DomainId, InsecureSoftwareKeyStore, KdfParams, Passkey, Password, RecoveryKey, Totp,
};
use zp_vault::model::{Login, PasskeyCredential, TotpEntry};
use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError};

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "the password chosen after recovery";

fn options() -> CreateOptions {
    CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: None,
    }
}

fn login() -> Login {
    Login::new("Example", "alice@example.com", "hunter2-hunter2")
}

fn totp() -> TotpEntry {
    TotpEntry::new("Example", "alice", vec![1; 20])
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

/// The original device: a vault with one item per domain.
struct Original {
    dir: tempfile::TempDir,
    path: PathBuf,
    hardware: InsecureSoftwareKeyStore,
    vault: Vault,
    ids: (zp_crypto::ItemId, zp_crypto::ItemId, zp_crypto::ItemId),
}

fn original() -> Original {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::create(&path, PASSWORD, Some(&hardware), options()).unwrap();
    let ids = (
        vault.insert(login()).unwrap(),
        vault.insert(totp()).unwrap(),
        vault.insert(passkey()).unwrap(),
    );
    Original {
        dir,
        path,
        hardware,
        vault,
        ids,
    }
}

/// Copies the vault file to a fresh directory, as if restored from a backup on a
/// new device.
fn backup_of(path: &Path) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("restored.zpvault");
    std::fs::copy(path, &copy).unwrap();
    (dir, copy)
}

/// The acceptance test of P1-14.
#[test]
fn a_vault_is_restored_on_a_new_device() {
    let mut o = original();
    assert!(!o.vault.has_recovery_kit().unwrap());
    let recovery_key = o.vault.create_recovery_kit().unwrap();
    assert!(o.vault.has_recovery_kit().unwrap());
    // What the user writes down, and later types in again.
    let written_down = recovery_key.to_code().to_lowercase().replace('-', " ");
    let (vault_id, old_device_id) = (o.vault.vault_id(), o.vault.device_id());
    drop(o.vault);

    // All devices are lost; only the backup file and the paper remain.
    let (_new_dir, restored) = backup_of(&o.path);
    drop(o.dir);
    let new_hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let typed = RecoveryKey::from_code(&written_down).unwrap();

    let mut vault = Vault::recover(
        &restored,
        &typed,
        NEW_PASSWORD,
        Some(&new_hardware),
        options(),
    )
    .unwrap();
    assert_eq!(vault.vault_id(), vault_id);
    assert_ne!(
        vault.device_id(),
        old_device_id,
        "the restored copy is a new device"
    );
    assert_eq!(vault.get::<Login>(o.ids.0).unwrap(), login());
    assert_eq!(vault.get::<TotpEntry>(o.ids.1).unwrap(), totp());
    assert_eq!(vault.get::<PasskeyCredential>(o.ids.2).unwrap(), passkey());
    // New items are written under the new device identity.
    vault
        .insert(Login::new("After recovery", "bob", "another password"))
        .unwrap();
    let new_device_id = vault.device_id();
    drop(vault);

    // From now on the new credentials work and the old ones do not.
    let mut vault = Vault::open(&restored).unwrap();
    assert_eq!(vault.device_id(), new_device_id);
    assert!(matches!(
        vault.unlock_password(PASSWORD),
        Err(VaultError::WrongPassword)
    ));
    vault.unlock_password(NEW_PASSWORD).unwrap();
    assert_eq!(vault.list::<Password>().unwrap().len(), 2);
    assert!(
        vault.unlock_hardware::<Totp>(&o.hardware).is_err(),
        "the old device's key is gone"
    );
    vault.unlock_hardware::<Totp>(&new_hardware).unwrap();
    vault.unlock_hardware::<Passkey>(&new_hardware).unwrap();
    assert_eq!(vault.get::<TotpEntry>(o.ids.1).unwrap(), totp());
}

#[test]
fn creating_a_kit_requires_every_domain_to_be_unlocked() {
    let mut o = original();
    o.vault.lock(DomainId::Totp);
    assert!(matches!(
        o.vault.create_recovery_kit(),
        Err(VaultError::Locked(DomainId::Totp))
    ));
    assert!(
        !o.vault.has_recovery_kit().unwrap(),
        "a refused kit must leave no slots behind"
    );

    o.vault.lock_all();
    assert!(matches!(
        o.vault.create_recovery_kit(),
        Err(VaultError::Locked(DomainId::Password))
    ));

    o.vault.unlock_password(PASSWORD).unwrap();
    o.vault.unlock_hardware::<Totp>(&o.hardware).unwrap();
    o.vault.unlock_hardware::<Passkey>(&o.hardware).unwrap();
    o.vault.create_recovery_kit().unwrap();
}

#[test]
fn a_wrong_recovery_key_changes_nothing() {
    let mut o = original();
    o.vault.create_recovery_kit().unwrap();
    drop(o.vault);
    let before = std::fs::read(&o.path).unwrap();

    // A valid key, but not this vault's.
    let stranger = RecoveryKey::generate().unwrap();
    assert!(matches!(
        Vault::recover(
            &o.path,
            &stranger,
            NEW_PASSWORD,
            Some(&o.hardware),
            options()
        ),
        Err(VaultError::WrongRecoveryKey)
    ));
    // The key of another vault.
    let mut other = original();
    let other_key = other.vault.create_recovery_kit().unwrap();
    assert!(matches!(
        Vault::recover(
            &o.path,
            &other_key,
            NEW_PASSWORD,
            Some(&o.hardware),
            options()
        ),
        Err(VaultError::WrongRecoveryKey)
    ));

    assert_eq!(
        std::fs::read(&o.path).unwrap(),
        before,
        "the file must be untouched"
    );
    Vault::open(&o.path)
        .unwrap()
        .unlock_password(PASSWORD)
        .unwrap();
}

#[test]
fn recovery_needs_a_kit_and_a_strong_new_password() {
    let mut o = original();
    let key = RecoveryKey::generate().unwrap();
    assert!(matches!(
        Vault::recover(&o.path, &key, NEW_PASSWORD, None, options()),
        Err(VaultError::NoRecoveryKit)
    ));

    let key = o.vault.create_recovery_kit().unwrap();
    drop(o.vault);
    let before = std::fs::read(&o.path).unwrap();
    assert!(matches!(
        Vault::recover(&o.path, &key, "too short", None, options()),
        Err(VaultError::WeakPassword)
    ));
    let weak = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::new(1024, 1, 1).unwrap()),
        clock: None,
        device_name: None,
    };
    assert!(matches!(
        Vault::recover(&o.path, &key, NEW_PASSWORD, None, weak),
        Err(VaultError::WeakKdf)
    ));
    assert_eq!(std::fs::read(&o.path).unwrap(), before);
}

#[test]
fn a_new_kit_invalidates_the_previous_recovery_key() {
    let mut o = original();
    let first = o.vault.create_recovery_kit().unwrap();
    let second = o.vault.create_recovery_kit().unwrap();
    assert_ne!(first.to_code().as_str(), second.to_code().as_str());
    drop(o.vault);

    assert!(matches!(
        Vault::recover(&o.path, &first, NEW_PASSWORD, Some(&o.hardware), options()),
        Err(VaultError::WrongRecoveryKey)
    ));
    Vault::recover(&o.path, &second, NEW_PASSWORD, Some(&o.hardware), options()).unwrap();
}

#[test]
fn without_a_hardware_key_store_only_the_password_domain_is_restored() {
    let mut o = original();
    let key = o.vault.create_recovery_kit().unwrap();
    drop(o.vault);
    let (_dir, restored) = backup_of(&o.path);

    let mut vault = Vault::recover(&restored, &key, NEW_PASSWORD, None, options()).unwrap();
    assert_eq!(vault.get::<Login>(o.ids.0).unwrap(), login());
    assert!(matches!(
        vault.get::<TotpEntry>(o.ids.1),
        Err(VaultError::Locked(DomainId::Totp))
    ));
    drop(vault);

    // The kit stays valid: the other domains can be restored later, on a device
    // that has a hardware key store.
    let new_hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault =
        Vault::recover(&restored, &key, PASSWORD, Some(&new_hardware), options()).unwrap();
    assert_eq!(vault.get::<TotpEntry>(o.ids.1).unwrap(), totp());
    assert_eq!(vault.get::<PasskeyCredential>(o.ids.2).unwrap(), passkey());
    assert!(vault.has_recovery_kit().unwrap());
}

#[test]
fn a_password_only_vault_has_a_password_only_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let mut vault = Vault::create(&path, PASSWORD, None, options()).unwrap();
    let id = vault.insert(login()).unwrap();
    let key = vault.create_recovery_kit().unwrap();
    drop(vault);

    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::recover(&path, &key, NEW_PASSWORD, Some(&hardware), options()).unwrap();
    assert_eq!(vault.get::<Login>(id).unwrap(), login());
    assert!(!vault.has_domain(DomainId::Totp).unwrap());
}

#[test]
fn the_recovery_key_is_not_stored_in_the_vault_file() {
    let mut o = original();
    let key = o.vault.create_recovery_kit().unwrap();
    drop(o.vault);
    let bytes = std::fs::read(&o.path).unwrap();
    let code = key.to_code();
    for needle in [code.as_str().to_owned(), code.replace('-', "")] {
        assert!(
            !bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
        );
    }
}
