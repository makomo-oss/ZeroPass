//! The TOTP and passkey domains of a device that does not have them
//! (ADR-0011): the signs that other devices have them, and making them later.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams, Passkey, Totp};
use zp_sync::sync_in_memory;
use zp_vault::model::{Login, PasskeyCredential, TotpEntry};
use zp_vault::{CreateOptions, JoinIdentity, KdfChoice, Store, Vault, VaultError, VaultGrant};

const PASSWORD: &str = "the master password of this device";

fn options(name: &str) -> CreateOptions {
    CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: Some(name.to_owned()),
    }
}

struct Device {
    _dir: tempfile::TempDir,
    path: PathBuf,
    vault: Vault,
}

fn device_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    (dir, path)
}

/// A vault created with a key store: every domain, a login and a TOTP entry.
fn with_key_store() -> Device {
    let (dir, path) = device_dir();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::create(&path, PASSWORD, Some(&hardware), options("PC")).unwrap();
    vault
        .insert(Login::new("Example", "alice", "pw-1"))
        .unwrap();
    vault
        .insert(TotpEntry::new("Example", "alice", vec![1; 20]))
        .unwrap();
    Device {
        _dir: dir,
        path,
        vault,
    }
}

fn grant(from: &mut Vault, identity: &JoinIdentity, name: &str) -> VaultGrant {
    from.grant(
        identity.device_id(),
        identity.sign_pk(),
        *identity.channel_key().public_bytes(),
        name,
    )
    .unwrap()
}

/// Joins the vault of `from` without a key store.
fn join_without_key_store(from: &mut Vault, name: &str) -> Device {
    let (dir, path) = device_dir();
    let identity = JoinIdentity::generate().unwrap();
    let grant = grant(from, &identity, name);
    let vault = Vault::join(&path, identity, grant, PASSWORD, None, options(name)).unwrap();
    Device {
        _dir: dir,
        path,
        vault,
    }
}

fn sync(a: &Path, b: &Path) {
    let (mut store_a, mut store_b) = (Store::open(a).unwrap(), Store::open(b).unwrap());
    sync_in_memory(&mut store_a, &mut store_b).unwrap();
}

fn elsewhere(vault: &Vault) -> [bool; 3] {
    DomainId::ALL.map(|domain| vault.domain_elsewhere(domain).unwrap())
}

#[test]
fn a_vault_made_without_a_key_store_shows_no_hardware_domain_anywhere() {
    let (_dir, path) = device_dir();
    let vault = Vault::create(&path, PASSWORD, None, options("PC")).unwrap();
    assert_eq!(elsewhere(&vault), [false; 3]);
    assert!(vault.domains_at_risk().unwrap().is_empty());
}

#[test]
fn a_device_has_no_domain_elsewhere_that_it_has_itself() {
    let pc = with_key_store();
    assert_eq!(elsewhere(&pc.vault), [false; 3]);
    assert!(pc.vault.domains_at_risk().unwrap().is_empty());
}

#[test]
fn joining_without_a_key_store_remembers_that_the_others_have_the_domains() {
    let mut pc = with_key_store();
    let laptop = join_without_key_store(&mut pc.vault, "laptop");
    // Before any sync: the grant carried the keys this device dropped.
    assert_eq!(elsewhere(&laptop.vault), [false, true, true]);
    assert_eq!(
        laptop.vault.domains_at_risk().unwrap(),
        [DomainId::Totp, DomainId::Passkey]
    );
    // The record survives reopening the file.
    drop(laptop.vault);
    let reopened = Vault::open(&laptop.path).unwrap();
    assert_eq!(elsewhere(&reopened), [false, true, true]);
}

#[test]
fn what_another_device_wrote_in_a_domain_is_a_sign_of_it() {
    // The laptop joined without a key store; the tablet joins through the
    // laptop, which has no TOTP or passkey keys to hand over.
    let mut pc = with_key_store();
    let mut laptop = join_without_key_store(&mut pc.vault, "laptop");
    let tablet = join_without_key_store(&mut laptop.vault, "tablet");
    assert_eq!(elsewhere(&tablet.vault), [false; 3]);

    // The PC's TOTP entry reaches the tablet (as ciphertext) through the laptop.
    sync(&pc.path, &laptop.path);
    sync(&laptop.path, &tablet.path);
    let tablet_vault = Vault::open(&tablet.path).unwrap();
    assert_eq!(elsewhere(&tablet_vault), [false, true, false]);
    assert_eq!(tablet_vault.domains_at_risk().unwrap(), [DomainId::Totp]);
}

fn passkey(rp_id: &str) -> PasskeyCredential {
    PasskeyCredential {
        rp_id: rp_id.into(),
        rp_name: "Example".into(),
        user_handle: vec![1, 2, 3],
        user_name: "alice".into(),
        user_display_name: "Alice".into(),
        credential_id: vec![9; 16],
        private_key: vec![7; 48],
        cose_algorithm: -7,
    }
}

/// A vault created without a key store, with a login.
fn without_key_store() -> Device {
    let (dir, path) = device_dir();
    let mut vault = Vault::create(&path, PASSWORD, None, options("PC")).unwrap();
    vault
        .insert(Login::new("Example", "alice", "pw-1"))
        .unwrap();
    Device {
        _dir: dir,
        path,
        vault,
    }
}

#[test]
fn a_vault_made_without_a_key_store_gets_its_domains_later() {
    let mut pc = without_key_store();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();

    pc.vault.set_up_domain::<Passkey>(&hardware).unwrap();
    assert!(pc.vault.has_domain(DomainId::Passkey).unwrap());
    assert!(!pc.vault.has_domain(DomainId::Totp).unwrap());
    let id = pc.vault.insert(passkey("example.com")).unwrap();
    assert!(matches!(
        pc.vault.set_up_domain::<Passkey>(&hardware),
        Err(VaultError::DomainPresent(DomainId::Passkey))
    ));

    // Later, the domain opens with the key store alone, like any other.
    drop(pc.vault);
    let mut vault = Vault::open(&pc.path).unwrap();
    vault.unlock_hardware::<Passkey>(&hardware).unwrap();
    assert_eq!(
        vault.get::<PasskeyCredential>(id).unwrap(),
        passkey("example.com")
    );
    // The master password does not open it.
    vault.lock_all();
    vault.unlock_password(PASSWORD).unwrap();
    assert!(matches!(
        vault.get::<PasskeyCredential>(id),
        Err(VaultError::Locked(DomainId::Passkey))
    ));
}

#[test]
fn setting_up_a_domain_needs_the_password_domain_and_no_sign_of_it_elsewhere() {
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut pc = without_key_store();
    pc.vault.lock_all();
    assert!(matches!(
        pc.vault.set_up_domain::<Totp>(&hardware),
        Err(VaultError::Locked(DomainId::Password))
    ));
    assert!(!pc.vault.has_domain(DomainId::Totp).unwrap());

    // A device that joined without a key store gets the keys of the others
    // instead of making new ones.
    let mut with = with_key_store();
    let mut laptop = join_without_key_store(&mut with.vault, "laptop");
    assert!(matches!(
        laptop.vault.set_up_domain::<Totp>(&hardware),
        Err(VaultError::DomainElsewhere(DomainId::Totp))
    ));
}

/// ADR-0011 §3: two devices that each made the domain alone do not read each
/// other's items until they exchange keys, and nothing breaks meanwhile.
#[test]
fn what_another_device_wrote_with_its_own_key_is_left_out_and_counted() {
    let mut pc = without_key_store();
    let mut laptop = join_without_key_store(&mut pc.vault, "laptop");
    let (pc_hw, laptop_hw) = (
        InsecureSoftwareKeyStore::generate().unwrap(),
        InsecureSoftwareKeyStore::generate().unwrap(),
    );
    pc.vault.set_up_domain::<Passkey>(&pc_hw).unwrap();
    laptop.vault.set_up_domain::<Passkey>(&laptop_hw).unwrap();
    pc.vault.insert(passkey("pc.example")).unwrap();
    laptop.vault.insert(passkey("laptop.example")).unwrap();

    sync(&pc.path, &laptop.path);
    let (readable, unreadable) = pc.vault.list_readable::<Passkey>().unwrap();
    assert_eq!(readable.len(), 1);
    assert_eq!(unreadable, 1);
    assert_eq!(pc.vault.list::<Passkey>().unwrap().len(), 1);
    let mut laptop = Vault::open(&laptop.path).unwrap();
    laptop.unlock_hardware::<Passkey>(&laptop_hw).unwrap();
    assert_eq!(laptop.list_readable::<Passkey>().unwrap().1, 1);

    // An export would pass for a complete copy: refused.
    assert!(matches!(
        pc.vault
            .export_encrypted("an export passphrase", &KdfParams::MINIMUM),
        Err(zp_vault::export::ExportError::Vault(
            VaultError::KeysMissing {
                domain: DomainId::Passkey,
                items: 1
            }
        ))
    ));
}
