//! Adding a device to a vault: grant on the existing device, join on the new
//! one, then sync. (The pairing channel that carries the grant between the
//! devices is tested in `zp-pairing`.)

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, ItemId, KdfParams, Passkey, Password, Totp};
use zp_sync::sync_in_memory;
use zp_vault::model::{Login, PasskeyCredential, TotpEntry};
use zp_vault::{CreateOptions, JoinIdentity, KdfChoice, Store, Vault, VaultError, VaultGrant};

const PASSWORD_A: &str = "the master password of device A";
const PASSWORD_B: &str = "device B has its own master password";

fn options(name: &str) -> CreateOptions {
    CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: Some(name.to_owned()),
    }
}

fn login(password: &str) -> Login {
    Login::new("Example", "alice@example.com", password)
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

struct Existing {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hardware: InsecureSoftwareKeyStore,
    vault: Vault,
    ids: (ItemId, ItemId, ItemId),
}

fn existing() -> Existing {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::create(&path, PASSWORD_A, Some(&hardware), options("device A")).unwrap();
    let ids = (
        vault.insert(login("pw-1")).unwrap(),
        vault.insert(totp()).unwrap(),
        vault.insert(passkey()).unwrap(),
    );
    Existing {
        _dir: dir,
        path,
        hardware,
        vault,
        ids,
    }
}

fn grant_for(existing: &mut Existing, identity: &JoinIdentity, name: &str) -> VaultGrant {
    existing
        .vault
        .grant(
            identity.device_id(),
            identity.sign_pk(),
            *identity.channel_key().public_bytes(),
            name,
        )
        .unwrap()
}

/// Syncs two vault files the way the sync daemon does: without any key.
fn sync(a: &Path, b: &Path) {
    let (mut store_a, mut store_b) = (Store::open(a).unwrap(), Store::open(b).unwrap());
    sync_in_memory(&mut store_a, &mut store_b).unwrap();
}

/// The acceptance test of P2-09 at the vault level: after joining and one sync,
/// the new device opens every domain and reads everything.
#[test]
fn a_new_device_joins_and_can_open_every_domain() {
    let mut a = existing();
    let dir_b = tempfile::tempdir().unwrap();
    let path_b = dir_b.path().join("b.zpvault");
    let hardware_b = InsecureSoftwareKeyStore::generate().unwrap();

    let identity = JoinIdentity::generate().unwrap();
    let device_b = identity.device_id();
    let grant = grant_for(&mut a, &identity, "device B");
    assert_eq!(grant.vault_id, a.vault.vault_id());
    assert_eq!(grant.keys.len(), 3);
    assert_eq!(grant.records.len(), 2);

    let mut b = Vault::join(
        &path_b,
        identity,
        grant,
        PASSWORD_B,
        Some(&hardware_b),
        options("ignored"),
    )
    .unwrap();
    assert_eq!(b.vault_id(), a.vault.vault_id());
    assert_eq!(b.device_id(), device_b);
    assert_ne!(b.device_id(), a.vault.device_id());
    // Unlocked, but empty until the first sync.
    assert!(b.list::<Password>().unwrap().is_empty());

    sync(&a.path, &path_b);
    assert_eq!(b.get::<Login>(a.ids.0).unwrap(), login("pw-1"));
    assert_eq!(b.get::<TotpEntry>(a.ids.1).unwrap(), totp());
    assert_eq!(b.get::<PasskeyCredential>(a.ids.2).unwrap(), passkey());

    // Both registries list both devices; B was introduced by A.
    for vault in [&a.vault, &b] {
        let registry = vault.registry().unwrap();
        assert_eq!(registry.active().count(), 2);
        let record = registry.get(&device_b).unwrap();
        assert_eq!(record.name, "device B");
        assert_eq!(record.introduced_by, a.vault.device_id());
    }

    // The new device has its own credentials: its password and key store work,
    // device A's do not.
    drop(b);
    let mut b = Vault::open(&path_b).unwrap();
    assert!(matches!(
        b.unlock_password(PASSWORD_A),
        Err(VaultError::WrongPassword)
    ));
    b.unlock_password(PASSWORD_B).unwrap();
    assert!(b.unlock_hardware::<Totp>(&a.hardware).is_err());
    b.unlock_hardware::<Totp>(&hardware_b).unwrap();
    b.unlock_hardware::<Passkey>(&hardware_b).unwrap();
    assert_eq!(b.get::<TotpEntry>(a.ids.1).unwrap(), totp());

    // Changes flow both ways from now on.
    let from_b = b.insert(login("written on B")).unwrap();
    b.update(a.ids.0, login("pw-2, changed on B")).unwrap();
    sync(&a.path, &path_b);
    assert_eq!(a.vault.get::<Login>(from_b).unwrap(), login("written on B"));
    assert_eq!(
        a.vault.get::<Login>(a.ids.0).unwrap(),
        login("pw-2, changed on B")
    );
}

#[test]
fn granting_requires_every_domain_to_be_unlocked() {
    let mut a = existing();
    let identity = JoinIdentity::generate().unwrap();
    let request = |vault: &mut Vault| {
        vault.grant(
            identity.device_id(),
            identity.sign_pk(),
            *identity.channel_key().public_bytes(),
            "device B",
        )
    };

    a.vault.lock(DomainId::Totp);
    assert!(matches!(
        request(&mut a.vault),
        Err(VaultError::Locked(DomainId::Totp))
    ));
    a.vault.lock_all();
    assert!(matches!(
        request(&mut a.vault),
        Err(VaultError::Locked(DomainId::Password))
    ));
    // A refused grant admits nobody.
    assert_eq!(a.vault.registry().unwrap().records().count(), 1);

    a.vault.unlock_password(PASSWORD_A).unwrap();
    a.vault.unlock_hardware::<Totp>(&a.hardware).unwrap();
    a.vault.unlock_hardware::<Passkey>(&a.hardware).unwrap();
    assert_eq!(request(&mut a.vault).unwrap().keys.len(), 3);
    // Granting the same device again (a retried pairing) is harmless.
    request(&mut a.vault).unwrap();
    assert_eq!(a.vault.registry().unwrap().records().count(), 2);
}

#[test]
fn a_device_without_a_key_store_joins_with_the_password_domain_only() {
    let mut a = existing();
    let dir_b = tempfile::tempdir().unwrap();
    let path_b = dir_b.path().join("b.zpvault");
    let identity = JoinIdentity::generate().unwrap();
    let grant = grant_for(&mut a, &identity, "old laptop");

    let mut b = Vault::join(&path_b, identity, grant, PASSWORD_B, None, options("x")).unwrap();
    sync(&a.path, &path_b);
    assert_eq!(b.get::<Login>(a.ids.0).unwrap(), login("pw-1"));
    assert!(!b.has_domain(DomainId::Totp).unwrap());
    assert!(matches!(
        b.get::<TotpEntry>(a.ids.1),
        Err(VaultError::Locked(DomainId::Totp))
    ));

    // The TOTP and passkey items are still held (as ciphertext) and passed on:
    // a third device that joins through B gets them from B.
    let bytes = std::fs::read(&path_b).unwrap();
    assert!(
        !bytes.windows(20).any(|window| window == [1u8; 20]),
        "the seed is not readable"
    );
    let store_b = Store::open(&path_b).unwrap();
    assert_eq!(
        store_b.version_vector().unwrap().get(&a.vault.device_id()),
        3
    );
}

#[test]
fn a_device_introduced_by_the_second_device_reaches_the_first_through_sync() {
    let mut a = existing();
    let (dir_b, dir_c) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (path_b, path_c) = (
        dir_b.path().join("b.zpvault"),
        dir_c.path().join("c.zpvault"),
    );
    let (hw_b, hw_c) = (
        InsecureSoftwareKeyStore::generate().unwrap(),
        InsecureSoftwareKeyStore::generate().unwrap(),
    );

    let identity_b = JoinIdentity::generate().unwrap();
    let grant = grant_for(&mut a, &identity_b, "device B");
    let mut b = Vault::join(
        &path_b,
        identity_b,
        grant,
        PASSWORD_B,
        Some(&hw_b),
        options("x"),
    )
    .unwrap();
    sync(&a.path, &path_b);

    // B, not A, admits C.
    let identity_c = JoinIdentity::generate().unwrap();
    let device_c = identity_c.device_id();
    let grant = b
        .grant(
            device_c,
            identity_c.sign_pk(),
            *identity_c.channel_key().public_bytes(),
            "device C",
        )
        .unwrap();
    let mut c = Vault::join(
        &path_c,
        identity_c,
        grant,
        "device C's own password",
        Some(&hw_c),
        options("x"),
    )
    .unwrap();
    sync(&path_b, &path_c);
    assert_eq!(c.get::<TotpEntry>(a.ids.1).unwrap(), totp());
    let from_c = c.insert(login("written on C")).unwrap();

    // A has never heard of C. At the session level that is no obstacle: C
    // presents its record, signed by B, whom A knows. (The sync channel is
    // stricter: it only connects devices that already know each other's
    // channel key, so in practice A first learns of C from B.)
    assert!(a.vault.registry().unwrap().get(&device_c).is_none());
    sync(&a.path, &path_c);
    assert!(a.vault.registry().unwrap().is_active(&device_c));
    assert_eq!(a.vault.get::<Login>(from_c).unwrap(), login("written on C"));
    // And B catches up with what C wrote through A.
    sync(&a.path, &path_b);
    assert_eq!(b.get::<Login>(from_c).unwrap(), login("written on C"));
}

#[test]
fn unusable_grants_and_weak_passwords_leave_no_file_behind() {
    let mut a = existing();
    let dir_b = tempfile::tempdir().unwrap();
    let path_b = dir_b.path().join("b.zpvault");
    let hardware_b = InsecureSoftwareKeyStore::generate().unwrap();
    let join = |identity: JoinIdentity, grant: VaultGrant, password: &str| {
        Vault::join(
            &path_b,
            identity,
            grant,
            password,
            Some(&hardware_b),
            options("x"),
        )
    };

    // A weak password.
    let identity = JoinIdentity::generate().unwrap();
    let grant = grant_for(&mut a, &identity, "b");
    assert!(matches!(
        join(identity, grant, "short"),
        Err(VaultError::WeakPassword)
    ));
    assert!(!path_b.exists());

    // A grant made for another device.
    let (identity, other) = (
        JoinIdentity::generate().unwrap(),
        JoinIdentity::generate().unwrap(),
    );
    let grant = grant_for(&mut a, &other, "someone else");
    assert!(matches!(
        join(identity, grant, PASSWORD_B),
        Err(VaultError::Sync(_))
    ));
    assert!(!path_b.exists());

    // A grant without the password domain key, or with an unknown key generation.
    let identity = JoinIdentity::generate().unwrap();
    let mut grant = grant_for(&mut a, &identity, "b");
    grant.keys.retain(|key| key.domain != DomainId::Password);
    assert!(matches!(
        join(identity, grant, PASSWORD_B),
        Err(VaultError::InvalidGrant(_))
    ));
    assert!(!path_b.exists());
    let identity = JoinIdentity::generate().unwrap();
    let mut grant = grant_for(&mut a, &identity, "b2");
    grant.keys[0].epoch = 0;
    assert!(matches!(
        join(identity, grant, PASSWORD_B),
        Err(VaultError::InvalidGrant(_))
    ));
    assert!(!path_b.exists());

    // A registry that was tampered with on the way.
    let identity = JoinIdentity::generate().unwrap();
    let mut grant = grant_for(&mut a, &identity, "b3");
    grant.records[0].name = "renamed".into();
    assert!(matches!(
        join(identity, grant, PASSWORD_B),
        Err(VaultError::Sync(_))
    ));
    assert!(!path_b.exists());

    // An existing file is never overwritten.
    std::fs::write(&path_b, b"precious").unwrap();
    let identity = JoinIdentity::generate().unwrap();
    let grant = grant_for(&mut a, &identity, "b4");
    assert!(matches!(
        join(identity, grant, PASSWORD_B),
        Err(VaultError::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&path_b).unwrap(), b"precious");
}
