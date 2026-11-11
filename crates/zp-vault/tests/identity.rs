//! Device identity and signed ops at the vault level: every change made through
//! a `Vault` is an op that other devices can verify without any vault key.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams, Passkey, Password, Totp};
use zp_vault::model::{Login, PasskeyCredential, TotpEntry};
use zp_vault::{CreateOptions, KdfChoice, Store, Vault, VaultError};

const PASSWORD: &str = "correct horse battery staple";

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

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hardware: InsecureSoftwareKeyStore,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    Fixture {
        path: dir.path().join("vault.zpvault"),
        _dir: dir,
        hardware: InsecureSoftwareKeyStore::generate().unwrap(),
    }
}

/// What the sync layer sees: the file, opened without any key.
fn locked_view(path: &Path) -> Store {
    Store::open(path).unwrap()
}

#[test]
fn a_new_vault_has_an_identity_and_signs_everything_it_writes() {
    let f = fixture();
    let mut vault =
        Vault::create(&f.path, PASSWORD, Some(&f.hardware), options("Study PC")).unwrap();
    let login_id = vault.insert(login("pw-1")).unwrap();
    vault.update(login_id, login("pw-2")).unwrap();
    vault.insert(totp()).unwrap();
    vault.insert(passkey()).unwrap();
    vault.delete::<Password>(login_id).unwrap();
    let (vault_id, device_id) = (vault.vault_id(), vault.device_id());
    drop(vault);

    // Everything below works on the locked file.
    let store = locked_view(&f.path);
    let registry = store.registry().unwrap();
    let record = registry.get(&device_id).unwrap();
    assert_eq!(record.name, "Study PC");
    assert!(record.is_self_introduced());
    assert_eq!(registry.active().count(), 1);
    assert_eq!(
        &record.noise_pk,
        store.channel_key().unwrap().public_bytes()
    );
    for domain in DomainId::ALL {
        assert!(store.has_device_key_slot(domain).unwrap());
    }

    assert_eq!(store.version_vector().unwrap().get(&device_id), 5);
    let ops = store.ops_after(device_id, 0, 100).unwrap();
    assert_eq!(ops.len(), 5);
    for op in &ops {
        op.verify(&vault_id, &record.sign_pk).unwrap();
    }
    assert!(
        ops[4].body.payload.is_none(),
        "the deletion is a signed tombstone"
    );
    // A forged tombstone for the remaining items does not verify.
    let mut forged = ops[4].clone();
    forged.body.item_id = ops[2].body.item_id;
    forged.body.seq = 6;
    assert!(forged.verify(&vault_id, &record.sign_pk).is_err());
}

#[test]
fn a_password_only_vault_signs_with_the_password_domain() {
    let f = fixture();
    let mut vault = Vault::create(&f.path, PASSWORD, None, options("laptop")).unwrap();
    vault.insert(login("pw")).unwrap();
    drop(vault);

    let store = locked_view(&f.path);
    assert!(store.has_device_key_slot(DomainId::Password).unwrap());
    assert!(!store.has_device_key_slot(DomainId::Totp).unwrap());
    assert_eq!(store.ops_after(store.device_id(), 0, 10).unwrap().len(), 1);
}

#[test]
fn a_locked_vault_cannot_produce_ops() {
    let f = fixture();
    let mut vault = Vault::create(&f.path, PASSWORD, Some(&f.hardware), options("pc")).unwrap();
    let id = vault.insert(login("pw")).unwrap();
    vault.lock_all();
    assert!(matches!(
        vault.delete::<Password>(id),
        Err(VaultError::Locked(DomainId::Password))
    ));
    assert!(matches!(
        vault.insert(login("x")),
        Err(VaultError::Locked(DomainId::Password))
    ));
    drop(vault);
    assert_eq!(
        locked_view(&f.path)
            .version_vector()
            .unwrap()
            .get(&locked_view(&f.path).device_id()),
        1
    );
}

/// Strips what migration 2 cannot create by itself, leaving the file as a vault
/// written by the first format looks right after migrating.
fn make_legacy(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "DELETE FROM devices;
         DELETE FROM device_keys;
         DELETE FROM meta WHERE key = 'channel_sk';
         UPDATE items SET signature = NULL;
         UPDATE item_history SET signature = NULL;",
    )
    .unwrap();
}

#[test]
fn a_vault_from_the_first_format_gets_its_identity_at_the_next_unlock() {
    let f = fixture();
    let mut vault = Vault::create(&f.path, PASSWORD, Some(&f.hardware), options("pc")).unwrap();
    let login_id = vault.insert(login("pw-1")).unwrap();
    vault.update(login_id, login("pw-2")).unwrap();
    let totp_id = vault.insert(totp()).unwrap();
    let device_id = vault.device_id();
    drop(vault);
    make_legacy(&f.path);

    // Locked: no identity, nothing to offer to other devices.
    let store = locked_view(&f.path);
    assert!(!store.is_provisioned().unwrap());
    assert!(store.ops_after(device_id, 0, 10).unwrap().is_empty());
    drop(store);

    // Unlocking the password domain creates the identity and signs its versions.
    let mut vault = Vault::open(&f.path).unwrap();
    vault.unlock_password(PASSWORD).unwrap();
    let store = locked_view(&f.path);
    assert!(store.is_provisioned().unwrap());
    assert!(store.has_device_key_slot(DomainId::Password).unwrap());
    assert!(!store.has_device_key_slot(DomainId::Totp).unwrap());
    // Ops 1 and 2 are the login; op 3 (TOTP) is still unsigned and ends the run.
    assert_eq!(store.ops_after(device_id, 0, 10).unwrap().len(), 2);
    drop(store);

    // Unlocking TOTP next to it hands the signing key over and signs the rest.
    vault.unlock_hardware::<Totp>(&f.hardware).unwrap();
    let store = locked_view(&f.path);
    assert!(store.has_device_key_slot(DomainId::Totp).unwrap());
    let ops = store.ops_after(device_id, 0, 10).unwrap();
    assert_eq!(ops.len(), 3);
    let registry = store.registry().unwrap();
    for op in &ops {
        op.verify(&vault.vault_id(), registry.sign_pk(&device_id).unwrap())
            .unwrap();
    }
    drop(store);

    // Everything still reads back, and new writes work in both domains.
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login("pw-2"));
    assert_eq!(vault.get::<TotpEntry>(totp_id).unwrap(), totp());
    vault.insert(totp()).unwrap();
    vault.insert(login("pw-3")).unwrap();
}

#[test]
fn a_domain_unlocked_alone_waits_for_the_signing_key() {
    let f = fixture();
    let mut vault = Vault::create(&f.path, PASSWORD, Some(&f.hardware), options("pc")).unwrap();
    vault.insert(passkey()).unwrap();
    drop(vault);
    make_legacy(&f.path);

    // The password domain is unlocked first, on its own: it gets the key.
    let mut vault = Vault::open(&f.path).unwrap();
    vault.unlock_password(PASSWORD).unwrap();
    vault.lock_all();

    // The passkey domain alone cannot reach the signing key yet.
    vault.unlock_hardware::<Passkey>(&f.hardware).unwrap();
    assert!(matches!(
        vault.insert(passkey()),
        Err(VaultError::DeviceKeyUnavailable(DomainId::Passkey))
    ));
    // Reading is unaffected.
    assert_eq!(vault.list::<Passkey>().unwrap().len(), 1);

    // Once both are unlocked together, the key is shared.
    vault.unlock_password(PASSWORD).unwrap();
    vault.insert(passkey()).unwrap();
    vault.lock(DomainId::Password);
    vault.insert(passkey()).unwrap();
}

#[test]
fn a_recovered_vault_is_a_new_device_and_keeps_the_old_ops_verifiable() {
    let f = fixture();
    let mut vault = Vault::create(&f.path, PASSWORD, Some(&f.hardware), options("old pc")).unwrap();
    let id = vault.insert(login("pw-1")).unwrap();
    let recovery_key = vault.create_recovery_kit().unwrap();
    let (vault_id, old_device) = (vault.vault_id(), vault.device_id());
    drop(vault);

    let new_hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::recover(
        &f.path,
        &recovery_key,
        "a new master password",
        Some(&new_hardware),
        options("new pc"),
    )
    .unwrap();
    let new_device = vault.device_id();
    vault.update(id, login("pw-2")).unwrap();
    vault.insert(totp()).unwrap();
    drop(vault);

    let store = locked_view(&f.path);
    let registry = store.registry().unwrap();
    assert!(registry.is_revoked(&old_device));
    assert!(registry.is_active(&new_device));
    assert_eq!(registry.get(&new_device).unwrap().name, "new pc");

    let old_ops = store.ops_after(old_device, 0, 10).unwrap();
    assert_eq!(old_ops.len(), 1);
    old_ops[0]
        .verify(&vault_id, registry.sign_pk(&old_device).unwrap())
        .unwrap();
    let new_ops = store.ops_after(new_device, 0, 10).unwrap();
    assert_eq!(new_ops.len(), 2);
    for op in &new_ops {
        op.verify(&vault_id, registry.sign_pk(&new_device).unwrap())
            .unwrap();
        // Not signed by the old device's key.
        assert!(
            op.verify(&vault_id, registry.sign_pk(&old_device).unwrap())
                .is_err()
        );
    }
}
