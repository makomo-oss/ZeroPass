//! Revoking a device and replacing the vault keys (`docs/spec/sync.md` §8).

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};

use zp_crypto::{
    CryptoError, DomainId, InsecureSoftwareKeyStore, KdfParams, Passkey, Password, Totp,
};
use zp_sync::{InMemoryError, OpLog, SyncError, sync_in_memory};
use zp_vault::model::{Login, PasskeyCredential, TotpEntry};
use zp_vault::{CreateOptions, JoinIdentity, KdfChoice, Store, Vault, VaultError};

const PASSWORD: &str = "a master password for the tests";
const NEW_PASSWORD: &str = "another master password entirely";

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

fn totp(issuer: &str) -> TotpEntry {
    TotpEntry::new(issuer, "alice", vec![1; 20])
}

fn passkey(rp: &str) -> PasskeyCredential {
    PasskeyCredential {
        rp_id: rp.into(),
        rp_name: "Example".into(),
        user_handle: vec![1, 2, 3],
        user_name: "alice".into(),
        user_display_name: "Alice".into(),
        credential_id: vec![9; 16],
        private_key: vec![7; 48],
        cose_algorithm: -7,
    }
}

struct Device {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hardware: InsecureSoftwareKeyStore,
    vault: Vault,
}

impl Device {
    /// Locks everything and unlocks it again, as after a restart.
    fn reopen(&mut self) {
        self.vault.lock_all();
        self.vault.unlock_password(PASSWORD).unwrap();
        self.vault.unlock_hardware::<Totp>(&self.hardware).unwrap();
        self.vault
            .unlock_hardware::<Passkey>(&self.hardware)
            .unwrap();
    }
}

fn found() -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let vault = Vault::create(&path, PASSWORD, Some(&hardware), options("founder")).unwrap();
    Device {
        _dir: dir,
        path,
        hardware,
        vault,
    }
}

/// Pairs a new device with `existing` and runs the first sync.
fn join(existing: &mut Device, name: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let identity = JoinIdentity::generate().unwrap();
    let grant = existing
        .vault
        .grant(
            identity.device_id(),
            identity.sign_pk(),
            *identity.channel_key().public_bytes(),
            name,
        )
        .unwrap();
    let vault = Vault::join(
        &path,
        identity,
        grant,
        PASSWORD,
        Some(&hardware),
        options(name),
    )
    .unwrap();
    sync(&existing.path, &path);
    Device {
        _dir: dir,
        path,
        hardware,
        vault,
    }
}

/// Syncs two vault files the way the sync daemon does: without any key.
fn try_sync(a: &Path, b: &Path) -> Result<(), InMemoryError<VaultError, VaultError>> {
    let (mut store_a, mut store_b) = (Store::open(a).unwrap(), Store::open(b).unwrap());
    sync_in_memory(&mut store_a, &mut store_b).map(|_| ())
}

fn sync(a: &Path, b: &Path) {
    try_sync(a, b).unwrap();
}

/// Hands the ops `from` authored to `to` outside of any session, as if the
/// ciphertext had leaked (a stolen backup, a tapped link).
fn leak(from: &Path, to: &Path) {
    let source = Store::open(from).unwrap();
    let mut target = Store::open(to).unwrap();
    let author = source.device_id();
    let held = target.version_vector().unwrap().get(&author);
    let ops = source.ops_after(author, held, 1000).unwrap();
    assert!(!ops.is_empty());
    OpLog::apply(&mut target, ops).unwrap();
}

fn epochs(vault: &mut Vault) -> (u32, u32, u32) {
    (
        vault.key_epoch::<Password>().unwrap(),
        vault.key_epoch::<Totp>().unwrap(),
        vault.key_epoch::<Passkey>().unwrap(),
    )
}

/// The acceptance test of P2-19: after a device has been revoked, it cannot
/// decrypt what the others write, while they carry on as before.
#[test]
fn a_revoked_device_cannot_read_what_is_written_afterwards() {
    let mut a = found();
    let old_login = a.vault.insert(login("old")).unwrap();
    let edited = a.vault.insert(login("before")).unwrap();
    let old_totp = a.vault.insert(totp("old")).unwrap();
    let mut b = join(&mut a, "device B");
    let mut c = join(&mut a, "device C");
    let device_c = c.vault.device_id();
    assert_eq!(epochs(&mut a.vault), (1, 1, 1));

    a.vault.revoke_device(device_c).unwrap();
    assert_eq!(epochs(&mut a.vault), (2, 2, 2));
    assert!(a.vault.registry().unwrap().is_revoked(&device_c));

    // Life goes on: new items in every domain and an edit of an old one.
    let new_login = a.vault.insert(login("new")).unwrap();
    let new_totp = a.vault.insert(totp("new")).unwrap();
    let new_passkey = a.vault.insert(passkey("new.example")).unwrap();
    a.vault.update(edited, login("after")).unwrap();

    // The remaining device gets the new keys with its next sync, while unlocked.
    sync(&a.path, &b.path);
    assert_eq!(b.vault.get::<Login>(new_login).unwrap(), login("new"));
    assert_eq!(b.vault.get::<Login>(edited).unwrap(), login("after"));
    assert_eq!(b.vault.get::<Login>(old_login).unwrap(), login("old"));
    assert_eq!(b.vault.get::<TotpEntry>(new_totp).unwrap(), totp("new"));
    assert_eq!(
        b.vault.get::<PasskeyCredential>(new_passkey).unwrap(),
        passkey("new.example")
    );
    assert_eq!(b.vault.history::<Password>(edited).unwrap().len(), 1);
    assert_eq!(epochs(&mut b.vault), (2, 2, 2));
    // ... and writes with them.
    let by_b = b.vault.insert(login("by B")).unwrap();
    sync(&a.path, &b.path);
    assert_eq!(a.vault.get::<Login>(by_b).unwrap(), login("by B"));

    // The same after a restart of either device, and after a password change.
    b.reopen();
    assert_eq!(b.vault.get::<Login>(new_login).unwrap(), login("new"));
    assert_eq!(b.vault.get::<TotpEntry>(old_totp).unwrap(), totp("old"));
    assert_eq!(epochs(&mut b.vault), (2, 2, 2));
    a.vault
        .change_master_password(PASSWORD, NEW_PASSWORD, KdfChoice::Fixed(KdfParams::MINIMUM))
        .unwrap();
    a.vault.lock_all();
    a.vault.unlock_password(NEW_PASSWORD).unwrap();
    assert_eq!(a.vault.get::<Login>(by_b).unwrap(), login("by B"));
    assert_eq!(a.vault.get::<Login>(old_login).unwrap(), login("old"));

    // The revoked device is refused by both, and is not handed the new keys.
    for other in [&a.path, &b.path] {
        assert!(matches!(
            try_sync(other, &c.path),
            Err(
                InMemoryError::A(VaultError::Sync(SyncError::RevokedDevice(_)))
                    | InMemoryError::B(VaultError::Sync(SyncError::RevokedDevice(_)))
            )
        ));
    }
    assert!(
        Store::open(&c.path)
            .unwrap()
            .key_updates()
            .unwrap()
            .is_empty()
    );

    // Even with the ciphertext in hand, it cannot read what came afterwards ...
    leak(&a.path, &c.path);
    for id in [new_login, edited] {
        assert!(matches!(
            c.vault.get::<Login>(id),
            Err(VaultError::KeyGenerationUnavailable {
                domain: DomainId::Password,
                epoch: 2
            })
        ));
    }
    assert!(matches!(
        c.vault.get::<TotpEntry>(new_totp),
        Err(VaultError::KeyGenerationUnavailable {
            domain: DomainId::Totp,
            epoch: 2
        })
    ));
    assert!(matches!(
        c.vault.get::<PasskeyCredential>(new_passkey),
        Err(VaultError::KeyGenerationUnavailable {
            domain: DomainId::Passkey,
            epoch: 2
        })
    ));
    c.reopen();
    assert!(c.vault.get::<Login>(new_login).is_err());
    // ... only what it had already received.
    assert_eq!(c.vault.get::<Login>(old_login).unwrap(), login("old"));
    assert_eq!(c.vault.get::<TotpEntry>(old_totp).unwrap(), totp("old"));
}

#[test]
fn revoking_needs_every_domain_and_changes_nothing_otherwise() {
    let mut a = found();
    let c = join(&mut a, "device C");
    let device_c = c.vault.device_id();

    assert!(matches!(
        a.vault.revoke_device(a.vault.device_id()),
        Err(VaultError::CannotRevokeSelf)
    ));
    a.vault.lock(DomainId::Totp);
    assert!(matches!(
        a.vault.revoke_device(device_c),
        Err(VaultError::Locked(DomainId::Totp))
    ));
    assert!(!a.vault.registry().unwrap().is_revoked(&device_c));
    assert!(
        Store::open(&a.path)
            .unwrap()
            .key_updates()
            .unwrap()
            .is_empty()
    );
    assert_eq!(a.vault.key_epoch::<Password>().unwrap(), 1);

    a.vault.unlock_hardware::<Totp>(&a.hardware).unwrap();
    a.vault.revoke_device(device_c).unwrap();
    assert_eq!(
        Store::open(&a.path).unwrap().key_updates().unwrap().len(),
        3
    );
    // Revoking twice is refused and rotates nothing more.
    assert!(matches!(
        a.vault.revoke_device(device_c),
        Err(VaultError::Sync(SyncError::RevokedDevice(_)))
    ));
    assert_eq!(epochs(&mut a.vault), (2, 2, 2));
}

#[test]
fn a_device_that_joins_after_a_rotation_reads_old_and_new() {
    let mut a = found();
    let old = a.vault.insert(login("old")).unwrap();
    let c = join(&mut a, "device C");
    a.vault.revoke_device(c.vault.device_id()).unwrap();
    let new = a.vault.insert(totp("new")).unwrap();

    let mut d = join(&mut a, "device D");
    assert_eq!(epochs(&mut d.vault), (2, 2, 2));
    assert_eq!(d.vault.get::<Login>(old).unwrap(), login("old"));
    assert_eq!(d.vault.get::<TotpEntry>(new).unwrap(), totp("new"));

    // Its key slots hold the current keys; the older ones are still reachable
    // after a restart.
    d.reopen();
    assert_eq!(d.vault.get::<Login>(old).unwrap(), login("old"));
    assert_eq!(d.vault.get::<TotpEntry>(new).unwrap(), totp("new"));
    let by_d = d.vault.insert(login("by D")).unwrap();
    sync(&a.path, &d.path);
    assert_eq!(a.vault.get::<Login>(by_d).unwrap(), login("by D"));
}

#[test]
fn rotations_on_two_devices_at_once_converge() {
    let mut a = found();
    let mut b = join(&mut a, "device B");

    assert_eq!(a.vault.rotate_key::<Password>().unwrap(), 2);
    assert_eq!(b.vault.rotate_key::<Password>().unwrap(), 2);
    let by_a = a.vault.insert(login("by A")).unwrap();
    let by_b = b.vault.insert(login("by B")).unwrap();

    sync(&a.path, &b.path);
    for device in [&mut a, &mut b] {
        assert_eq!(device.vault.get::<Login>(by_a).unwrap(), login("by A"));
        assert_eq!(device.vault.get::<Login>(by_b).unwrap(), login("by B"));
        assert_eq!(device.vault.key_epoch::<Password>().unwrap(), 2);
        device.reopen();
        assert_eq!(device.vault.get::<Login>(by_a).unwrap(), login("by A"));
        assert_eq!(device.vault.get::<Login>(by_b).unwrap(), login("by B"));
    }

    // Both carry on from there, whichever of the two keys the next rotation
    // builds on.
    assert_eq!(b.vault.rotate_key::<Password>().unwrap(), 3);
    let later = b.vault.insert(login("later")).unwrap();
    sync(&a.path, &b.path);
    assert_eq!(a.vault.get::<Login>(later).unwrap(), login("later"));
    assert_eq!(a.vault.key_epoch::<Password>().unwrap(), 3);
    assert_eq!(a.vault.list::<Password>().unwrap().len(), 3);
}

/// A revoked device that is still trusted by someone who has not heard of the
/// revocation must not be able to plant a key that the others then write with.
#[test]
fn a_key_chosen_by_a_revoked_device_is_not_written_with() {
    let mut a = found();
    let mut b = join(&mut a, "device B");
    let mut c = join(&mut a, "device C");
    sync(&b.path, &c.path);

    a.vault.revoke_device(c.vault.device_id()).unwrap();
    // C rotates too and reaches B first.
    assert_eq!(c.vault.rotate_key::<Password>().unwrap(), 2);
    sync(&b.path, &c.path);
    let early = b.vault.insert(login("early")).unwrap();
    // Then B hears from A.
    sync(&a.path, &b.path);
    let late = b.vault.insert(login("late")).unwrap();
    sync(&a.path, &b.path);
    assert_eq!(a.vault.get::<Login>(early).unwrap(), login("early"));
    assert_eq!(a.vault.get::<Login>(late).unwrap(), login("late"));

    leak(&b.path, &c.path);
    // What B wrote before it knew is lost to C (C chose that key) ...
    assert_eq!(c.vault.get::<Login>(early).unwrap(), login("early"));
    // ... what it wrote afterwards is not.
    assert!(matches!(
        c.vault.get::<Login>(late),
        Err(VaultError::Crypto(CryptoError::Decrypt))
    ));
}

#[test]
fn a_recovery_kit_from_before_a_rotation_still_restores_everything() {
    let mut a = found();
    let old = a.vault.insert(login("old")).unwrap();
    let recovery_key = a.vault.create_recovery_kit().unwrap();
    let c = join(&mut a, "device C");
    a.vault.revoke_device(c.vault.device_id()).unwrap();
    let new_login = a.vault.insert(login("new")).unwrap();
    let new_totp = a.vault.insert(totp("new")).unwrap();
    let device_a = a.vault.device_id();
    drop(a.vault);

    // The backup copy of the file is restored on a new machine.
    let dir = tempfile::tempdir().unwrap();
    let restored_path = dir.path().join("restored.zpvault");
    std::fs::copy(&a.path, &restored_path).unwrap();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut restored = Vault::recover(
        &restored_path,
        &recovery_key,
        NEW_PASSWORD,
        Some(&hardware),
        options("restored"),
    )
    .unwrap();
    assert_eq!(restored.get::<Login>(old).unwrap(), login("old"));
    assert_eq!(restored.get::<Login>(new_login).unwrap(), login("new"));
    assert_eq!(restored.get::<TotpEntry>(new_totp).unwrap(), totp("new"));

    // Recovery revokes the earlier devices, so it replaces the keys once more.
    assert!(restored.registry().unwrap().is_revoked(&device_a));
    assert_eq!(epochs(&mut restored), (3, 3, 3));
    let after = restored.insert(login("after")).unwrap();
    restored.lock_all();
    restored.unlock_password(NEW_PASSWORD).unwrap();
    assert_eq!(restored.get::<Login>(after).unwrap(), login("after"));
    assert_eq!(restored.get::<Login>(old).unwrap(), login("old"));
}
