//! A vault kept in memory (ADR-0012): created, joined and recovered without a
//! file, stored as an image, and opened again from it.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use zp_crypto::{InsecureSoftwareKeyStore, KdfParams, Passkey, Password, Totp};
use zp_vault::model::{Login, TotpEntry};
use zp_vault::{Clock, CreateOptions, JoinIdentity, KdfChoice, Place, Vault, VaultError};

const PASSWORD: &str = "the master password of the phone";
const PASSWORD_PC: &str = "the master password of the computer";

fn options(name: &str) -> CreateOptions {
    CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: Some(name.to_owned()),
    }
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn a_vault_made_in_memory_is_kept_by_its_image() {
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault =
        Vault::create_in(Place::Memory, PASSWORD, Some(&hardware), options("phone")).unwrap();
    let login = vault
        .insert(Login::new("Example", "alice", "s3cret-in-memory"))
        .unwrap();
    let totp = vault
        .insert(TotpEntry::new("Example", "alice", vec![7; 20]))
        .unwrap();
    let image = vault.image().unwrap();
    drop(vault);

    // No plaintext and no key in the image.
    assert!(!contains(&image, b"s3cret-in-memory"));
    assert!(!contains(&image, b"alice"));
    assert!(!contains(&image, PASSWORD.as_bytes()));

    let mut reopened = Vault::open_image(&image, Clock::system()).unwrap();
    assert!(matches!(
        reopened.get::<Login>(login),
        Err(VaultError::Locked(_))
    ));
    reopened.unlock_password(PASSWORD).unwrap();
    assert_eq!(
        reopened.get::<Login>(login).unwrap().password,
        "s3cret-in-memory"
    );
    // The hardware-bound domains open with the key store only, as from a file.
    assert!(matches!(
        reopened.get::<TotpEntry>(totp),
        Err(VaultError::Locked(_))
    ));
    reopened.unlock_hardware::<Totp>(&hardware).unwrap();
    assert_eq!(reopened.get::<TotpEntry>(totp).unwrap().secret, vec![7; 20]);
}

#[test]
fn an_image_is_the_vault_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let mut on_disk = Vault::create(&path, PASSWORD, None, options("pc")).unwrap();
    let id = on_disk
        .insert(Login::new("Disk", "bob", "from-the-file"))
        .unwrap();
    drop(on_disk);

    // A file opens as an image...
    let mut in_memory = Vault::open_image(&std::fs::read(&path).unwrap(), Clock::system()).unwrap();
    in_memory.unlock_password(PASSWORD).unwrap();
    assert_eq!(
        in_memory.get::<Login>(id).unwrap().password,
        "from-the-file"
    );
    let added = in_memory
        .insert(Login::new("Memory", "carol", "added-in-memory"))
        .unwrap();

    // ...and an image, written out, is a file.
    let copy = dir.path().join("copy.zpvault");
    std::fs::write(&copy, in_memory.image().unwrap()).unwrap();
    let mut from_copy = Vault::open(&copy).unwrap();
    from_copy.unlock_password(PASSWORD).unwrap();
    assert_eq!(
        from_copy.get::<Login>(added).unwrap().password,
        "added-in-memory"
    );
    // Changes in memory never reach the original file.
    let mut original = Vault::open(&path).unwrap();
    original.unlock_password(PASSWORD).unwrap();
    assert!(original.get::<Login>(added).is_err());
}

#[test]
fn what_is_not_a_vault_does_not_open() {
    assert!(matches!(
        Vault::open_image(&[], Clock::system()),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        Vault::open_image(&[0x5a; 4096], Clock::system()),
        Err(VaultError::NotAVault)
    ));
    // A SQLite database that is not a vault.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("other.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
        .unwrap();
    drop(conn);
    assert!(matches!(
        Vault::open_image(&std::fs::read(&path).unwrap(), Clock::system()),
        Err(VaultError::NotAVault)
    ));
}

#[test]
fn a_device_joins_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let hardware_pc = InsecureSoftwareKeyStore::generate().unwrap();
    let mut pc = Vault::create(
        &dir.path().join("pc.zpvault"),
        PASSWORD_PC,
        Some(&hardware_pc),
        options("pc"),
    )
    .unwrap();

    let identity = JoinIdentity::generate().unwrap();
    let grant = pc
        .grant(
            identity.device_id(),
            identity.sign_pk(),
            *identity.channel_key().public_bytes(),
            "phone",
        )
        .unwrap();
    let hardware_phone = InsecureSoftwareKeyStore::generate().unwrap();
    let mut phone = Vault::join_in(
        Place::Memory,
        identity,
        grant,
        PASSWORD,
        Some(&hardware_phone),
        options("phone"),
    )
    .unwrap();
    assert_eq!(phone.vault_id(), pc.vault_id());
    assert!(!dir.path().join("phone.zpvault").exists());

    // The joined vault, stored and opened again, has every domain.
    let image = phone.image().unwrap();
    let mut phone = Vault::open_image(&image, Clock::system()).unwrap();
    phone.unlock_password(PASSWORD).unwrap();
    phone.unlock_hardware::<Totp>(&hardware_phone).unwrap();
    phone.unlock_hardware::<Passkey>(&hardware_phone).unwrap();
    assert!(phone.list::<Password>().unwrap().is_empty());
}

#[test]
fn a_vault_in_memory_is_recovered_in_memory() {
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault =
        Vault::create_in(Place::Memory, PASSWORD, Some(&hardware), options("phone")).unwrap();
    let id = vault
        .insert(Login::new("Example", "alice", "kept-by-the-kit"))
        .unwrap();
    let recovery_key = vault.create_recovery_kit().unwrap();
    let image = vault.image().unwrap();

    let new_password = "a new master password after recovery";
    assert!(matches!(
        Vault::recover_image(
            &image,
            &zp_crypto::RecoveryKey::generate().unwrap(),
            new_password,
            None,
            options("phone"),
        ),
        Err(VaultError::WrongRecoveryKey)
    ));
    let mut recovered = Vault::recover_image(
        &image,
        &recovery_key,
        new_password,
        Some(&hardware),
        options("phone"),
    )
    .unwrap();
    assert_eq!(
        recovered.get::<Login>(id).unwrap().password,
        "kept-by-the-kit"
    );
    let image = recovered.image().unwrap();
    let mut reopened = Vault::open_image(&image, Clock::system()).unwrap();
    assert!(matches!(
        reopened.unlock_password(PASSWORD),
        Err(VaultError::WrongPassword)
    ));
    reopened.unlock_password(new_password).unwrap();
}
