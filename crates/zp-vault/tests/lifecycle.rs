//! Vault lifecycle: creation, independent per-domain unlock, locking, master
//! password change and idle auto-lock. Uses only the public API.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use zp_crypto::{
    CryptoError, DomainId, HardwareKeyError, InsecureSoftwareKeyStore, KdfParams, Passkey,
    Password, Totp,
};
use zp_vault::model::{Login, PasskeyCredential, SecureNote, TotpEntry};
use zp_vault::{AutoLock, Clock, CreateOptions, KdfChoice, Vault, VaultError, is_user_cancelled};

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a different, equally long passphrase";
/// The weakest parameters a vault accepts; keeps the tests fast.
const KDF: KdfChoice = KdfChoice::Fixed(KdfParams::MINIMUM);

struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1_800_000_000_000)))
    }

    fn clock(&self) -> Clock {
        let now = Arc::clone(&self.0);
        Clock::from_fn(move || now.load(Ordering::SeqCst))
    }

    fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hardware: InsecureSoftwareKeyStore,
    time: TestClock,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            path: dir.path().join("vault.zpvault"),
            _dir: dir,
            hardware: InsecureSoftwareKeyStore::generate().unwrap(),
            time: TestClock::new(),
        }
    }

    fn options(&self) -> CreateOptions {
        CreateOptions {
            kdf: KDF,
            clock: Some(self.time.clock()),
            device_name: None,
        }
    }

    fn create(&self) -> Vault {
        Vault::create(&self.path, PASSWORD, Some(&self.hardware), self.options()).unwrap()
    }

    fn open(&self) -> Vault {
        Vault::open_with_clock(&self.path, self.time.clock()).unwrap()
    }
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

fn login() -> Login {
    Login::new("Example", "alice@example.com", "hunter2-hunter2")
}

fn totp() -> TotpEntry {
    TotpEntry::new("Example", "alice", vec![1; 20])
}

fn locked(result: Result<impl Sized, VaultError>, domain: DomainId) -> bool {
    matches!(result, Err(VaultError::Locked(d)) if d == domain)
}

fn unlocked_domains(vault: &mut Vault) -> Vec<DomainId> {
    DomainId::ALL
        .into_iter()
        .filter(|&domain| vault.is_unlocked(domain))
        .collect()
}

#[test]
fn a_new_vault_is_unlocked_and_a_reopened_vault_is_locked() {
    let f = Fixture::new();
    let mut vault = f.create();
    assert_eq!(unlocked_domains(&mut vault), DomainId::ALL);
    let login_id = vault.insert(login()).unwrap();
    let totp_id = vault.insert(totp()).unwrap();
    let passkey_id = vault.insert(passkey()).unwrap();
    let (vault_id, device_id) = (vault.vault_id(), vault.device_id());
    drop(vault);

    let mut vault = f.open();
    assert_eq!((vault.vault_id(), vault.device_id()), (vault_id, device_id));
    assert_eq!(unlocked_domains(&mut vault), []);
    assert!(locked(vault.get::<Login>(login_id), DomainId::Password));
    assert!(locked(vault.get::<TotpEntry>(totp_id), DomainId::Totp));
    assert!(locked(
        vault.get::<PasskeyCredential>(passkey_id),
        DomainId::Passkey
    ));
    assert!(locked(vault.list::<Password>(), DomainId::Password));
    assert!(locked(vault.insert(login()), DomainId::Password));
    assert!(locked(
        vault.delete::<Password>(login_id),
        DomainId::Password
    ));
}

/// The acceptance test of P1-09: the master password opens the password domain
/// and nothing else.
#[test]
fn unlocking_the_password_domain_leaves_totp_and_passkey_locked() {
    let f = Fixture::new();
    let mut vault = f.create();
    let login_id = vault.insert(login()).unwrap();
    let totp_id = vault.insert(totp()).unwrap();
    let passkey_id = vault.insert(passkey()).unwrap();
    drop(vault);

    let mut vault = f.open();
    vault.unlock_password(PASSWORD).unwrap();

    assert_eq!(unlocked_domains(&mut vault), [DomainId::Password]);
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login());
    assert!(locked(vault.get::<TotpEntry>(totp_id), DomainId::Totp));
    assert!(locked(vault.list::<Totp>(), DomainId::Totp));
    assert!(locked(vault.insert(totp()), DomainId::Totp));
    assert!(locked(
        vault.get::<PasskeyCredential>(passkey_id),
        DomainId::Passkey
    ));
    assert!(locked(vault.list::<Passkey>(), DomainId::Passkey));
    assert!(locked(vault.delete::<Totp>(totp_id), DomainId::Totp));
}

#[test]
fn hardware_domains_unlock_one_at_a_time() {
    let f = Fixture::new();
    let mut vault = f.create();
    let totp_id = vault.insert(totp()).unwrap();
    let passkey_id = vault.insert(passkey()).unwrap();
    drop(vault);

    let mut vault = f.open();
    vault.unlock_hardware::<Totp>(&f.hardware).unwrap();
    assert_eq!(unlocked_domains(&mut vault), [DomainId::Totp]);
    assert_eq!(vault.get::<TotpEntry>(totp_id).unwrap(), totp());
    assert!(locked(
        vault.get::<PasskeyCredential>(passkey_id),
        DomainId::Passkey
    ));
    assert!(locked(vault.list::<Password>(), DomainId::Password));

    vault.unlock_hardware::<Passkey>(&f.hardware).unwrap();
    assert_eq!(
        vault.get::<PasskeyCredential>(passkey_id).unwrap(),
        passkey()
    );
    assert_eq!(
        unlocked_domains(&mut vault),
        [DomainId::Totp, DomainId::Passkey]
    );
}

#[test]
fn the_file_holds_no_password_slot_for_totp_or_passkey() {
    let f = Fixture::new();
    drop(f.create());
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    let slots: Vec<(u8, u8)> = conn
        .prepare("SELECT domain, kind FROM key_slots ORDER BY domain, kind")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    // (domain, kind): password domain by password; TOTP and passkey by hardware only.
    assert_eq!(slots, [(1, 1), (2, 2), (3, 2)]);
}

#[test]
fn a_wrong_master_password_unlocks_nothing() {
    let f = Fixture::new();
    drop(f.create());
    let mut vault = f.open();
    for wrong in [
        "correct horse battery stapl",
        "",
        "Correct horse battery staple",
    ] {
        assert!(matches!(
            vault.unlock_password(wrong),
            Err(VaultError::WrongPassword)
        ));
    }
    assert_eq!(unlocked_domains(&mut vault), []);
    vault.unlock_password(PASSWORD).unwrap();
}

#[test]
fn hardware_unlock_needs_the_user_and_the_right_device() {
    let f = Fixture::new();
    drop(f.create());
    let mut vault = f.open();

    f.hardware.set_user_present(false);
    let error = vault.unlock_hardware::<Totp>(&f.hardware).unwrap_err();
    assert!(is_user_cancelled(&error));
    assert!(!vault.is_unlocked(DomainId::Totp));
    f.hardware.set_user_present(true);

    let another_device = InsecureSoftwareKeyStore::generate().unwrap();
    assert!(matches!(
        vault.unlock_hardware::<Totp>(&another_device),
        Err(VaultError::Crypto(CryptoError::HardwareKey(
            HardwareKeyError::Decrypt
        )))
    ));
    assert!(!vault.is_unlocked(DomainId::Totp));

    vault.unlock_hardware::<Totp>(&f.hardware).unwrap();
    assert!(vault.is_unlocked(DomainId::Totp));
}

#[test]
fn domains_can_be_locked_individually_or_all_at_once() {
    let f = Fixture::new();
    let mut vault = f.create();
    let login_id = vault.insert(login()).unwrap();

    vault.lock(DomainId::Totp);
    assert_eq!(
        unlocked_domains(&mut vault),
        [DomainId::Password, DomainId::Passkey]
    );
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login());

    vault.lock_all();
    assert_eq!(unlocked_domains(&mut vault), []);
    assert!(locked(vault.get::<Login>(login_id), DomainId::Password));

    vault.unlock_password(PASSWORD).unwrap();
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login());
}

#[test]
fn a_vault_without_a_hardware_key_store_has_no_totp_or_passkey_domain() {
    let f = Fixture::new();
    let mut vault = Vault::create(&f.path, PASSWORD, None, f.options()).unwrap();
    assert_eq!(unlocked_domains(&mut vault), [DomainId::Password]);
    assert!(vault.has_domain(DomainId::Password).unwrap());
    assert!(!vault.has_domain(DomainId::Totp).unwrap());
    assert!(!vault.has_domain(DomainId::Passkey).unwrap());

    vault.insert(login()).unwrap();
    assert!(locked(vault.insert(totp()), DomainId::Totp));
    assert!(matches!(
        vault.unlock_hardware::<Totp>(&f.hardware),
        Err(VaultError::DomainUnavailable(DomainId::Totp))
    ));
}

#[test]
fn changing_the_master_password_keeps_the_items() {
    let f = Fixture::new();
    let mut vault = f.create();
    let login_id = vault.insert(login()).unwrap();
    let note_id = vault.insert(SecureNote::new("note", "body")).unwrap();
    let before = vault.kdf_params().unwrap();

    assert!(matches!(
        vault.change_master_password("not the password!", NEW_PASSWORD, KDF),
        Err(VaultError::WrongPassword)
    ));
    assert!(matches!(
        vault.change_master_password(PASSWORD, "too short", KDF),
        Err(VaultError::WeakPassword)
    ));
    // Nothing changed so far.
    vault.lock_all();
    vault.unlock_password(PASSWORD).unwrap();

    let stronger = KdfParams::new(KdfParams::MINIMUM.m_kib(), 3, 1).unwrap();
    vault
        .change_master_password(PASSWORD, NEW_PASSWORD, KdfChoice::Fixed(stronger))
        .unwrap();
    assert_eq!(vault.kdf_params().unwrap(), stronger);
    assert_ne!(vault.kdf_params().unwrap(), before);
    // The session stays unlocked across the change.
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login());
    drop(vault);

    let mut vault = f.open();
    assert!(matches!(
        vault.unlock_password(PASSWORD),
        Err(VaultError::WrongPassword)
    ));
    vault.unlock_password(NEW_PASSWORD).unwrap();
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login());
    assert_eq!(
        vault.get::<SecureNote>(note_id).unwrap(),
        SecureNote::new("note", "body")
    );
}

#[test]
fn the_master_password_can_be_changed_while_locked() {
    let f = Fixture::new();
    drop(f.create());
    let mut vault = f.open();
    vault
        .change_master_password(PASSWORD, NEW_PASSWORD, KDF)
        .unwrap();
    assert_eq!(
        unlocked_domains(&mut vault),
        [],
        "changing the password must not unlock"
    );
    vault.unlock_password(NEW_PASSWORD).unwrap();
}

#[test]
fn changing_the_master_password_does_not_touch_the_hardware_domains() {
    let f = Fixture::new();
    let mut vault = f.create();
    let totp_id = vault.insert(totp()).unwrap();
    vault
        .change_master_password(PASSWORD, NEW_PASSWORD, KDF)
        .unwrap();
    drop(vault);

    let mut vault = f.open();
    vault.unlock_password(NEW_PASSWORD).unwrap();
    assert!(locked(vault.get::<TotpEntry>(totp_id), DomainId::Totp));
    vault.unlock_hardware::<Totp>(&f.hardware).unwrap();
    assert_eq!(vault.get::<TotpEntry>(totp_id).unwrap(), totp());
}

#[test]
fn idle_domains_lock_themselves() {
    let f = Fixture::new();
    let mut vault = f.create();
    let login_id = vault.insert(login()).unwrap();
    let totp_id = vault.insert(totp()).unwrap();
    assert_eq!(
        vault.auto_lock(),
        AutoLock {
            password: Some(Duration::from_secs(300)),
            hardware: Some(Duration::from_secs(60)),
        }
    );

    // Activity keeps a domain unlocked: 59 s + 59 s with a use in between.
    f.time.advance(Duration::from_secs(59));
    assert_eq!(vault.get::<TotpEntry>(totp_id).unwrap(), totp());
    f.time.advance(Duration::from_secs(59));
    assert_eq!(vault.get::<TotpEntry>(totp_id).unwrap(), totp());

    // A full minute without use locks the hardware-bound domains only.
    f.time.advance(Duration::from_secs(60));
    assert!(locked(vault.get::<TotpEntry>(totp_id), DomainId::Totp));
    assert_eq!(unlocked_domains(&mut vault), [DomainId::Password]);
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login());

    // Five idle minutes lock the password domain as well.
    f.time.advance(Duration::from_secs(299));
    assert!(vault.is_unlocked(DomainId::Password));
    f.time.advance(Duration::from_secs(1));
    assert!(locked(vault.get::<Login>(login_id), DomainId::Password));
    assert_eq!(unlocked_domains(&mut vault), []);

    // Unlocking again starts a fresh idle period.
    vault.unlock_password(PASSWORD).unwrap();
    f.time.advance(Duration::from_secs(299));
    assert_eq!(vault.get::<Login>(login_id).unwrap(), login());
}

#[test]
fn auto_lock_is_configurable() {
    let f = Fixture::new();
    let mut vault = f.create();

    vault.set_auto_lock(AutoLock {
        password: None,
        hardware: Some(Duration::from_secs(5)),
    });
    f.time.advance(Duration::from_secs(24 * 60 * 60));
    assert_eq!(unlocked_domains(&mut vault), [DomainId::Password]);

    // Shortening the timeout applies immediately to an already idle domain.
    vault.set_auto_lock(AutoLock {
        password: Some(Duration::from_secs(10)),
        hardware: None,
    });
    assert_eq!(unlocked_domains(&mut vault), []);
}

fn assert_no_file(path: &Path) {
    assert!(
        !path.exists(),
        "a rejected creation must not leave a vault file behind"
    );
}

#[test]
fn weak_master_passwords_and_kdf_parameters_are_refused() {
    let f = Fixture::new();
    for weak in ["", "short", "elevenchars", "１１文字のパスワードだ"] {
        assert!(matches!(
            Vault::create(&f.path, weak, Some(&f.hardware), f.options()),
            Err(VaultError::WeakPassword)
        ));
        assert_no_file(&f.path);
    }

    let weak_kdf = KdfChoice::Fixed(KdfParams::new(1024, 1, 1).unwrap());
    let options = CreateOptions {
        kdf: weak_kdf,
        clock: None,
        device_name: None,
    };
    assert!(matches!(
        Vault::create(&f.path, PASSWORD, Some(&f.hardware), options),
        Err(VaultError::WeakKdf)
    ));
    assert_no_file(&f.path);

    // Twelve characters is enough, whatever the script.
    Vault::create(
        &f.path,
        "１２文字のパスワードです",
        Some(&f.hardware),
        f.options(),
    )
    .unwrap();
}

#[test]
fn a_failing_hardware_key_store_aborts_creation() {
    struct Broken;
    impl zp_crypto::HardwareKeyStore for Broken {
        fn wrap(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, HardwareKeyError> {
            Err(HardwareKeyError::Unavailable("no TPM".into()))
        }
        fn unwrap(
            &self,
            _: &[u8],
            _: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, HardwareKeyError> {
            Err(HardwareKeyError::Unavailable("no TPM".into()))
        }
    }

    let f = Fixture::new();
    assert!(matches!(
        Vault::create(&f.path, PASSWORD, Some(&Broken), f.options()),
        Err(VaultError::Crypto(CryptoError::HardwareKey(
            HardwareKeyError::Unavailable(_)
        )))
    ));
    assert_no_file(&f.path);
}

#[test]
fn creation_never_overwrites_and_opening_needs_a_vault() {
    let f = Fixture::new();
    drop(f.create());
    assert!(matches!(
        Vault::create(&f.path, PASSWORD, Some(&f.hardware), f.options()),
        Err(VaultError::AlreadyExists)
    ));
    // The existing vault is intact.
    f.open().unlock_password(PASSWORD).unwrap();

    let missing = f.path.with_file_name("missing.zpvault");
    assert!(matches!(Vault::open(&missing), Err(VaultError::NotFound)));
}

#[test]
fn calibrated_parameters_meet_the_minimum() {
    let f = Fixture::new();
    let options = CreateOptions {
        kdf: KdfChoice::Calibrate(Duration::from_millis(1)),
        clock: None,
        device_name: None,
    };
    let vault = Vault::create(&f.path, PASSWORD, None, options).unwrap();
    let params = vault.kdf_params().unwrap();
    assert!(params.meets_minimum());
    assert_eq!(params, KdfParams::DEFAULT);
}
