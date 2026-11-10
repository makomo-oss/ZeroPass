//! TOTP codes through the vault: the seed lives in the TOTP domain, so a code can
//! only be produced after the hardware key store has unlocked that domain.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams};
use zp_vault::model::{Login, TotpEntry};
use zp_vault::totp::{self, TotpError};
use zp_vault::{Clock, CreateOptions, KdfChoice, Vault, VaultError};

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn a_totp_code_requires_the_totp_domain_to_be_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let now_ms = Arc::new(AtomicU64::new(59_000));
    let source = Arc::clone(&now_ms);
    let clock = Clock::from_fn(move || source.load(Ordering::SeqCst));
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: Some(clock.clone()),
    };

    let mut vault = Vault::create(&path, PASSWORD, Some(&hardware), options).unwrap();
    let login_id = vault
        .insert(Login::new("RFC", "test", "a login password"))
        .unwrap();
    // The RFC 6238 SHA-1 test secret, scanned from a QR code.
    let entry = totp::parse_otpauth_uri(
        "otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
    )
    .unwrap()
    .for_login(login_id);
    let totp_id = vault.insert(entry).unwrap();
    drop(vault);

    let mut vault = Vault::open_with_clock(&path, clock).unwrap();
    vault.unlock_password(PASSWORD).unwrap();
    assert!(matches!(
        vault.totp_code(totp_id),
        Err(VaultError::Locked(DomainId::Totp))
    ));

    hardware.set_user_present(false);
    assert!(vault.unlock_hardware::<zp_crypto::Totp>(&hardware).is_err());
    assert!(matches!(
        vault.totp_code(totp_id),
        Err(VaultError::Locked(DomainId::Totp))
    ));

    hardware.set_user_present(true);
    vault.unlock_hardware::<zp_crypto::Totp>(&hardware).unwrap();
    let code = vault.totp_code(totp_id).unwrap();
    assert_eq!(code.as_str(), "94287082");
    assert_eq!(code.seconds_remaining(), 1);

    // One second later the next time step begins.
    now_ms.store(60_000, Ordering::SeqCst);
    let code = vault.totp_code(totp_id).unwrap();
    assert_ne!(code.as_str(), "94287082");
    assert_eq!(code.seconds_remaining(), 30);

    // The linked login is reachable from the entry.
    assert_eq!(
        vault.get::<TotpEntry>(totp_id).unwrap().login(),
        Some(login_id)
    );
    // A login is not a TOTP entry.
    assert!(matches!(
        vault.totp_code(login_id),
        Err(VaultError::DomainMismatch)
    ));
}

#[test]
fn an_invalid_stored_entry_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
    };
    let mut vault = Vault::create(
        &dir.path().join("v.zpvault"),
        PASSWORD,
        Some(&hardware),
        options,
    )
    .unwrap();

    let mut entry = TotpEntry::new("Example", "alice", vec![1; 20]);
    entry.digits = 12;
    let id = vault.insert(entry).unwrap();
    assert!(matches!(
        vault.totp_code(id),
        Err(VaultError::Totp(TotpError::InvalidDigits))
    ));
}
