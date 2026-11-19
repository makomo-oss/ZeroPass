//! Cross-device passkey synchronization tests (PLAN.md P5-05):
//!
//! - Device A registers ES256 and EdDSA passkeys -> pairs with Device B (distinct
//!   master password and distinct hardware key store) -> syncs ciphertext ops
//!   while all domains are locked -> Device B unlocks ONLY the Passkey domain and
//!   signs valid WebAuthn assertions verified against Device A's registration
//!   public keys.
//! - Bidirectional sync and discoverable-credential replacement across devices.
//! - Device revocation rotates VK-K: remaining peers keep signing old and new
//!   passkeys, while the revoked device is refused sync and cannot decrypt or
//!   sign post-revocation passkeys even if it obtains their ciphertext ops.
//! - Recovery Kit restore preserves synced passkeys under a new device's
//!   hardware key store.

#![allow(clippy::unwrap_used, reason = "test code may panic")]

use std::path::{Path, PathBuf};

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams, Passkey};
use zp_passkey::{
    Algorithm, COSE_ALG_EDDSA, COSE_ALG_ES256, CeremonyType, FLAGS_GET_ASSERTION,
    GetAssertionRequest, MakeCredentialRequest, PasskeyError, SIGN_COUNT, build_client_data_json,
    find_credentials, get_assertion, make_credential, verify_assertion,
};
use zp_sync::{InMemoryError, OpLog, SyncError, sync_in_memory};
use zp_vault::{CreateOptions, JoinIdentity, KdfChoice, Store, Vault, VaultError};

const PASSWORD_A: &str = "device A master password";
const PASSWORD_B: &str = "device B completely different password";
const PASSWORD_C: &str = "device C third master password";
const PASSWORD_RECOVERED: &str = "recovered device master password";

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
    hardware: InsecureSoftwareKeyStore,
    vault: Vault,
}

fn create_device(name: &str, password: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{name}.zpvault"));
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let vault = Vault::create(&path, password, Some(&hardware), options(name)).unwrap();
    Device {
        _dir: dir,
        path,
        hardware,
        vault,
    }
}

fn join_device(existing: &mut Device, name: &str, password: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{name}.zpvault"));
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
        password,
        Some(&hardware),
        options(name),
    )
    .unwrap();
    Device {
        _dir: dir,
        path,
        hardware,
        vault,
    }
}

/// Syncs two vault files the way `zp-syncd` does: ciphertext only, no keys.
fn try_sync(a: &Path, b: &Path) -> Result<(), InMemoryError<VaultError, VaultError>> {
    let (mut store_a, mut store_b) = (Store::open(a).unwrap(), Store::open(b).unwrap());
    sync_in_memory(&mut store_a, &mut store_b).map(|_| ())
}

fn sync(a: &Path, b: &Path) {
    try_sync(a, b).unwrap();
}

/// Copies raw ciphertext ops from `src` to `dst` bypassing revocation checks,
/// simulating a revoked device obtaining ciphertext from the wire or a backup.
fn leak_ops(src: &Path, dst: &Path) {
    let src_store = Store::open(src).unwrap();
    let mut dst_store = Store::open(dst).unwrap();
    let vv = src_store.version_vector().unwrap();
    let mut ops = Vec::new();
    for (device, _) in vv.iter() {
        ops.extend(src_store.ops_after(device, 0, usize::MAX).unwrap());
    }
    dst_store.apply(ops).unwrap();
}

fn hash_challenge(ty: CeremonyType, challenge: &[u8], origin: &str) -> [u8; 32] {
    build_client_data_json(ty, challenge, origin, false).1
}

#[test]
fn passkeys_sync_between_two_devices_and_authenticate_both_ways() {
    let mut pc_a = create_device("pc-a", PASSWORD_A);

    // 1. PC A registers both an ES256 and an EdDSA passkey on webauthn.io.
    let alice = make_credential(
        &mut pc_a.vault,
        &MakeCredentialRequest {
            rp_id: "webauthn.io".into(),
            rp_name: "webauthn.io".into(),
            user_handle: b"alice-handle".to_vec(),
            user_name: "alice@example.com".into(),
            user_display_name: "Alice".into(),
            algorithms: vec![COSE_ALG_ES256],
            exclude_credential_ids: Vec::new(),
            client_data_hash: hash_challenge(
                CeremonyType::Create,
                b"reg-a-1",
                "https://webauthn.io",
            ),
        },
    )
    .unwrap();
    assert_eq!(alice.algorithm, Algorithm::Es256);

    let bob = make_credential(
        &mut pc_a.vault,
        &MakeCredentialRequest {
            rp_id: "webauthn.io".into(),
            rp_name: "webauthn.io".into(),
            user_handle: b"bob-handle".to_vec(),
            user_name: "bob@example.com".into(),
            user_display_name: "Bob".into(),
            algorithms: vec![COSE_ALG_EDDSA],
            exclude_credential_ids: Vec::new(),
            client_data_hash: hash_challenge(
                CeremonyType::Create,
                b"reg-a-2",
                "https://webauthn.io",
            ),
        },
    )
    .unwrap();
    assert_eq!(bob.algorithm, Algorithm::EdDsa);

    // 2. PC B pairs with its own master password and its own hardware key store.
    let mut pc_b = join_device(&mut pc_a, "pc-b", PASSWORD_B);
    assert_ne!(pc_a.vault.device_id(), pc_b.vault.device_id());

    // 3. Lock every domain on both devices, then sync ciphertext ops.
    pc_a.vault.lock_all();
    pc_b.vault.lock_all();
    sync(&pc_a.path, &pc_b.path);

    // 4. Unlock ONLY the Passkey domain on PC B (Password & TOTP stay locked).
    pc_b.vault
        .unlock_hardware::<Passkey>(&pc_b.hardware)
        .unwrap();
    assert!(!pc_b.vault.is_unlocked(DomainId::Password));
    assert!(!pc_b.vault.is_unlocked(DomainId::Totp));
    assert!(pc_b.vault.is_unlocked(DomainId::Passkey));

    let candidates = find_credentials(&mut pc_b.vault, "webauthn.io", &[]).unwrap();
    assert_eq!(candidates.len(), 2);

    // 5. PC B signs assertions for both synced passkeys and the RP verifies them
    //    against the public keys registered on PC A.
    let alice_hash = hash_challenge(CeremonyType::Get, b"auth-b-alice", "https://webauthn.io");
    let alice_assertion = get_assertion(
        &mut pc_b.vault,
        &GetAssertionRequest {
            rp_id: "webauthn.io".into(),
            client_data_hash: alice_hash,
            allow_credential_ids: vec![alice.credential_id.clone()],
            credential_id: None,
        },
    )
    .unwrap();
    assert_eq!(alice_assertion.credential_id, alice.credential_id);
    assert_eq!(alice_assertion.user_handle, b"alice-handle");
    assert_eq!(alice_assertion.authenticator_data[32], FLAGS_GET_ASSERTION);
    assert_eq!(
        u32::from_be_bytes(
            alice_assertion.authenticator_data[33..37]
                .try_into()
                .unwrap()
        ),
        SIGN_COUNT
    );
    verify_assertion(
        "webauthn.io",
        Algorithm::Es256,
        &alice.public_key.spki_der,
        &alice_hash,
        &alice_assertion.authenticator_data,
        &alice_assertion.signature,
    )
    .unwrap();

    let bob_hash = hash_challenge(CeremonyType::Get, b"auth-b-bob", "https://webauthn.io");
    let bob_assertion = get_assertion(
        &mut pc_b.vault,
        &GetAssertionRequest {
            rp_id: "webauthn.io".into(),
            client_data_hash: bob_hash,
            allow_credential_ids: Vec::new(),
            credential_id: Some(bob.credential_id.clone()),
        },
    )
    .unwrap();
    assert_eq!(bob_assertion.credential_id, bob.credential_id);
    assert_eq!(bob_assertion.user_handle, b"bob-handle");
    verify_assertion(
        "webauthn.io",
        Algorithm::EdDsa,
        &bob.public_key.spki_der,
        &bob_hash,
        &bob_assertion.authenticator_data,
        &bob_assertion.signature,
    )
    .unwrap();

    // 6. Reverse direction: PC B registers a new passkey (carol) and replaces
    //    alice's discoverable passkey on webauthn.io.
    let carol = make_credential(
        &mut pc_b.vault,
        &MakeCredentialRequest {
            rp_id: "app.example.com".into(),
            rp_name: "Example App".into(),
            user_handle: b"carol-handle".to_vec(),
            user_name: "carol@example.com".into(),
            user_display_name: "Carol".into(),
            algorithms: vec![COSE_ALG_EDDSA],
            exclude_credential_ids: Vec::new(),
            client_data_hash: hash_challenge(
                CeremonyType::Create,
                b"reg-b-carol",
                "https://app.example.com",
            ),
        },
    )
    .unwrap();

    let alice_v2 = make_credential(
        &mut pc_b.vault,
        &MakeCredentialRequest {
            rp_id: "webauthn.io".into(),
            rp_name: "webauthn.io".into(),
            user_handle: b"alice-handle".to_vec(),
            user_name: "alice@example.com".into(),
            user_display_name: "Alice".into(),
            algorithms: vec![COSE_ALG_ES256],
            exclude_credential_ids: Vec::new(),
            client_data_hash: hash_challenge(
                CeremonyType::Create,
                b"reg-b-a2",
                "https://webauthn.io",
            ),
        },
    )
    .unwrap();
    assert_eq!(alice_v2.item_id, alice.item_id);
    assert_ne!(alice_v2.credential_id, alice.credential_id);

    // Sync B -> A while both are locked.
    pc_b.vault.lock_all();
    sync(&pc_a.path, &pc_b.path);

    // PC A unlocks ONLY Passkey domain and verifies both changes.
    pc_a.vault
        .unlock_hardware::<Passkey>(&pc_a.hardware)
        .unwrap();
    let carol_hash = hash_challenge(
        CeremonyType::Get,
        b"auth-a-carol",
        "https://app.example.com",
    );
    let carol_assertion = get_assertion(
        &mut pc_a.vault,
        &GetAssertionRequest {
            rp_id: "app.example.com".into(),
            client_data_hash: carol_hash,
            allow_credential_ids: Vec::new(),
            credential_id: None,
        },
    )
    .unwrap();
    verify_assertion(
        "app.example.com",
        Algorithm::EdDsa,
        &carol.public_key.spki_der,
        &carol_hash,
        &carol_assertion.authenticator_data,
        &carol_assertion.signature,
    )
    .unwrap();

    // Alice's old credential ID was replaced and is no longer accepted.
    let stale_err = get_assertion(
        &mut pc_a.vault,
        &GetAssertionRequest {
            rp_id: "webauthn.io".into(),
            client_data_hash: alice_hash,
            allow_credential_ids: vec![alice.credential_id.clone()],
            credential_id: None,
        },
    )
    .unwrap_err();
    assert!(matches!(stale_err, PasskeyError::CredentialNotFound));

    // Alice's replacement credential signs and verifies with PC B's new key.
    let alice_v2_hash = hash_challenge(CeremonyType::Get, b"auth-a-a2", "https://webauthn.io");
    let alice_v2_assertion = get_assertion(
        &mut pc_a.vault,
        &GetAssertionRequest {
            rp_id: "webauthn.io".into(),
            client_data_hash: alice_v2_hash,
            allow_credential_ids: vec![alice_v2.credential_id.clone()],
            credential_id: None,
        },
    )
    .unwrap();
    verify_assertion(
        "webauthn.io",
        Algorithm::Es256,
        &alice_v2.public_key.spki_der,
        &alice_v2_hash,
        &alice_v2_assertion.authenticator_data,
        &alice_v2_assertion.signature,
    )
    .unwrap();
}

#[test]
fn revoked_device_cannot_decrypt_or_sign_post_revocation_passkeys() {
    let mut pc_a = create_device("pc-a", PASSWORD_A);
    let before = make_credential(
        &mut pc_a.vault,
        &MakeCredentialRequest {
            rp_id: "before.example".into(),
            rp_name: "Before".into(),
            user_handle: b"u-before".to_vec(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            algorithms: vec![COSE_ALG_ES256],
            exclude_credential_ids: Vec::new(),
            client_data_hash: [0x11; 32],
        },
    )
    .unwrap();

    let mut pc_b = join_device(&mut pc_a, "pc-b", PASSWORD_B);
    let mut pc_c = join_device(&mut pc_a, "pc-c", PASSWORD_C);
    sync(&pc_a.path, &pc_b.path);
    sync(&pc_a.path, &pc_c.path);

    // PC A revokes PC B (rotating VK-K to epoch 2) and creates a new passkey.
    let pc_b_id = pc_b.vault.device_id();
    pc_a.vault.revoke_device(pc_b_id).unwrap();
    let after = make_credential(
        &mut pc_a.vault,
        &MakeCredentialRequest {
            rp_id: "after.example".into(),
            rp_name: "After".into(),
            user_handle: b"u-after".to_vec(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            algorithms: vec![COSE_ALG_EDDSA],
            exclude_credential_ids: Vec::new(),
            client_data_hash: [0x22; 32],
        },
    )
    .unwrap();

    // Non-revoked PC C syncs key updates + ops and can sign both old (epoch 1)
    // and new (epoch 2) passkeys.
    sync(&pc_a.path, &pc_c.path);
    let auth_before = get_assertion(
        &mut pc_c.vault,
        &GetAssertionRequest {
            rp_id: "before.example".into(),
            client_data_hash: [0x33; 32],
            allow_credential_ids: Vec::new(),
            credential_id: None,
        },
    )
    .unwrap();
    verify_assertion(
        "before.example",
        Algorithm::Es256,
        &before.public_key.spki_der,
        &[0x33; 32],
        &auth_before.authenticator_data,
        &auth_before.signature,
    )
    .unwrap();

    let auth_after = get_assertion(
        &mut pc_c.vault,
        &GetAssertionRequest {
            rp_id: "after.example".into(),
            client_data_hash: [0x44; 32],
            allow_credential_ids: Vec::new(),
            credential_id: None,
        },
    )
    .unwrap();
    verify_assertion(
        "after.example",
        Algorithm::EdDsa,
        &after.public_key.spki_der,
        &[0x44; 32],
        &auth_after.authenticator_data,
        &auth_after.signature,
    )
    .unwrap();

    // Syncing with revoked PC B is refused.
    assert!(matches!(
        try_sync(&pc_a.path, &pc_b.path),
        Err(
            InMemoryError::A(VaultError::Sync(SyncError::RevokedDevice(_)))
                | InMemoryError::B(VaultError::Sync(SyncError::RevokedDevice(_)))
        )
    ));

    // Even if PC B obtains the raw post-revocation ciphertext ops directly, it
    // lacks epoch-2 VK-K and cannot decrypt or sign the new passkey.
    leak_ops(&pc_a.path, &pc_b.path);
    let err = pc_b
        .vault
        .get_content::<Passkey>(after.item_id)
        .unwrap_err();
    assert!(
        matches!(
            err,
            VaultError::KeyGenerationUnavailable {
                domain: DomainId::Passkey,
                epoch: 2
            }
        ),
        "unexpected error: {err:?}"
    );
    let assert_err = get_assertion(
        &mut pc_b.vault,
        &GetAssertionRequest {
            rp_id: "after.example".into(),
            client_data_hash: [0x44; 32],
            allow_credential_ids: vec![after.credential_id],
            credential_id: None,
        },
    )
    .unwrap_err();
    assert!(
        matches!(
            assert_err,
            PasskeyError::Vault(VaultError::KeyGenerationUnavailable {
                domain: DomainId::Passkey,
                epoch: 2
            })
        ),
        "unexpected assertion error: {assert_err:?}"
    );
}

#[test]
fn passkeys_survive_recovery_kit_restore_on_a_new_device() {
    let mut pc_a = create_device("pc-a", PASSWORD_A);
    let kit = pc_a.vault.create_recovery_kit().unwrap();
    let created = make_credential(
        &mut pc_a.vault,
        &MakeCredentialRequest {
            rp_id: "webauthn.io".into(),
            rp_name: "webauthn.io".into(),
            user_handle: b"recover-me".to_vec(),
            user_name: "alice@example.com".into(),
            user_display_name: "Alice".into(),
            algorithms: vec![COSE_ALG_ES256],
            exclude_credential_ids: Vec::new(),
            client_data_hash: [0x55; 32],
        },
    )
    .unwrap();

    // Copy the vault file to a fresh directory and recover with a new hardware
    // key store and master password.
    let dir_new = tempfile::tempdir().unwrap();
    let recovered_path = dir_new.path().join("recovered.zpvault");
    std::fs::copy(&pc_a.path, &recovered_path).unwrap();
    let new_hw = InsecureSoftwareKeyStore::generate().unwrap();
    let mut recovered = Vault::recover(
        &recovered_path,
        &kit,
        PASSWORD_RECOVERED,
        Some(&new_hw),
        options("recovered-pc"),
    )
    .unwrap();

    // Reopen and unlock only the Passkey domain with the new device's key store.
    recovered.lock_all();
    recovered.unlock_hardware::<Passkey>(&new_hw).unwrap();

    let hash = hash_challenge(CeremonyType::Get, b"post-recovery", "https://webauthn.io");
    let assertion = get_assertion(
        &mut recovered,
        &GetAssertionRequest {
            rp_id: "webauthn.io".into(),
            client_data_hash: hash,
            allow_credential_ids: Vec::new(),
            credential_id: None,
        },
    )
    .unwrap();
    assert_eq!(assertion.credential_id, created.credential_id);
    verify_assertion(
        "webauthn.io",
        Algorithm::Es256,
        &created.public_key.spki_der,
        &hash,
        &assertion.authenticator_data,
        &assertion.signature,
    )
    .unwrap();
}
