//! The API driven the way the Android app drives it: the app process's client
//! reaches an embedded vault process over streams in memory (socket pairs on
//! the phone), the key store is a stand-in, and the radio link to a desktop
//! vault is an in-memory stand-in for Bluetooth LE.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use zp_crypto::{InsecureSoftwareKeyStore, KdfParams};
use zp_ipc::{Client, memory_pair};
use zp_pairing::{Asking, OfferRole, PairingOffer};
use zp_transport::ble::tag_value;
use zp_transport::discovery::{slot_of, tag_for};
use zp_transport::{
    DriveConfig, Link, MemoryLink, PairingLink, pair_as_existing, sync_as_responder,
};
use zp_vault::model::{Login, TotpEntry};
use zp_vault::{CreateOptions, KdfChoice, Store, Vault};
use zp_vaultd::embedded::Engine;

use crate::client::{Connect, store_atomically};
use crate::{
    ByteLink, Domain, HardwareError, ItemContent, LinkError, PlatformKeyStore, Problem,
    VaultClient, ZpError, announces_pairing, ble_uuids, offer_info,
};

const PC_PASSWORD: &str = "the master password of the PC";
const PHONE_PASSWORD: &str = "the phone has its own password";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn problem(error: ZpError) -> Problem {
    error.problem()
}

/// What an app implements on top of its radio.
struct AppSide {
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
}

impl ByteLink for AppSide {
    fn read(&self, _timeout_ms: u32) -> Result<Vec<u8>, LinkError> {
        let mut buffer = vec![0u8; 4096];
        match self.reader.lock().unwrap().read(&mut buffer) {
            Ok(0) => Err(LinkError::Closed),
            Ok(count) => Ok(buffer[..count].to_vec()),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(Vec::new()),
            Err(_) => Err(LinkError::Closed),
        }
    }

    fn write(&self, bytes: Vec<u8>) -> Result<(), LinkError> {
        self.writer
            .lock()
            .unwrap()
            .write_all(&bytes)
            .map_err(|_| LinkError::Closed)
    }
}

/// A link between the desktop (a transport link) and the phone (a `ByteLink`).
fn link() -> (Box<dyn Link>, Arc<dyn ByteLink>) {
    let (desktop, phone) = MemoryLink::pair();
    let (reader, writer) = Box::new(phone).split().unwrap();
    let app = AppSide {
        reader: Mutex::new(reader),
        writer: Mutex::new(writer),
    };
    (Box::new(desktop), Arc::new(app))
}

/// A stand-in for the Android Keystore: a deterministic keyed function of the
/// challenge, which asks the "user" every time.
struct FakeKeyStore {
    secret: [u8; 32],
    prompts: AtomicU32,
    user_present: AtomicBool,
    available: AtomicBool,
}

impl FakeKeyStore {
    fn new(secret: u8) -> Arc<Self> {
        Arc::new(Self {
            secret: [secret; 32],
            prompts: AtomicU32::new(0),
            user_present: AtomicBool::new(true),
            available: AtomicBool::new(true),
        })
    }

    fn prompts(&self) -> u32 {
        self.prompts.load(Ordering::SeqCst)
    }
}

impl PlatformKeyStore for FakeKeyStore {
    fn probe(&self, _create: bool) -> Result<u8, HardwareError> {
        if self.available.load(Ordering::SeqCst) {
            Ok(0x04)
        } else {
            Err(HardwareError::Unavailable {
                reason: "no secure lock screen".into(),
            })
        }
    }

    fn sign(&self, challenge: Vec<u8>) -> Result<Vec<u8>, HardwareError> {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        if !self.user_present.load(Ordering::SeqCst) {
            return Err(HardwareError::Cancelled);
        }
        let mut out = self.secret;
        for (index, byte) in challenge.iter().enumerate() {
            let slot = index % 32;
            out[slot] = out[slot].wrapping_mul(131).wrapping_add(*byte);
        }
        Ok(out.to_vec())
    }
}

/// The app process with its vault process: a client of an embedded engine.
fn phone(path: &Path, key_store: Option<Arc<dyn PlatformKeyStore>>) -> VaultClient {
    let engine = Arc::new(Engine::new());
    let connect: Connect = Arc::new(move || {
        let (app_end, engine_end) = memory_pair();
        let engine = Arc::clone(&engine);
        thread::spawn(move || engine.converse(engine_end));
        Ok(Client::over(app_end, "test")?)
    });
    VaultClient::with(connect, path.to_path_buf(), key_store).unwrap()
}

fn titles(client: &VaultClient) -> Vec<String> {
    let mut titles: Vec<String> = client
        .list(Domain::Password, String::new())
        .unwrap()
        .items
        .into_iter()
        .map(|item| item.title)
        .collect();
    titles.sort();
    titles
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

struct Pc {
    _dir: tempfile::TempDir,
    path: PathBuf,
    phone_path: PathBuf,
    vault: Vault,
}

fn pc() -> Pc {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pc.zpvault");
    let phone_path = dir.path().join("phone").join("vault.zpvault");
    std::fs::create_dir(phone_path.parent().unwrap()).unwrap();
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        device_name: Some("PC".to_owned()),
        ..CreateOptions::default()
    };
    let vault = Vault::create(&path, PC_PASSWORD, Some(&hardware), options).unwrap();
    Pc {
        _dir: dir,
        path,
        phone_path,
        vault,
    }
}

/// The PC shows a code and the phone joins with it.
fn join(pc: Pc, client: &VaultClient) -> Pc {
    let Pc {
        _dir,
        path,
        phone_path,
        mut vault,
    } = pc;
    let key = vault.channel_key().unwrap();
    let offer =
        PairingOffer::new(OfferRole::Existing, *key.public_bytes(), Vec::new(), now()).unwrap();
    let code = offer.to_text().as_str().to_owned();
    let (pc_link, phone_link) = link();
    let psk = offer.psk.clone();
    let pc_side = thread::spawn(move || {
        let pairing = PairingLink {
            scanned: false,
            psk: &psk,
            offered_key: None,
        };
        pair_as_existing(
            pc_link,
            &mut vault,
            &pairing,
            |asking| matches!(asking, Asking::Join(request) if request.name == "Test phone"),
            &DriveConfig::default(),
        )
        .unwrap();
        vault
    });
    let joined = client
        .join(
            code,
            "Test phone".to_owned(),
            PHONE_PASSWORD.to_owned(),
            false,
            phone_link,
        )
        .unwrap();
    let vault = pc_side.join().unwrap();
    assert_eq!(joined.vault_id, vault.vault_id().to_string());
    assert_eq!(joined.first_sync_error, None);
    Pc {
        _dir,
        path,
        phone_path,
        vault,
    }
}

#[test]
fn a_phone_joins_writes_and_syncs_through_its_vault_process() {
    let mut pc = pc();
    let from_pc = pc
        .vault
        .insert(Login::new("Mail", "alice", "pc-secret"))
        .unwrap();
    let mut totp = TotpEntry::new("Mail", "alice", b"12345678901234567890".to_vec());
    totp.login_item_id = from_pc.as_bytes().to_vec();
    pc.vault.insert(totp).unwrap();

    // The code and the tag the phone looks for.
    let key = pc.vault.channel_key().unwrap();
    let offer =
        PairingOffer::new(OfferRole::Existing, *key.public_bytes(), Vec::new(), now()).unwrap();
    let info = offer_info(offer.to_text().as_str().to_owned()).unwrap();
    let shown = tag_value(None, Some(zp_transport::ble::pairing_tag(&offer.psk)));
    assert!(announces_pairing(shown.to_vec(), info.pairing_tag.clone()));
    assert!(!announces_pairing(
        tag_value(None, None).to_vec(),
        info.pairing_tag
    ));
    assert_eq!(
        problem(offer_info("ZP1:not-a-code".to_owned()).unwrap_err()),
        Problem::BadCode
    );

    let store = FakeKeyStore::new(7);
    let client = phone(&pc.phone_path, Some(store.clone()));
    assert!(!client.status().unwrap().exists);
    let pc = join(pc, &client);

    // The app stored the vault file; nothing in it is readable.
    let file = std::fs::read(&pc.phone_path).unwrap();
    assert!(!contains(&file, b"pc-secret"));
    assert!(!contains(&file, b"alice"));
    let status = client.status().unwrap();
    assert!(status.exists);
    assert!(status.domains.iter().all(|domain| domain.available));

    // Joining left the password domain open. The phone's own password, and
    // the PC's login.
    client.lock(None).unwrap();
    assert_eq!(
        problem(client.unlock_password(PC_PASSWORD.to_owned()).unwrap_err()),
        Problem::WrongPassword
    );
    assert_eq!(
        problem(client.list(Domain::Password, String::new()).unwrap_err()),
        Problem::Locked
    );
    client.unlock_password(PHONE_PASSWORD.to_owned()).unwrap();
    let logins = client.list(Domain::Password, String::new()).unwrap();
    assert_eq!(logins.items.len(), 1);
    assert_eq!(logins.items[0].id, from_pc.to_string());
    match client.get(from_pc.to_string()).unwrap() {
        ItemContent::Login { password, .. } => assert_eq!(password, "pc-secret"),
        other => panic!("not a login: {other:?}"),
    }

    // The one-time codes open with the key store only, which asks every time.
    assert_eq!(
        problem(client.list(Domain::Totp, String::new()).unwrap_err()),
        Problem::Locked
    );
    let prompts = store.prompts();
    store.user_present.store(false, Ordering::SeqCst);
    assert_eq!(
        problem(client.unlock(Domain::Totp).unwrap_err()),
        Problem::Cancelled
    );
    store.user_present.store(true, Ordering::SeqCst);
    client.unlock(Domain::Totp).unwrap();
    assert_eq!(store.prompts(), prompts + 2);
    let codes = client.list(Domain::Totp, String::new()).unwrap();
    assert_eq!(codes.items.len(), 1);
    let code = client.totp_code(codes.items[0].id.clone()).unwrap();
    assert_eq!(code.code.len(), 6);

    let devices = client.devices().unwrap();
    assert_eq!(devices.len(), 2);

    // Both sides change something; the phone finds the PC by its tag.
    let from_phone = client
        .add_login(
            "Shop".into(),
            "bob".into(),
            "phone-secret".into(),
            vec![],
            String::new(),
        )
        .unwrap();
    client.delete(from_pc.to_string()).unwrap();
    let Pc {
        _dir,
        path,
        phone_path,
        mut vault,
    } = pc;
    let later = vault.insert(Login::new("Bank", "carol", "later")).unwrap();
    client.lock(None).unwrap();

    let pc_tag = tag_for(&vault.vault_id(), key.public_bytes(), slot_of(now()));
    let peer = client
        .recognise_peer(tag_value(Some(pc_tag), None).to_vec())
        .unwrap()
        .unwrap();
    assert_eq!(peer.device_id, vault.device_id().to_string());
    assert_eq!(peer.name, "PC");
    for value in [
        tag_value(Some([9; 8]), None).to_vec(),
        tag_value(None, None).to_vec(),
        vec![1],
    ] {
        assert!(client.recognise_peer(value).unwrap().is_none());
    }
    assert_eq!(client.other_devices().unwrap().len(), 1);

    // Sync on the locked vaults of both.
    drop(vault);
    let (pc_link, phone_link) = link();
    let pc_file = path.clone();
    let pc_side = thread::spawn(move || {
        let mut store = Store::open(&pc_file).unwrap();
        let key = store.channel_key().unwrap();
        sync_as_responder(pc_link, &mut store, &key, &DriveConfig::default()).unwrap()
    });
    let outcome = client.sync_with(peer.device_id, phone_link).unwrap();
    pc_side.join().unwrap();
    assert_eq!((outcome.sent, outcome.received), (2, 1));

    let mut vault = Vault::open(&path).unwrap();
    vault.unlock_password(PC_PASSWORD).unwrap();
    let from_phone = zp_crypto::ItemId::from_bytes(crate::parse_hex(&from_phone).unwrap());
    assert_eq!(
        vault.get::<Login>(from_phone).unwrap().password,
        "phone-secret"
    );
    assert!(vault.get::<Login>(from_pc).is_err());

    // A new vault process, as after Android ended the old one: the stored file.
    drop(client);
    let client = phone(&phone_path, Some(store.clone()));
    let status = client.status().unwrap();
    assert!(status.exists && status.domains.iter().all(|domain| !domain.unlocked));
    client.unlock_password(PHONE_PASSWORD.to_owned()).unwrap();
    assert_eq!(titles(&client), ["Bank", "Shop"]);
    match client.get(later.to_string()).unwrap() {
        ItemContent::Login { password, .. } => assert_eq!(password, "later"),
        other => panic!("not a login: {other:?}"),
    }

    // A device that is not in the vault cannot be synced with.
    let (_pc_link, phone_link) = link();
    assert!(client.sync_with("00".repeat(16), phone_link).is_err());
}

#[test]
fn a_phone_makes_its_own_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let store = FakeKeyStore::new(3);

    // Without a usable key store, the vault is not made by mistake without
    // the TOTP and passkey domains.
    store.available.store(false, Ordering::SeqCst);
    let client = phone(&path, Some(store.clone()));
    assert_eq!(
        problem(
            client
                .create(PHONE_PASSWORD.into(), "Phone".into(), false)
                .unwrap_err()
        ),
        Problem::HardwareUnavailable
    );
    assert!(!path.exists());
    store.available.store(true, Ordering::SeqCst);

    assert_eq!(
        problem(
            client
                .create("short".into(), String::new(), false)
                .unwrap_err()
        ),
        Problem::WeakPassword
    );
    let status = client
        .create(PHONE_PASSWORD.into(), "Phone".into(), false)
        .unwrap();
    assert!(status.domains.iter().all(|domain| domain.available));
    assert!(path.exists());
    let devices = client.devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "Phone");
    assert_eq!(
        problem(
            client
                .create(PHONE_PASSWORD.into(), "Phone".into(), false)
                .unwrap_err()
        ),
        Problem::VaultExists
    );

    let note = client
        .add_note("Wi-Fi".into(), "the door code is 1234".into())
        .unwrap();
    client
        .update_note(note.clone(), "Wi-Fi".into(), "now 5678".into())
        .unwrap();
    match client.get(note).unwrap() {
        ItemContent::Note { body, .. } => assert_eq!(body, "now 5678"),
        other => panic!("not a note: {other:?}"),
    }
    let kit = client.create_recovery_kit(false).unwrap();
    assert!(!kit.is_empty());
    assert_eq!(
        problem(client.create_recovery_kit(false).unwrap_err()),
        Problem::RecoveryKitExists
    );
    assert!(client.status().unwrap().has_recovery_kit);
    assert!(!contains(&std::fs::read(&path).unwrap(), b"door code"));

    // Without a key store at all, only the password domain.
    let other = dir.path().join("other.zpvault");
    let client = phone(&other, None);
    assert_eq!(
        problem(
            client
                .create(PHONE_PASSWORD.into(), "Phone".into(), false)
                .unwrap_err()
        ),
        Problem::HardwareUnavailable
    );
    let status = client
        .create(PHONE_PASSWORD.into(), String::new(), true)
        .unwrap();
    let available: Vec<Domain> = status
        .domains
        .iter()
        .filter(|domain| domain.available)
        .map(|domain| domain.domain)
        .collect();
    assert_eq!(available, [Domain::Password]);
}

#[test]
fn a_damaged_file_is_not_taken_for_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    std::fs::write(&path, [0x42; 4096]).unwrap();
    let engine = Arc::new(Engine::new());
    let connect: Connect = Arc::new(move || {
        let (app_end, engine_end) = memory_pair();
        let engine = Arc::clone(&engine);
        thread::spawn(move || engine.converse(engine_end));
        Ok(Client::over(app_end, "test")?)
    });
    assert!(VaultClient::with(connect, path.clone(), None).is_err());
    // Left as it was.
    assert_eq!(std::fs::read(&path).unwrap(), [0x42; 4096]);
}

#[test]
fn the_file_is_replaced_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    store_atomically(&path, b"first").unwrap();
    store_atomically(&path, b"second, longer").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"second, longer");
    assert!(!dir.path().join("vault.zpvault.tmp").exists());
}

#[test]
fn the_uuids_are_those_of_the_specification() {
    let uuids = ble_uuids();
    assert_eq!(uuids.service, "5a50c0de-0001-4b1d-9c5e-7a65726f7061");
    assert_eq!(uuids.tag, "5a50c0de-0002-4b1d-9c5e-7a65726f7061");
    assert_eq!(uuids.rx, "5a50c0de-0003-4b1d-9c5e-7a65726f7061");
    assert_eq!(uuids.tx, "5a50c0de-0004-4b1d-9c5e-7a65726f7061");
}

#[test]
fn other_apps_get_logins_and_passkeys_through_the_vault_process() {
    use crate::{PasskeyCreation, PasskeyRequest};

    let dir = tempfile::tempdir().unwrap();
    let store = FakeKeyStore::new(9);
    let client = phone(&dir.path().join("vault.zpvault"), Some(store.clone()));
    client
        .create(PHONE_PASSWORD.into(), "Phone".into(), false)
        .unwrap();

    // An app's login, saved from the app and filled into it only.
    let app = "androidapp://com.example.bank".to_owned();
    let id = client
        .save_page_login(
            app.clone(),
            String::new(),
            "alice".into(),
            "app-secret".into(),
        )
        .unwrap();
    let logins = client.page_logins(app.clone()).unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].id, id);
    assert!(
        client
            .page_logins("androidapp://com.evil".into())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        client
            .page_credential(app.clone(), id.clone())
            .unwrap()
            .password,
        "app-secret"
    );
    assert_eq!(
        problem(
            client
                .page_credential("https://example.com".into(), id.clone())
                .unwrap_err()
        ),
        Problem::Denied
    );
    let comparison = client
        .compare_page_login(app.clone(), "alice".into(), "new-secret".into())
        .unwrap();
    assert_eq!(
        (comparison.id.as_deref(), comparison.same),
        (Some(id.as_str()), false)
    );
    client
        .update_page_login(app.clone(), id.clone(), "new-secret".into())
        .unwrap();
    assert!(
        client
            .compare_page_login(app, "alice".into(), "new-secret".into())
            .unwrap()
            .same
    );

    // A passkey for a page whose browser makes the client data.
    let hash = vec![7; 32];
    let prompts = store.prompts();
    let made = client
        .create_passkey(PasskeyCreation {
            origin: "https://login.example.com".into(),
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            user_handle: b"alice".to_vec(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            challenge: b"registration".to_vec(),
            algorithms: vec![-7],
            exclude: vec![],
            client_data_hash: Some(hash.clone()),
        })
        .unwrap();
    assert!(made.client_data_json.is_empty());
    assert_eq!(store.prompts(), prompts + 1);

    let request = PasskeyRequest {
        origin: "https://login.example.com".into(),
        rp_id: "example.com".into(),
        challenge: b"sign in".to_vec(),
        allow: vec![],
        client_data_hash: Some(hash),
    };
    let choices = client.passkey_choices(request.clone()).unwrap();
    assert_eq!(choices.len(), 1);
    assert_eq!(choices[0].user_name, "alice");
    assert_eq!(store.prompts(), prompts + 2);
    let signed = client
        .sign_with_passkey(request.clone(), choices[0].credential_id.clone())
        .unwrap();
    assert_eq!(signed.credential_id, made.credential_id);
    assert!(signed.client_data_json.is_empty());
    assert_eq!(store.prompts(), prompts + 2, "the pick is not asked again");

    // A phishing page cannot use the site's relying party.
    let phishing = PasskeyRequest {
        origin: "https://example.com.evil.net".into(),
        ..request
    };
    assert_eq!(
        problem(client.passkey_choices(phishing).unwrap_err()),
        Problem::Denied
    );
}
