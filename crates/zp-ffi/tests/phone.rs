//! The mobile API driven the way an app drives it, against a desktop vault:
//! the link is an in-memory stand-in for Bluetooth LE.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use zp_crypto::{InsecureSoftwareKeyStore, KdfParams};
use zp_ffi::{
    ByteLink, FfiError, LinkError, MobileVault, announces_pairing, ble_uuids, join_vault,
    offer_info, recognise_peer, sync_with,
};
use zp_pairing::{OfferRole, PairingOffer};
use zp_transport::ble::tag_value;
use zp_transport::discovery::{slot_of, tag_for};
use zp_transport::{
    DriveConfig, Link, MemoryLink, PairingLink, pair_as_existing, sync_as_responder,
};
use zp_vault::model::Login;
use zp_vault::{CreateOptions, KdfChoice, Store, Vault};

const PC_PASSWORD: &str = "the master password of the PC";
const PHONE_PASSWORD: &str = "the phone has its own password";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

#[test]
fn a_phone_joins_writes_and_syncs() {
    let dir = tempfile::tempdir().unwrap();
    let pc_path = dir.path().join("pc.zpvault");
    let phone_path = dir.path().join("phone.zpvault");
    let phone_file = phone_path.to_str().unwrap().to_owned();

    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        device_name: Some("PC".to_owned()),
        ..CreateOptions::default()
    };
    let mut pc = Vault::create(&pc_path, PC_PASSWORD, Some(&hardware), options).unwrap();
    let from_pc = pc.insert(Login::new("Mail", "alice", "pc-secret")).unwrap();

    // The PC shows a code; the phone scans it and learns which tag to look for.
    let key = pc.channel_key().unwrap();
    let offer =
        PairingOffer::new(OfferRole::Existing, *key.public_bytes(), Vec::new(), now()).unwrap();
    let code = offer.to_text().as_str().to_owned();
    let info = offer_info(code.clone()).unwrap();
    let shown = tag_value(None, Some(zp_transport::ble::pairing_tag(&offer.psk)));
    assert!(announces_pairing(shown.to_vec(), info.pairing_tag.clone()));
    assert!(!announces_pairing(
        tag_value(None, None).to_vec(),
        info.pairing_tag.clone()
    ));
    assert!(!announces_pairing(vec![1, 2, 3], info.pairing_tag));
    assert!(matches!(
        offer_info("ZP1:not-a-code".to_owned()),
        Err(FfiError::BadCode(_))
    ));

    // Pairing: the PC confirms the name the phone gave.
    let (pc_link, phone_link) = link();
    let psk = offer.psk.clone();
    let pc_side = thread::spawn(move || {
        let pairing = PairingLink {
            scanned: false,
            psk: &psk,
            offered_key: None,
        };
        let admitted = pair_as_existing(
            pc_link,
            &mut pc,
            &pairing,
            |request| request.name == "Test phone",
            &DriveConfig::default(),
        )
        .unwrap();
        (pc, admitted)
    });
    let joined = join_vault(
        phone_file.clone(),
        PHONE_PASSWORD.to_owned(),
        "Test phone".to_owned(),
        code,
        phone_link,
    )
    .unwrap();
    let (mut pc, admitted) = pc_side.join().unwrap();
    assert_eq!(joined.device_id, admitted.device.to_string());
    assert_eq!(joined.vault_id, pc.vault_id().to_string());
    assert_eq!(joined.first_sync_error, None);
    assert_eq!(joined.first_sync.unwrap().received, 1);

    // The phone opens the vault with its own password and reads the PC's login.
    let vault = MobileVault::open(phone_file.clone()).unwrap();
    assert!(matches!(vault.logins(), Err(FfiError::Locked)));
    assert!(matches!(
        vault.unlock(PC_PASSWORD.to_owned()),
        Err(FfiError::WrongPassword)
    ));
    vault.unlock(PHONE_PASSWORD.to_owned()).unwrap();
    let logins = vault.logins().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].id, from_pc.to_string());
    assert_eq!(
        (logins[0].title.as_str(), logins[0].username.as_str()),
        ("Mail", "alice")
    );
    assert_eq!(
        vault.login_password(logins[0].id.clone()).unwrap(),
        "pc-secret"
    );
    let devices = vault.devices().unwrap();
    assert_eq!(devices.len(), 2);
    assert!(
        devices
            .iter()
            .any(|device| device.is_this_device && device.name == "Test phone")
    );

    // Later: both sides change something, and the phone finds the PC by its tag.
    let from_phone = vault
        .add_login(
            "Shop".to_owned(),
            "bob".to_owned(),
            "phone-secret".to_owned(),
        )
        .unwrap();
    vault.delete_login(from_pc.to_string()).unwrap();
    let later = pc.insert(Login::new("Bank", "carol", "later")).unwrap();
    vault.lock();

    let pc_tag = tag_for(&pc.vault_id(), key.public_bytes(), slot_of(now()));
    let peer = recognise_peer(phone_file.clone(), tag_value(Some(pc_tag), None).to_vec())
        .unwrap()
        .unwrap();
    assert_eq!(peer.device_id, pc.device_id().to_string());
    assert_eq!(peer.name, "PC");
    // Somebody else's device, an idle peripheral and garbage are not recognised.
    for value in [
        tag_value(Some([9; 8]), None).to_vec(),
        tag_value(None, None).to_vec(),
        vec![1],
    ] {
        assert!(recognise_peer(phone_file.clone(), value).unwrap().is_none());
    }

    // Sync runs on the locked files of both.
    let (pc_link, phone_link) = link();
    let pc_file = pc_path.clone();
    let pc_side = thread::spawn(move || {
        let mut store = Store::open(&pc_file).unwrap();
        let key = store.channel_key().unwrap();
        sync_as_responder(pc_link, &mut store, &key, &DriveConfig::default()).unwrap()
    });
    let outcome = sync_with(phone_file.clone(), peer.device_id, phone_link).unwrap();
    pc_side.join().unwrap();
    assert_eq!((outcome.sent, outcome.received), (2, 1));

    let from_phone = zp_crypto::ItemId::from_slice(&hex_bytes(&from_phone)).unwrap();
    assert_eq!(
        pc.get::<Login>(from_phone).unwrap().password,
        "phone-secret"
    );
    assert!(pc.get::<Login>(from_pc).is_err());
    vault.unlock(PHONE_PASSWORD.to_owned()).unwrap();
    let titles: Vec<String> = vault
        .logins()
        .unwrap()
        .into_iter()
        .map(|login| login.title)
        .collect();
    assert!(titles.contains(&"Bank".to_owned()) && titles.contains(&"Shop".to_owned()));
    assert_eq!(titles.len(), 2);
    assert_eq!(vault.login_password(later.to_string()).unwrap(), "later");

    // A device that is not in the vault cannot be synced with.
    let (_pc_link, phone_link) = link();
    assert!(sync_with(phone_file, "00".repeat(16), phone_link).is_err());
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_uuids_are_those_of_the_specification() {
    let uuids = ble_uuids();
    assert_eq!(uuids.service, "5a50c0de-0001-4b1d-9c5e-7a65726f7061");
    assert_eq!(uuids.tag, "5a50c0de-0002-4b1d-9c5e-7a65726f7061");
    assert_eq!(uuids.rx, "5a50c0de-0003-4b1d-9c5e-7a65726f7061");
    assert_eq!(uuids.tx, "5a50c0de-0004-4b1d-9c5e-7a65726f7061");
}
