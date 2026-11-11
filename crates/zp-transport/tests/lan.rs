//! Pairing and sync over the real LAN transport (mDNS + TCP), with two
//! "devices" on this machine's own local network address.
//!
//! These tests need a network interface with a private address and working
//! multicast, which CI machines do not reliably have, so they are ignored by
//! default:
//!
//! ```text
//! cargo test -p zp-transport --test lan -- --ignored
//! ```

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zp_crypto::{InsecureSoftwareKeyStore, KdfParams};
use zp_pairing::{Hint, Joiner, OfferRole, PairingOffer};
use zp_transport::discovery::{identify, slot_of, tag_for};
use zp_transport::{
    Address, DriveConfig, LanTransport, NewVault, PairingLink, Transport, pair_as_existing,
    pair_as_new, sync_as_initiator, sync_as_responder,
};
use zp_vault::model::Login;
use zp_vault::{CreateOptions, KdfChoice, Store, Vault};

const PASSWORD_PC: &str = "the master password of the PC";
const PASSWORD_PHONE: &str = "the phone has its own password";
const WAIT: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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

#[test]
#[ignore = "needs a local network interface with multicast"]
fn two_devices_pair_and_sync_over_the_lan() {
    let config = DriveConfig::default();
    let dir = tempfile::tempdir().unwrap();
    let (pc_path, phone_path) = (
        dir.path().join("pc.zpvault"),
        dir.path().join("phone.zpvault"),
    );
    let (pc_hw, phone_hw) = (
        InsecureSoftwareKeyStore::generate().unwrap(),
        InsecureSoftwareKeyStore::generate().unwrap(),
    );

    let mut pc_vault =
        Vault::create(&pc_path, PASSWORD_PC, Some(&pc_hw), options("Study PC")).unwrap();
    let from_pc = pc_vault.insert(login("written on the PC")).unwrap();
    let mut pc_lan = LanTransport::new().unwrap();
    let mut phone_lan = LanTransport::new().unwrap();

    // --- Pairing: the PC shows a code that says where it listens. ---
    let started = Instant::now();
    let key = pc_vault.channel_key().unwrap();
    let hints: Vec<Hint> = pc_lan
        .addresses()
        .iter()
        .map(|address| Hint::Socket(SocketAddr::new((*address).into(), pc_lan.port())))
        .collect();
    assert!(!hints.is_empty());
    let offer =
        PairingOffer::new(OfferRole::Existing, *key.public_bytes(), hints, now_secs()).unwrap();
    let text = offer.to_text();

    let mut phone_vault = thread::scope(|scope| {
        let pc_side = scope.spawn(|| {
            let link = pc_lan.accept(WAIT).unwrap().expect("the phone connects");
            let pairing = PairingLink {
                scanned: false,
                psk: &offer.psk,
                offered_key: None,
            };
            pair_as_existing(
                link,
                &mut pc_vault,
                &pairing,
                |request| request.name == "Pixel 8",
                &config,
            )
        });

        let scanned = PairingOffer::parse(&text, now_secs()).unwrap();
        let Hint::Socket(address) = scanned.hints[0] else {
            panic!("a socket hint")
        };
        let link = phone_lan.connect(&Address::Socket(address)).unwrap();
        let pairing = PairingLink {
            scanned: true,
            psk: &scanned.psk,
            offered_key: Some(scanned.noise_pk),
        };
        let new_vault = NewVault {
            path: &phone_path,
            master_password: PASSWORD_PHONE,
            hardware: Some(&phone_hw),
            options: options("x"),
        };
        let joined = pair_as_new(
            link,
            Joiner::new("Pixel 8").unwrap(),
            &pairing,
            new_vault,
            &config,
        )
        .unwrap();
        pc_side.join().unwrap().unwrap().sync.unwrap();
        joined.sync.unwrap();
        joined.vault
    });
    eprintln!(
        "pairing + first sync over the LAN took {:?}",
        started.elapsed()
    );
    assert_eq!(
        phone_vault.get::<Login>(from_pc).unwrap(),
        login("written on the PC")
    );

    // --- Ordinary sync: both lock; they find each other with mDNS. ---
    let from_phone = phone_vault.insert(login("written on the phone")).unwrap();
    pc_vault.lock_all();
    phone_vault.lock_all();
    let (mut pc_store, mut phone_store) = (
        Store::open(&pc_path).unwrap(),
        Store::open(&phone_path).unwrap(),
    );
    let (pc_key, phone_key) = (
        pc_store.channel_key().unwrap(),
        phone_store.channel_key().unwrap(),
    );
    let vault_id = Store::vault_id(&pc_store);

    let started = Instant::now();
    pc_lan
        .advertise(tag_for(
            &vault_id,
            pc_key.public_bytes(),
            slot_of(now_secs()),
        ))
        .unwrap();
    let registry = Store::registry(&phone_store).unwrap();
    let deadline = Instant::now() + WAIT;
    let (peer, address) = loop {
        let found = phone_lan.discover(Duration::from_millis(300)).unwrap();
        let hit = found.iter().find_map(|d| {
            identify(&registry, &d.tag, now_secs()).map(|r| (r.clone(), d.address.clone()))
        });
        if let Some(hit) = hit {
            break hit;
        }
        assert!(Instant::now() < deadline, "the PC was not discovered");
    };
    eprintln!("discovery took {:?}", started.elapsed());
    assert_eq!(peer.device_id, Store::device_id(&pc_store));

    thread::scope(|scope| {
        let pc_side = scope.spawn(|| {
            let link = pc_lan.accept(WAIT).unwrap().expect("the phone connects");
            sync_as_responder(link, &mut pc_store, &pc_key, &config)
        });
        let link = phone_lan.connect(&address).unwrap();
        let report =
            sync_as_initiator(link, &mut phone_store, &phone_key, &peer.noise_pk, &config).unwrap();
        assert_eq!(report.sent, 1);
        pc_side.join().unwrap().unwrap();
    });
    eprintln!("discovery + sync took {:?}", started.elapsed());

    pc_vault.unlock_password(PASSWORD_PC).unwrap();
    assert_eq!(
        pc_vault.get::<Login>(from_phone).unwrap(),
        login("written on the phone")
    );
}
