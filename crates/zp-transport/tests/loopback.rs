//! The drivers over the loopback transport: two devices, each on its own
//! thread, pair, discover each other by anonymous tag, and sync vault files.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use zp_crypto::{DeviceId, InsecureSoftwareKeyStore, KdfParams, Password, Totp};
use zp_pairing::{Hint, Joiner, OfferRole, PairingError, PairingOffer};
use zp_transport::discovery::{identify, slot_of, tag_for};
use zp_transport::{
    Address, DriveConfig, DriveError, LoopbackNetwork, LoopbackTransport, NewVault, PairingLink,
    Transport, pair_as_existing, pair_as_new, sync_as_initiator, sync_as_responder,
};
use zp_vault::model::{Login, TotpEntry};
use zp_vault::{Clock, CreateOptions, KdfChoice, Store, Vault};

const PASSWORD_PC: &str = "the master password of the PC";
const PASSWORD_PHONE: &str = "the phone has its own password";
const NOW: u64 = 1_800_000_000;
const WAIT: Duration = Duration::from_secs(5);

fn config() -> DriveConfig {
    DriveConfig {
        idle_timeout: Duration::from_secs(10),
        progress_interval: Duration::from_secs(2),
    }
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

struct Device {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hardware: InsecureSoftwareKeyStore,
    vault: Vault,
    transport: LoopbackTransport,
}

fn founder(network: &LoopbackNetwork) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pc.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let vault = Vault::create(&path, PASSWORD_PC, Some(&hardware), options("Study PC")).unwrap();
    Device {
        _dir: dir,
        path,
        hardware,
        vault,
        transport: network.endpoint(),
    }
}

/// Pairs a new device with `existing` over the loopback transport: the existing
/// device shows the code and listens, the new one scans and connects.
fn pair(existing: &mut Device, network: &LoopbackNetwork, name: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("phone.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut transport = network.endpoint();

    let key = existing.vault.channel_key().unwrap();
    let offer = PairingOffer::new(
        OfferRole::Existing,
        *key.public_bytes(),
        vec![Hint::Ble],
        NOW,
    )
    .unwrap();
    let text = offer.to_text();
    existing.transport.advertise([0xAA; 8]).unwrap();
    let address = transport.discover(WAIT).unwrap()[0].address.clone();

    let joined = thread::scope(|scope| {
        let existing_side = scope.spawn(|| {
            let link = existing.transport.accept(WAIT).unwrap().unwrap();
            let pairing = PairingLink {
                scanned: false,
                psk: &offer.psk,
                offered_key: None,
            };
            pair_as_existing(
                link,
                &mut existing.vault,
                &pairing,
                |request| request.name == name,
                &config(),
            )
        });

        // The new device scans the code and connects.
        let scanned = PairingOffer::parse(&text, NOW + 3).unwrap();
        let link = transport.connect(&address).unwrap();
        let pairing = PairingLink {
            scanned: true,
            psk: &scanned.psk,
            offered_key: Some(scanned.noise_pk),
        };
        let new_vault = NewVault {
            path: &path,
            master_password: PASSWORD_PHONE,
            hardware: Some(&hardware),
            options: options("ignored"),
        };
        let joined = pair_as_new(
            link,
            Joiner::new(name).unwrap(),
            &pairing,
            new_vault,
            &config(),
        )
        .unwrap();

        let admitted = existing_side.join().unwrap().unwrap();
        assert_eq!(admitted.name, name);
        assert_eq!(admitted.device, joined.vault.device_id());
        admitted.sync.unwrap();
        joined
    });
    joined.sync.unwrap();
    existing.transport.stop_advertising().unwrap();
    Device {
        _dir: dir,
        path,
        hardware,
        vault: joined.vault,
        transport,
    }
}

/// One round of ordinary sync: `listener` announces itself and waits; `caller`
/// recognises its tag, connects and syncs. Both work on the locked files.
fn sync(listener: &mut Device, caller: &mut Device) {
    let mut listener_store = Store::open(&listener.path).unwrap();
    let mut caller_store = Store::open(&caller.path).unwrap();
    let listener_key = listener_store.channel_key().unwrap();
    let caller_key = caller_store.channel_key().unwrap();
    let vault_id = Store::vault_id(&listener_store);

    listener
        .transport
        .advertise(tag_for(
            &vault_id,
            listener_key.public_bytes(),
            slot_of(NOW),
        ))
        .unwrap();
    let found = caller.transport.discover(WAIT).unwrap();
    assert_eq!(found.len(), 1);
    let registry = Store::registry(&caller_store).unwrap();
    let peer = identify(&registry, &found[0].tag, NOW)
        .expect("the tag belongs to a member")
        .clone();
    assert_eq!(peer.device_id, Store::device_id(&listener_store));

    thread::scope(|scope| {
        let listener_side = scope.spawn(|| {
            let link = listener.transport.accept(WAIT).unwrap().unwrap();
            sync_as_responder(link, &mut listener_store, &listener_key, &config())
        });
        let link = caller.transport.connect(&found[0].address).unwrap();
        let report = sync_as_initiator(
            link,
            &mut caller_store,
            &caller_key,
            &peer.noise_pk,
            &config(),
        )
        .unwrap();
        assert_eq!(report.peer, Some(peer.device_id));
        listener_side.join().unwrap().unwrap();
    });
    listener.transport.stop_advertising().unwrap();
}

/// The acceptance test of P2-10: pairing and sync run through the `Transport`
/// trait, with the two devices on separate threads.
#[test]
fn devices_pair_and_sync_through_a_transport() {
    let network = LoopbackNetwork::new();
    let mut pc = founder(&network);
    let from_pc = pc.vault.insert(login("written on the PC")).unwrap();
    let totp = pc
        .vault
        .insert(TotpEntry::new("Example", "alice", vec![3; 20]))
        .unwrap();

    let mut phone = pair(&mut pc, &network, "Pixel 8");
    // The first sync happened as part of pairing.
    assert_eq!(
        phone.vault.get::<Login>(from_pc).unwrap(),
        login("written on the PC")
    );
    assert_eq!(
        phone.vault.get::<TotpEntry>(totp).unwrap().secret,
        vec![3; 20]
    );

    // Later: both change things, lock, and sync when they meet again.
    let from_phone = phone.vault.insert(login("written on the phone")).unwrap();
    pc.vault
        .update(from_pc, login("changed on the PC"))
        .unwrap();
    pc.vault.lock_all();
    phone.vault.lock_all();
    sync(&mut pc, &mut phone);

    pc.vault.unlock_password(PASSWORD_PC).unwrap();
    phone.vault.unlock_password(PASSWORD_PHONE).unwrap();
    assert_eq!(
        pc.vault.get::<Login>(from_phone).unwrap(),
        login("written on the phone")
    );
    assert_eq!(
        phone.vault.get::<Login>(from_pc).unwrap(),
        login("changed on the PC")
    );
    assert_eq!(
        pc.vault.version_vector().unwrap(),
        phone.vault.version_vector().unwrap()
    );

    // The roles of listener and caller can be swapped.
    phone.vault.delete::<Password>(from_phone).unwrap();
    sync(&mut phone, &mut pc);
    assert!(pc.vault.get::<Login>(from_phone).is_err());
    // The TOTP domain opens with each device's own key store.
    pc.vault.unlock_hardware::<Totp>(&pc.hardware).unwrap();
    phone
        .vault
        .unlock_hardware::<Totp>(&phone.hardware)
        .unwrap();
    assert_eq!(
        phone.vault.get::<TotpEntry>(totp).unwrap(),
        pc.vault.get::<TotpEntry>(totp).unwrap()
    );
}

#[test]
fn a_third_device_paired_with_the_phone_syncs_with_the_pc() {
    let network = LoopbackNetwork::new();
    let mut pc = founder(&network);
    let item = pc.vault.insert(login("pw")).unwrap();
    let mut phone = pair(&mut pc, &network, "Pixel 8");
    // The tablet is admitted by the phone, not the PC.
    let mut tablet = pair(&mut phone, &network, "Tablet");
    assert_eq!(tablet.vault.get::<Login>(item).unwrap(), login("pw"));

    // The PC has never heard of the tablet, yet they sync: the tablet presents
    // its record, signed by the phone, and the session binds it to the channel.
    let written = tablet.vault.insert(login("written on the tablet")).unwrap();
    sync(&mut pc, &mut tablet);
    assert_eq!(
        pc.vault.get::<Login>(written).unwrap(),
        login("written on the tablet")
    );
    assert_eq!(pc.vault.registry().unwrap().active().count(), 3);
}

/// Builds a vault file that claims to be a device of `vault_id` without ever
/// having been admitted.
fn impostor(vault_id: zp_crypto::VaultId, dir: &Path) -> Store {
    let mut store = Store::create_for_vault(
        &dir.join("impostor.zpvault"),
        vault_id,
        DeviceId::generate().unwrap(),
        Clock::system(),
    )
    .unwrap();
    store.provision_device("impostor").unwrap();
    store
}

#[test]
fn a_device_that_was_never_admitted_gets_nothing() {
    let network = LoopbackNetwork::new();
    let mut pc = founder(&network);
    pc.vault.insert(login("secret")).unwrap();
    let dir = tempfile::tempdir().unwrap();

    // The impostor somehow knows the vault identifier and the PC's public
    // channel key, which is all the handshake needs.
    let mut pc_store = Store::open(&pc.path).unwrap();
    let pc_key = pc_store.channel_key().unwrap();
    let mut fake = impostor(Store::vault_id(&pc_store), dir.path());
    let fake_key = fake.channel_key().unwrap();
    let mut transport = network.endpoint();
    pc.transport.advertise([1; 8]).unwrap();
    let address = transport.discover(WAIT).unwrap()[0].address.clone();

    let (pc_result, fake_result) = thread::scope(|scope| {
        let pc_side = scope.spawn(|| {
            let link = pc.transport.accept(WAIT).unwrap().unwrap();
            sync_as_responder(link, &mut pc_store, &pc_key, &config())
        });
        let link = transport.connect(&address).unwrap();
        let fake_result =
            sync_as_initiator(link, &mut fake, &fake_key, pc_key.public_bytes(), &config());
        (pc_side.join().unwrap(), fake_result)
    });

    assert!(
        matches!(&pc_result, Err(DriveError::Sync(text)) if text.contains("unknown device")),
        "{pc_result:?}"
    );
    assert!(fake_result.is_err());
    // The impostor received no ops and was not added to the registry.
    assert!(Store::version_vector(&fake).unwrap().is_empty());
    assert_eq!(pc.vault.registry().unwrap().records().count(), 1);
}

#[test]
fn devices_of_different_vaults_cannot_even_shake_hands() {
    let network = LoopbackNetwork::new();
    let (mut a, mut b) = (founder(&network), founder(&network));
    let (mut store_a, mut store_b) = (Store::open(&a.path).unwrap(), Store::open(&b.path).unwrap());
    let (key_a, key_b) = (
        store_a.channel_key().unwrap(),
        store_b.channel_key().unwrap(),
    );
    a.transport.advertise([1; 8]).unwrap();
    let address = b.transport.discover(WAIT).unwrap()[0].address.clone();

    let (result_a, result_b) = thread::scope(|scope| {
        let side_a = scope.spawn(|| {
            let link = a.transport.accept(WAIT).unwrap().unwrap();
            sync_as_responder(link, &mut store_a, &key_a, &config())
        });
        let link = b.transport.connect(&address).unwrap();
        let result_b =
            sync_as_initiator(link, &mut store_b, &key_b, key_a.public_bytes(), &config());
        (side_a.join().unwrap(), result_b)
    });
    assert!(
        matches!(result_a, Err(DriveError::Pairing(PairingError::Handshake))),
        "{result_a:?}"
    );
    assert!(result_b.is_err());
}

#[test]
fn a_silent_or_vanishing_peer_does_not_hang_the_driver() {
    let network = LoopbackNetwork::new();
    let mut pc = founder(&network);
    let mut pc_store = Store::open(&pc.path).unwrap();
    let pc_key = pc_store.channel_key().unwrap();
    let mut other = network.endpoint();
    pc.transport.advertise([1; 8]).unwrap();
    let address = other.discover(WAIT).unwrap()[0].address.clone();
    let quick = DriveConfig {
        idle_timeout: Duration::from_millis(300),
        ..DriveConfig::default()
    };

    // Connects and says nothing.
    let silent = other.connect(&address).unwrap();
    let link = pc.transport.accept(WAIT).unwrap().unwrap();
    assert!(matches!(
        sync_as_responder(link, &mut pc_store, &pc_key, &quick),
        Err(DriveError::Timeout)
    ));
    drop(silent);

    // Connects and hangs up.
    drop(other.connect(&address).unwrap());
    let link = pc.transport.accept(WAIT).unwrap().unwrap();
    assert!(matches!(
        sync_as_responder(link, &mut pc_store, &pc_key, &quick),
        Err(DriveError::Closed)
    ));
    assert!(other.connect(&Address::Loopback(9999)).is_err());
}

#[test]
fn pairing_is_refused_without_the_code_or_the_users_consent() {
    let network = LoopbackNetwork::new();
    let mut pc = founder(&network);
    let key = pc.vault.channel_key().unwrap();
    let offer = PairingOffer::new(OfferRole::Existing, *key.public_bytes(), vec![], NOW).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.zpvault");
    let mut transport = network.endpoint();
    pc.transport.advertise([1; 8]).unwrap();
    let address = transport.discover(WAIT).unwrap()[0].address.clone();

    let attempt =
        |pc: &mut Device, transport: &mut LoopbackTransport, psk: &[u8; 32], approve: bool| {
            thread::scope(|scope| {
                let pc_side = scope.spawn(|| {
                    let link = pc.transport.accept(WAIT).unwrap().unwrap();
                    let pairing = PairingLink {
                        scanned: false,
                        psk: &offer.psk,
                        offered_key: None,
                    };
                    pair_as_existing(link, &mut pc.vault, &pairing, |_| approve, &config())
                });
                let link = transport.connect(&address).unwrap();
                let pairing = PairingLink {
                    scanned: true,
                    psk,
                    offered_key: Some(offer.noise_pk),
                };
                let new_vault = NewVault {
                    path: &path,
                    master_password: PASSWORD_PHONE,
                    hardware: None,
                    options: options("x"),
                };
                let new_side = pair_as_new(
                    link,
                    Joiner::new("stranger").unwrap(),
                    &pairing,
                    new_vault,
                    &config(),
                );
                (pc_side.join().unwrap().map(|_| ()), new_side.map(|_| ()))
            })
        };

    // A wrong secret: the handshake fails on both sides.
    let (pc_result, new_result) = attempt(&mut pc, &mut transport, &[0; 32], true);
    assert!(
        matches!(pc_result, Err(DriveError::Pairing(PairingError::Handshake))),
        "{pc_result:?}"
    );
    assert!(new_result.is_err());

    // The right secret, but the user says no: both sides learn of the refusal.
    let (pc_result, new_result) = attempt(&mut pc, &mut transport, &offer.psk, false);
    assert!(
        matches!(pc_result, Err(DriveError::Pairing(PairingError::Declined))),
        "{pc_result:?}"
    );
    assert!(
        matches!(new_result, Err(DriveError::Pairing(PairingError::Declined))),
        "{new_result:?}"
    );

    assert!(!path.exists());
    assert_eq!(pc.vault.registry().unwrap().records().count(), 1);
}
