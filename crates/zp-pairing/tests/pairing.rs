//! Pairing end to end, in memory: QR offer → Noise handshake → join → first sync.
//! The bytes that would cross the air are passed between the two sides by hand
//! and recorded, so the test can also check what an eavesdropper would see.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::PathBuf;

use zp_crypto::{DomainId, InsecureSoftwareKeyStore, ItemId, KdfParams, Passkey, Password, Totp};
use zp_pairing::flow::{ack_message, is_ack, refusal_message};
use zp_pairing::{
    Handshake, Hint, Joiner, OfferRole, PairingError, PairingOffer, SecureChannel, admit,
};
use zp_sync::{FrameDecoder, Session, encode_frame};
use zp_vault::model::{Login, PasskeyCredential, TotpEntry};
use zp_vault::{CreateOptions, KdfChoice, Store, Vault};

const PASSWORD_A: &str = "the master password of the PC";
const PASSWORD_B: &str = "the phone has its own password";
const NOW: u64 = 1_800_000_000;

fn options(name: &str) -> CreateOptions {
    CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: Some(name.to_owned()),
    }
}

fn login() -> Login {
    Login::new(
        "Example Bank",
        "alice@example.com",
        "a-very-secret-password",
    )
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

/// The device that already has the vault.
struct Existing {
    _dir: tempfile::TempDir,
    path: PathBuf,
    hardware: InsecureSoftwareKeyStore,
    vault: Vault,
    ids: (ItemId, ItemId, ItemId),
}

fn existing() -> Existing {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pc.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::create(&path, PASSWORD_A, Some(&hardware), options("Study PC")).unwrap();
    let ids = (
        vault.insert(login()).unwrap(),
        vault.insert(totp()).unwrap(),
        vault.insert(passkey()).unwrap(),
    );
    Existing {
        _dir: dir,
        path,
        hardware,
        vault,
        ids,
    }
}

/// One end of the encrypted channel, speaking in framed messages. Everything it
/// puts on the air is appended to `air`.
struct End {
    channel: SecureChannel,
    decoder: FrameDecoder,
}

impl End {
    fn send(&mut self, message: &[u8], air: &mut Vec<u8>) -> Vec<u8> {
        let bytes = self.channel.send(&encode_frame(message).unwrap()).unwrap();
        air.extend_from_slice(&bytes);
        bytes
    }

    fn receive(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.decoder.push(&self.channel.receive(bytes).unwrap());
        let mut messages = Vec::new();
        while let Some(message) = self.decoder.next_message().unwrap() {
            messages.push(message);
        }
        messages
    }
}

/// Runs the pairing handshake. Returns (initiator end, responder end).
fn handshake(
    mut initiator: Handshake,
    mut responder: Handshake,
    air: &mut Vec<u8>,
) -> Result<(End, End), PairingError> {
    let mut to_responder = initiator.step(&[])?;
    loop {
        air.extend_from_slice(&to_responder);
        let to_initiator = responder.step(&to_responder)?;
        air.extend_from_slice(&to_initiator);
        to_responder = initiator.step(&to_initiator)?;
        if to_responder.is_empty() && initiator.is_finished() && responder.is_finished() {
            break;
        }
    }
    let end = |handshake: Handshake| -> Result<End, PairingError> {
        Ok(End {
            channel: handshake.into_channel()?,
            decoder: FrameDecoder::new(),
        })
    };
    Ok((end(initiator)?, end(responder)?))
}

/// The first sync, over the channel that was just used for pairing.
fn sync_over(
    a: &mut End,
    store_a: &mut Store,
    b: &mut End,
    store_b: &mut Store,
    air: &mut Vec<u8>,
) {
    // Each side binds the session to the channel key the handshake authenticated.
    let mut session_a = Session::start(store_a, Some(*a.channel.remote_static())).unwrap();
    let mut session_b = Session::start(store_b, Some(*b.channel.remote_static())).unwrap();
    loop {
        let mut progressed = false;
        while let Some(message) = session_a.poll_send(store_a).unwrap() {
            let bytes = a.send(&message, air);
            for message in b.receive(&bytes) {
                session_b.receive(store_b, &message).unwrap();
            }
            progressed = true;
        }
        while let Some(message) = session_b.poll_send(store_b).unwrap() {
            let bytes = b.send(&message, air);
            for message in a.receive(&bytes) {
                session_a.receive(store_a, &message).unwrap();
            }
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    assert!(session_a.is_complete() && session_b.is_complete());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn new_device_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("phone.zpvault");
    (dir, path)
}

/// The acceptance test of P2-09: the PC shows a QR code, the phone scans it, and
/// after pairing and the first sync the phone opens every domain.
#[test]
fn a_phone_joins_by_scanning_the_code_on_the_pc() {
    let mut pc = existing();
    let (_dir, phone_path) = new_device_path();
    let phone_hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut air = Vec::new();

    // The PC shows the offer; the phone scans it.
    let pc_key = pc.vault.channel_key().unwrap();
    let offer = PairingOffer::new(
        OfferRole::Existing,
        *pc_key.public_bytes(),
        vec![Hint::Socket("192.168.1.20:47000".parse().unwrap())],
        NOW,
    )
    .unwrap();
    let scanned = PairingOffer::parse(&offer.to_text(), NOW + 5).unwrap();
    assert_eq!(scanned.role, OfferRole::Existing);

    // Handshake: the scanner initiates.
    let joiner = Joiner::new("Pixel 8").unwrap();
    let (mut phone, mut pc_end) = handshake(
        Handshake::pairing(true, joiner.channel_key(), &scanned.psk).unwrap(),
        Handshake::pairing(false, &pc_key, &offer.psk).unwrap(),
        &mut air,
    )
    .unwrap();
    // The phone checks that it reached the device whose code it scanned.
    assert_eq!(phone.channel.remote_static(), &scanned.noise_pk);

    // JoinRequest → (confirmation) → JoinGrant → JoinAck.
    let bytes = phone.send(&joiner.request(), &mut air);
    let request = pc_end.receive(&bytes).remove(0);
    let mut shown_to_user = None;
    let peer_key = *pc_end.channel.remote_static();
    let grant = admit(&mut pc.vault, &peer_key, &request, |request| {
        shown_to_user = Some(request.name.clone());
        true
    })
    .unwrap();
    assert_eq!(shown_to_user.as_deref(), Some("Pixel 8"));

    let bytes = pc_end.send(&grant, &mut air);
    let reply = phone.receive(&bytes).remove(0);
    let mut phone_vault = joiner
        .accept(
            &reply,
            &phone_path,
            PASSWORD_B,
            Some(&phone_hardware),
            options("ignored"),
        )
        .unwrap();
    let bytes = phone.send(&ack_message(), &mut air);
    assert!(is_ack(&pc_end.receive(&bytes).remove(0)));

    // First sync on the same channel, on the files (no keys involved).
    let (mut pc_store, mut phone_store) = (
        Store::open(&pc.path).unwrap(),
        Store::open(&phone_path).unwrap(),
    );
    sync_over(
        &mut pc_end,
        &mut pc_store,
        &mut phone,
        &mut phone_store,
        &mut air,
    );
    drop((pc_store, phone_store));

    // The phone has everything, in every domain.
    assert_eq!(phone_vault.get::<Login>(pc.ids.0).unwrap(), login());
    assert_eq!(phone_vault.get::<TotpEntry>(pc.ids.1).unwrap(), totp());
    assert_eq!(
        phone_vault.get::<PasskeyCredential>(pc.ids.2).unwrap(),
        passkey()
    );
    assert_eq!(
        phone_vault
            .registry()
            .unwrap()
            .get(&phone_vault.device_id())
            .unwrap()
            .name,
        "Pixel 8"
    );
    assert_eq!(pc.vault.registry().unwrap().active().count(), 2);

    // And it can unlock every domain again later with its own credentials.
    drop(phone_vault);
    let mut phone_vault = Vault::open(&phone_path).unwrap();
    phone_vault.unlock_password(PASSWORD_B).unwrap();
    phone_vault
        .unlock_hardware::<Totp>(&phone_hardware)
        .unwrap();
    phone_vault
        .unlock_hardware::<Passkey>(&phone_hardware)
        .unwrap();
    assert_eq!(phone_vault.list::<Password>().unwrap().len(), 1);
    assert_eq!(phone_vault.list::<Totp>().unwrap().len(), 1);
    assert_eq!(phone_vault.list::<Passkey>().unwrap().len(), 1);

    // Nothing readable crossed the air: no names, no item content.
    assert!(air.len() > 500);
    for secret in [
        &b"Pixel 8"[..],
        b"Study PC",
        b"Example Bank",
        b"a-very-secret-password",
        &[1u8; 20],
    ] {
        assert!(
            !contains(&air, secret),
            "{:?} was sent in the clear",
            String::from_utf8_lossy(secret)
        );
    }
}

/// The roles reversed: the new device shows the code, the existing device scans.
#[test]
fn a_new_pc_joins_by_showing_a_code_to_the_phone() {
    let mut phone = existing();
    let (_dir, pc_path) = new_device_path();
    let mut air = Vec::new();

    let joiner = Joiner::new("New laptop").unwrap();
    let offer = PairingOffer::new(
        OfferRole::New,
        *joiner.channel_key().public_bytes(),
        vec![Hint::Ble],
        NOW,
    )
    .unwrap();
    let scanned = PairingOffer::parse(&offer.to_text(), NOW).unwrap();
    assert_eq!(scanned.role, OfferRole::New);

    // The existing device scanned, so it initiates.
    let phone_key = phone.vault.channel_key().unwrap();
    let (mut phone_end, mut pc_end) = handshake(
        Handshake::pairing(true, &phone_key, &scanned.psk).unwrap(),
        Handshake::pairing(false, joiner.channel_key(), &offer.psk).unwrap(),
        &mut air,
    )
    .unwrap();
    assert_eq!(phone_end.channel.remote_static(), &scanned.noise_pk);

    let bytes = pc_end.send(&joiner.request(), &mut air);
    let request = phone_end.receive(&bytes).remove(0);
    let peer_key = *phone_end.channel.remote_static();
    let grant = admit(&mut phone.vault, &peer_key, &request, |_| true).unwrap();
    let bytes = phone_end.send(&grant, &mut air);
    let reply = pc_end.receive(&bytes).remove(0);
    // The laptop has no hardware key store: it gets the password domain only.
    let mut pc_vault = joiner
        .accept(&reply, &pc_path, PASSWORD_B, None, options("x"))
        .unwrap();

    let (mut phone_store, mut pc_store) = (
        Store::open(&phone.path).unwrap(),
        Store::open(&pc_path).unwrap(),
    );
    sync_over(
        &mut phone_end,
        &mut phone_store,
        &mut pc_end,
        &mut pc_store,
        &mut air,
    );
    assert_eq!(pc_vault.get::<Login>(phone.ids.0).unwrap(), login());
    assert!(!pc_vault.has_domain(DomainId::Totp).unwrap());
    // The TOTP item is held as ciphertext all the same.
    assert_eq!(
        pc_store
            .version_vector()
            .unwrap()
            .get(&phone.vault.device_id()),
        3
    );
}

#[test]
fn pairing_fails_without_the_secret_or_after_the_code_expired() {
    let pc = existing();
    let pc_key = pc.vault.channel_key().unwrap();
    let offer =
        PairingOffer::new(OfferRole::Existing, *pc_key.public_bytes(), vec![], NOW).unwrap();
    let text = offer.to_text();

    // Too late.
    assert_eq!(
        PairingOffer::parse(&text, NOW + 61).unwrap_err(),
        PairingError::OfferExpired
    );

    // Someone who knows the PC's address and public key, but not the secret.
    let attacker = Joiner::new("attacker").unwrap();
    let result = handshake(
        Handshake::pairing(true, attacker.channel_key(), &[0u8; 32]).unwrap(),
        Handshake::pairing(false, &pc_key, &offer.psk).unwrap(),
        &mut Vec::new(),
    );
    assert_eq!(result.err(), Some(PairingError::Handshake));
}

#[test]
fn nothing_is_granted_when_the_user_declines_or_a_domain_is_locked() {
    let mut pc = existing();
    let pc_key = pc.vault.channel_key().unwrap();
    let joiner = Joiner::new("Unknown tablet").unwrap();
    let peer_key = *joiner.channel_key().public_bytes();
    let request = joiner.request();

    // The user does not recognise the device.
    assert_eq!(
        admit(&mut pc.vault, &peer_key, &request, |_| false).unwrap_err(),
        PairingError::Declined
    );
    // The request names a key other than the one the channel authenticated.
    assert_eq!(
        admit(&mut pc.vault, pc_key.public_bytes(), &request, |_| true).unwrap_err(),
        PairingError::KeyMismatch
    );
    // A domain is locked: pairing needs the master password and the biometrics.
    pc.vault.lock(DomainId::Passkey);
    let error = admit(&mut pc.vault, &peer_key, &request, |_| true).unwrap_err();
    assert!(
        matches!(&error, PairingError::Vault(text) if text.contains("Passkey")),
        "{error:?}"
    );
    // Garbage instead of a request.
    assert_eq!(
        admit(&mut pc.vault, &peer_key, b"\xFF\xFF", |_| true).unwrap_err(),
        PairingError::Protocol
    );
    assert_eq!(
        pc.vault.registry().unwrap().records().count(),
        1,
        "nobody was admitted"
    );

    // The new device handles a refusal and nonsense replies without creating a file.
    let (_dir, path) = new_device_path();
    let joiner = Joiner::new("tablet").unwrap();
    assert_eq!(
        joiner
            .accept(&refusal_message(), &path, PASSWORD_B, None, options("x"))
            .unwrap_err(),
        PairingError::Declined
    );
    let joiner = Joiner::new("tablet").unwrap();
    assert_eq!(
        joiner
            .accept(&ack_message(), &path, PASSWORD_B, None, options("x"))
            .unwrap_err(),
        PairingError::Protocol
    );
    assert!(!path.exists());
    let _ = &pc.hardware;
}

#[test]
fn a_grant_meant_for_another_device_cannot_be_used() {
    let mut pc = existing();
    let (intended, thief) = (Joiner::new("phone").unwrap(), Joiner::new("thief").unwrap());
    let peer_key = *intended.channel_key().public_bytes();
    let grant = admit(&mut pc.vault, &peer_key, &intended.request(), |_| true).unwrap();

    // Even with the decrypted grant in hand, another device cannot join with it:
    // the registry in the grant does not contain that device's keys.
    let (_dir, path) = new_device_path();
    let error = thief
        .accept(&grant, &path, PASSWORD_B, None, options("x"))
        .unwrap_err();
    assert!(matches!(error, PairingError::Vault(_)), "{error:?}");
    assert!(!path.exists());
}
