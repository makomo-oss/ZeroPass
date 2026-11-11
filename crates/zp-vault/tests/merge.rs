//! Merging ops between vault files (`docs/spec/sync.md` §5): several devices of
//! one vault exchange ops through the `OpLog` interface and converge.
//!
//! Exchanging ops never takes a vault key: the `pull` helper below only uses the
//! `Store`, exactly as the sync daemon does on a locked vault.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::PathBuf;

use proptest::prelude::*;
use zp_crypto::{DeviceId, ItemId, Password, Totp, VaultKey};
use zp_sync::{ApplyReport, Op, OpLog, SyncError};
use zp_vault::model::{Item, Login, TotpEntry};
use zp_vault::{Clock, Store, VaultError};

struct Device {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: Store,
}

/// Several devices of one vault. They share the vault keys, as paired devices do.
struct World {
    vk_p: VaultKey<Password>,
    vk_t: VaultKey<Totp>,
    devices: Vec<Device>,
}

fn world(count: usize) -> World {
    let (vk_p, vk_t) = (VaultKey::generate().unwrap(), VaultKey::generate().unwrap());
    let mut devices: Vec<Device> = Vec::new();
    for n in 0..count {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.zpvault");
        let name = format!("device {n}");
        let store = if let Some(first) = devices.first_mut() {
            // A joining device: introduced by the first one.
            let vault_id = Store::vault_id(&first.store);
            let device_id = DeviceId::generate().unwrap();
            let mut store =
                Store::create_for_vault(&path, vault_id, device_id, Clock::system()).unwrap();
            let signer = store.create_identity().unwrap();
            first
                .store
                .introduce_device(
                    &vk_p,
                    Store::device_id(&store),
                    signer.public_key(),
                    *store.channel_key().unwrap().public_bytes(),
                    &name,
                )
                .unwrap();
            let registry = Store::registry(&first.store).unwrap();
            store
                .import_registry(
                    &signer,
                    registry.records().cloned().collect(),
                    registry.revocations().cloned().collect(),
                )
                .unwrap();
            store.add_device_key_slot(&signer, &vk_p).unwrap();
            store.add_device_key_slot(&signer, &vk_t).unwrap();
            store
        } else {
            let mut store = Store::create(&path).unwrap();
            let signer = store.provision_device(&name).unwrap();
            store.add_device_key_slot(&signer, &vk_p).unwrap();
            store.add_device_key_slot(&signer, &vk_t).unwrap();
            store
        };
        devices.push(Device {
            _dir: dir,
            path,
            store,
        });
    }
    // Everyone learns about everyone.
    let registry = Store::registry(&devices[0].store).unwrap();
    for device in &mut devices {
        device
            .store
            .merge_registry(registry.records().cloned().collect(), Vec::new())
            .unwrap();
    }
    World {
        vk_p,
        vk_t,
        devices,
    }
}

fn pair(devices: &mut [Device], from: usize, to: usize) -> (&Store, &mut Store) {
    assert_ne!(from, to);
    if from < to {
        let (left, right) = devices.split_at_mut(to);
        (&left[from].store, &mut right[0].store)
    } else {
        let (left, right) = devices.split_at_mut(from);
        (&right[0].store, &mut left[to].store)
    }
}

/// `to` takes everything it lacks from `from`, at most `limit` ops per author.
fn pull(devices: &mut [Device], from: usize, to: usize, limit: usize) -> ApplyReport {
    let (source, target) = pair(devices, from, to);
    let ahead = Store::version_vector(source)
        .unwrap()
        .ahead_of(&Store::version_vector(target).unwrap());
    let mut report = ApplyReport::default();
    for (device, after, _) in ahead {
        let ops = Store::ops_after(source, device, after, limit).unwrap();
        report.absorb(target.apply(ops).unwrap());
    }
    report
}

fn sync_all(devices: &mut [Device]) {
    for _ in 0..2 {
        for from in 0..devices.len() {
            for to in 0..devices.len() {
                if from != to {
                    pull(devices, from, to, usize::MAX);
                }
            }
        }
    }
}

type OpId = (Vec<u8>, i64);

/// The observable state of a vault file: which op is current for each item, and
/// which ops are in the history.
fn snapshot(device: &Device) -> (Vec<(Vec<u8>, OpId)>, Vec<OpId>) {
    let conn = rusqlite::Connection::open(&device.path).unwrap();
    let current = conn
        .prepare("SELECT item_id, device_id, seq FROM items ORDER BY item_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?))))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let history = conn
        .prepare("SELECT device_id, seq FROM item_history ORDER BY device_id, seq")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    (current, history)
}

fn login(password: &str) -> Login {
    Login::new("Example", "alice@example.com", password)
}

fn is_sync_error(result: Result<ApplyReport, VaultError>, expected: &SyncError) -> bool {
    matches!(result, Err(VaultError::Sync(error)) if error == *expected)
}

#[test]
fn an_item_written_on_one_device_can_be_read_on_another() {
    let mut w = world(2);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("pw-1"))
        .unwrap();

    let report = pull(&mut w.devices, 0, 1, usize::MAX);
    assert_eq!(
        report,
        ApplyReport {
            applied: 1,
            duplicates: 0,
            became_current: 1
        }
    );
    assert_eq!(
        w.devices[1].store.get_item::<Login>(&w.vk_p, id).unwrap(),
        login("pw-1")
    );
    assert_eq!(
        Store::version_vector(&w.devices[0].store).unwrap(),
        Store::version_vector(&w.devices[1].store).unwrap()
    );
    // Pulling again finds nothing new.
    assert_eq!(
        pull(&mut w.devices, 0, 1, usize::MAX),
        ApplyReport::default()
    );
}

#[test]
fn received_items_survive_reopening_the_file() {
    let mut w = world(2);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("pw-1"))
        .unwrap();
    pull(&mut w.devices, 0, 1, usize::MAX);
    let before = snapshot(&w.devices[1]);

    let reopened = Store::open(&w.devices[1].path).unwrap();
    assert_eq!(
        reopened.get_item::<Login>(&w.vk_p, id).unwrap(),
        login("pw-1")
    );
    drop(reopened);
    assert_eq!(snapshot(&w.devices[1]), before);
}

#[test]
fn totp_items_sync_as_ciphertext_without_any_key() {
    let mut w = world(2);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_t, TotpEntry::new("Example", "alice", vec![7; 20]))
        .unwrap();
    // `pull` uses no key at all; the receiving side could be fully locked.
    pull(&mut w.devices, 0, 1, usize::MAX);
    let bytes = std::fs::read(&w.devices[1].path).unwrap();
    assert!(!bytes.windows(20).any(|window| window == [7; 20]));
    // With the TOTP vault key the item opens on the second device too.
    let entry = w.devices[1]
        .store
        .get_item::<TotpEntry>(&w.vk_t, id)
        .unwrap();
    assert_eq!(entry.secret, vec![7; 20]);
}

#[test]
fn the_later_of_two_concurrent_edits_wins_and_the_other_is_kept() {
    let mut w = world(2);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("original"))
        .unwrap();
    pull(&mut w.devices, 0, 1, usize::MAX);

    // Both edit while apart. Device 1 writes second, so its stamp is greater.
    w.devices[0]
        .store
        .update_item(&w.vk_p, id, login("edit on device 0"))
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    w.devices[1]
        .store
        .update_item(&w.vk_p, id, login("edit on device 1"))
        .unwrap();

    let into_1 = pull(&mut w.devices, 0, 1, usize::MAX);
    assert_eq!((into_1.applied, into_1.became_current), (1, 0));
    let into_0 = pull(&mut w.devices, 1, 0, usize::MAX);
    assert_eq!((into_0.applied, into_0.became_current), (1, 1));

    for device in &w.devices {
        assert_eq!(
            device.store.get_item::<Login>(&w.vk_p, id).unwrap(),
            login("edit on device 1")
        );
        let history: Vec<String> = device
            .store
            .item_history(&w.vk_p, id)
            .unwrap()
            .into_iter()
            .map(|entry| {
                Login::from_content(entry.content.unwrap())
                    .unwrap()
                    .password
                    .clone()
            })
            .collect();
        assert_eq!(history, ["edit on device 0", "original"]);
    }
    assert_eq!(snapshot(&w.devices[0]), snapshot(&w.devices[1]));
}

#[test]
fn a_deletion_propagates_and_a_later_update_revives_the_item() {
    let mut w = world(2);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("pw"))
        .unwrap();
    pull(&mut w.devices, 0, 1, usize::MAX);

    w.devices[0].store.delete_item(&w.vk_p, id).unwrap();
    pull(&mut w.devices, 0, 1, usize::MAX);
    assert!(matches!(
        w.devices[1].store.get_item::<Login>(&w.vk_p, id),
        Err(VaultError::ItemNotFound)
    ));

    // Device 1 had not seen the deletion when it updated the item later on.
    let mut w = world(2);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("pw"))
        .unwrap();
    pull(&mut w.devices, 0, 1, usize::MAX);
    w.devices[0].store.delete_item(&w.vk_p, id).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    w.devices[1]
        .store
        .update_item(&w.vk_p, id, login("still needed"))
        .unwrap();
    sync_all(&mut w.devices);
    for device in &w.devices {
        assert_eq!(
            device.store.get_item::<Login>(&w.vk_p, id).unwrap(),
            login("still needed")
        );
    }
}

#[test]
fn ops_reach_a_device_through_a_third_one() {
    let mut w = world(3);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("pw"))
        .unwrap();
    pull(&mut w.devices, 0, 1, usize::MAX);
    // Device 2 only ever talks to device 1.
    assert_eq!(pull(&mut w.devices, 1, 2, usize::MAX).applied, 1);
    assert_eq!(
        w.devices[2].store.get_item::<Login>(&w.vk_p, id).unwrap(),
        login("pw")
    );
    assert_eq!(snapshot(&w.devices[2]), snapshot(&w.devices[0]));
}

#[test]
fn local_versions_order_after_everything_received() {
    let mut w = world(2);
    let id = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("pw-1"))
        .unwrap();
    let device_0 = Store::device_id(&w.devices[0].store);
    let received = Store::ops_after(&w.devices[0].store, device_0, 0, 1)
        .unwrap()
        .remove(0);
    pull(&mut w.devices, 0, 1, usize::MAX);

    // Even if device 1's wall clock lagged behind, its update must win.
    w.devices[1]
        .store
        .update_item(&w.vk_p, id, login("pw-2"))
        .unwrap();
    let device_1 = Store::device_id(&w.devices[1].store);
    let update = Store::ops_after(&w.devices[1].store, device_1, 0, 1)
        .unwrap()
        .remove(0);
    assert!(update.body.hlc > received.body.hlc);
}

fn first_op(w: &World) -> Op {
    let device = Store::device_id(&w.devices[0].store);
    Store::ops_after(&w.devices[0].store, device, 0, 1)
        .unwrap()
        .remove(0)
}

#[test]
fn forged_out_of_order_and_conflicting_ops_are_refused_atomically() {
    let mut w = world(2);
    w.devices[0]
        .store
        .insert_items(&w.vk_p, (0..3).map(|n| login(&format!("pw-{n}"))))
        .unwrap();
    let author = Store::device_id(&w.devices[0].store);
    let ops = Store::ops_after(&w.devices[0].store, author, 0, 10).unwrap();
    let empty = snapshot(&w.devices[1]);
    let target = &mut w.devices[1].store;

    // Modified after signing.
    let mut tampered = ops[0].clone();
    tampered.body.hlc += 1;
    assert!(is_sync_error(
        target.apply(vec![tampered]),
        &SyncError::BadSignature
    ));
    // A forged tombstone: no key is needed to build one, but it carries no valid
    // signature.
    let mut tombstone = ops[0].clone();
    tombstone.body.payload = None;
    assert!(is_sync_error(
        target.apply(vec![tombstone]),
        &SyncError::BadSignature
    ));
    // A gap, and a valid op followed by an invalid one.
    assert!(is_sync_error(
        target.apply(vec![ops[1].clone()]),
        &SyncError::OutOfOrder {
            device: author,
            expected: 1,
            got: 2
        }
    ));
    let mut second_bad = ops[1].clone();
    second_bad.signature[0] ^= 1;
    assert!(target.apply(vec![ops[0].clone(), second_bad]).is_err());
    // An op of a device nobody introduced.
    let stranger = world(1);
    let foreign_id = stranger.devices[0].store.vault_id();
    assert_ne!(foreign_id, Store::vault_id(target));
    let mut stranger = stranger;
    stranger.devices[0]
        .store
        .insert_item(&stranger.vk_p, login("x"))
        .unwrap();
    let foreign = first_op(&stranger);
    assert!(is_sync_error(
        target.apply(vec![foreign.clone()]),
        &SyncError::UnknownDevice(foreign.body.device_id)
    ));
    assert!(Store::version_vector(target).unwrap().is_empty());
    assert_eq!(
        snapshot(&w.devices[1]),
        empty,
        "refused batches must leave nothing behind"
    );

    // The genuine ops are accepted, also when delivered twice.
    let target = &mut w.devices[1].store;
    assert_eq!(target.apply(ops.clone()).unwrap().applied, 3);
    assert_eq!(target.apply(ops.clone()).unwrap().duplicates, 3);
    // Same identifier with other content.
    let mut conflicting = ops[1].clone();
    conflicting.signature = ops[2].signature;
    // (It fails the signature check first; a validly signed conflict needs the
    // author's key and is covered by the in-memory tests.)
    assert!(target.apply(vec![conflicting]).is_err());
}

#[test]
fn an_op_from_the_far_future_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let w = world(1);
    let vault_id = Store::vault_id(&w.devices[0].store);
    // A device whose clock is two days ahead writes an item.
    let ahead = Clock::from_fn(|| Clock::system().now_ms() + 2 * 24 * 60 * 60 * 1000);
    let mut w = w;
    let mut fast = Store::create_for_vault(
        &dir.path().join("fast.zpvault"),
        vault_id,
        DeviceId::generate().unwrap(),
        ahead,
    )
    .unwrap();
    let signer = fast.create_identity().unwrap();
    w.devices[0]
        .store
        .introduce_device(
            &w.vk_p,
            Store::device_id(&fast),
            signer.public_key(),
            *fast.channel_key().unwrap().public_bytes(),
            "fast clock",
        )
        .unwrap();
    let registry = Store::registry(&w.devices[0].store).unwrap();
    fast.import_registry(&signer, registry.records().cloned().collect(), Vec::new())
        .unwrap();
    fast.add_device_key_slot(&signer, &w.vk_p).unwrap();
    fast.insert_item(&w.vk_p, login("from the future")).unwrap();

    let ops = Store::ops_after(&fast, Store::device_id(&fast), 0, 10).unwrap();
    assert!(is_sync_error(
        w.devices[0].store.apply(ops),
        &SyncError::ClockSkew
    ));
}

#[derive(Debug, Clone)]
enum Action {
    Write {
        device: usize,
        item: usize,
        content: Option<u8>,
    },
    Pull {
        from: usize,
        to: usize,
        limit: usize,
    },
}

const DEVICES: usize = 3;

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        (
            0..DEVICES,
            0usize..4,
            proptest::option::weighted(0.8, any::<u8>())
        )
            .prop_map(|(device, item, content)| Action::Write {
                device,
                item,
                content
            }),
        (0..DEVICES, 0..DEVICES, 1usize..5).prop_map(|(from, to, limit)| Action::Pull {
            from,
            to,
            limit
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// The convergence property again, this time on real vault files: after any
    /// mix of writes and partial exchanges, a full sync leaves all files with
    /// the same current versions and the same history.
    #[test]
    fn vault_files_converge(actions in proptest::collection::vec(action(), 1..30)) {
        let mut w = world(DEVICES);
        // Slots for the items the script may touch; filled on first write.
        let mut items: Vec<Option<ItemId>> = vec![None; 4];

        for action in &actions {
            match *action {
                Action::Write { device, item, content } => {
                    let store = &mut w.devices[device].store;
                    match (items[item], content) {
                        (None, Some(byte)) => {
                            items[item] = Some(store.insert_item(&w.vk_p, login(&byte.to_string())).unwrap());
                        }
                        (Some(id), Some(byte)) => {
                            // The item may be unknown or deleted on this device.
                            let _ = store.update_item(&w.vk_p, id, login(&byte.to_string()));
                        }
                        (Some(id), None) => {
                            let _ = store.delete_item(&w.vk_p, id);
                        }
                        (None, None) => {}
                    }
                }
                Action::Pull { from, to, limit } if from != to => {
                    pull(&mut w.devices, from, to, limit);
                }
                Action::Pull { .. } => {}
            }
        }
        sync_all(&mut w.devices);

        let reference = snapshot(&w.devices[0]);
        for device in &w.devices[1..] {
            prop_assert_eq!(snapshot(device), reference.clone());
        }
        // Every device decrypts the same content.
        let listing = |device: &Device| -> Vec<(ItemId, String)> {
            device
                .store
                .list_items(&w.vk_p)
                .unwrap()
                .into_iter()
                .map(|(id, content)| (id, Login::from_content(content).unwrap().password.clone()))
                .collect()
        };
        let expected = listing(&w.devices[0]);
        for device in &w.devices[1..] {
            prop_assert_eq!(listing(device), expected.clone());
        }
    }
}

#[test]
fn device_ids_are_distinct_and_registries_agree() {
    let w = world(3);
    let ids: Vec<DeviceId> = w
        .devices
        .iter()
        .map(|d| Store::device_id(&d.store))
        .collect();
    assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    let reference = Store::registry(&w.devices[0].store).unwrap();
    assert_eq!(reference.active().count(), 3);
    for device in &w.devices {
        assert_eq!(Store::registry(&device.store).unwrap(), reference);
    }
}

/// The acceptance test of P2-06: two vault files converge by running the sync
/// session against each other, with no vault key involved.
#[test]
fn two_vault_files_converge_through_a_session() {
    let mut w = world(2);
    let on_0 = w.devices[0]
        .store
        .insert_item(&w.vk_p, login("written on device 0"))
        .unwrap();
    let totp = w.devices[0]
        .store
        .insert_item(&w.vk_t, TotpEntry::new("Example", "alice", vec![5; 20]))
        .unwrap();
    let on_1 = w.devices[1]
        .store
        .insert_item(&w.vk_p, login("written on device 1"))
        .unwrap();
    w.devices[1]
        .store
        .update_item(&w.vk_p, on_1, login("updated on device 1"))
        .unwrap();

    let (a, b) = w.devices.split_at_mut(1);
    let (report_0, report_1) = zp_sync::sync_in_memory(&mut a[0].store, &mut b[0].store).unwrap();
    assert_eq!((report_0.sent, report_0.received.applied), (2, 2));
    assert_eq!((report_1.sent, report_1.received.applied), (2, 2));
    assert_eq!(report_0.peer, Some(Store::device_id(&w.devices[1].store)));

    assert_eq!(snapshot(&w.devices[0]), snapshot(&w.devices[1]));
    for device in &w.devices {
        assert_eq!(
            device.store.get_item::<Login>(&w.vk_p, on_0).unwrap(),
            login("written on device 0")
        );
        assert_eq!(
            device.store.get_item::<Login>(&w.vk_p, on_1).unwrap(),
            login("updated on device 1")
        );
        assert_eq!(
            device
                .store
                .get_item::<TotpEntry>(&w.vk_t, totp)
                .unwrap()
                .secret,
            vec![5; 20]
        );
    }

    // Nothing left to exchange.
    let (a, b) = w.devices.split_at_mut(1);
    let (report_0, report_1) = zp_sync::sync_in_memory(&mut a[0].store, &mut b[0].store).unwrap();
    assert_eq!((report_0.sent, report_1.sent), (0, 0));
}

/// The same session carried over a byte stream that delivers the frames in
/// arbitrary pieces, as a real transport does.
#[test]
fn a_session_survives_a_fragmenting_byte_stream() {
    use zp_sync::{FrameDecoder, Session, encode_frame};

    let mut w = world(2);
    w.devices[0]
        .store
        .insert_items(&w.vk_p, (0..40).map(|n| login(&format!("pw-{n}"))))
        .unwrap();
    w.devices[1]
        .store
        .insert_item(&w.vk_p, login("other side"))
        .unwrap();
    let (a, b) = w.devices.split_at_mut(1);
    let (a, b) = (&mut a[0].store, &mut b[0].store);

    let mut session_a = Session::start(a, Some(Store::device_id(b))).unwrap();
    let mut session_b = Session::start(b, Some(Store::device_id(a))).unwrap();
    let (mut decoder_a, mut decoder_b) = (FrameDecoder::new(), FrameDecoder::new());
    loop {
        let mut progressed = false;
        // A → B, cut into 7-byte pieces.
        while let Some(message) = session_a.poll_send(a).unwrap() {
            for piece in encode_frame(&message).unwrap().chunks(7) {
                decoder_b.push(piece);
                while let Some(message) = decoder_b.next_message().unwrap() {
                    session_b.receive(b, &message).unwrap();
                }
            }
            progressed = true;
        }
        // B → A, cut into 1000-byte pieces.
        while let Some(message) = session_b.poll_send(b).unwrap() {
            for piece in encode_frame(&message).unwrap().chunks(1000) {
                decoder_a.push(piece);
                while let Some(message) = decoder_a.next_message().unwrap() {
                    session_a.receive(a, &message).unwrap();
                }
            }
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    assert!(session_a.is_complete() && session_b.is_complete());
    assert!(!decoder_a.has_partial() && !decoder_b.has_partial());
    assert_eq!(session_a.report().sent, 40);
    assert_eq!(session_b.report().received.applied, 40);
    assert_eq!(snapshot(&w.devices[0]), snapshot(&w.devices[1]));
}

/// A device that joins later receives the whole history, including ops authored
/// by a device it has never met.
#[test]
fn a_new_device_catches_up_through_one_session() {
    let mut w = world(3);
    let from_1 = w.devices[1]
        .store
        .insert_item(&w.vk_p, login("from device 1"))
        .unwrap();
    {
        let (a, b) = w.devices.split_at_mut(1);
        zp_sync::sync_in_memory(&mut a[0].store, &mut b[0].store).unwrap();
    }
    w.devices[0]
        .store
        .insert_item(&w.vk_p, login("from device 0"))
        .unwrap();

    // Device 2 has only ever been introduced; it syncs with device 0 alone.
    let (a, rest) = w.devices.split_at_mut(1);
    let (_, report_2) = zp_sync::sync_in_memory(&mut a[0].store, &mut rest[1].store).unwrap();
    assert_eq!(report_2.received.applied, 2);
    assert_eq!(
        w.devices[2]
            .store
            .get_item::<Login>(&w.vk_p, from_1)
            .unwrap(),
        login("from device 1")
    );
    assert_eq!(snapshot(&w.devices[2]), snapshot(&w.devices[0]));
}
