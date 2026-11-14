//! The sync loop: two daemons keep two vault files in sync while the user works
//! with the vaults, without ever being given a key.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use zp_crypto::{InsecureSoftwareKeyStore, ItemId, KdfParams, Password};
use zp_transport::daemon::{DaemonConfig, Event, SyncDaemon};
use zp_transport::{DriveConfig, LoopbackNetwork, LoopbackTransport};
use zp_vault::model::Login;
use zp_vault::{CreateOptions, JoinIdentity, KdfChoice, Store, Vault};

const PASSWORD: &str = "a master password for the tests";

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

fn fast() -> DaemonConfig {
    DaemonConfig {
        accept_wait: Duration::from_millis(50),
        discover_wait: Duration::from_millis(20),
        poll_interval: Duration::from_millis(200),
        retry_after: Duration::from_millis(200),
        drive: DriveConfig {
            idle_timeout: Duration::from_secs(5),
            progress_interval: Duration::from_secs(1),
        },
    }
}

struct Device {
    path: PathBuf,
    vault: Vault,
}

/// A founding device and `others` devices admitted by it, each with its own file.
fn devices(dir: &Path, others: usize) -> Vec<Device> {
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let path = dir.join("device-0.zpvault");
    let vault = Vault::create(&path, PASSWORD, Some(&hardware), options("device 0")).unwrap();
    let mut all = vec![Device { path, vault }];
    for n in 1..=others {
        let identity = JoinIdentity::generate().unwrap();
        let grant = all[0]
            .vault
            .grant(
                identity.device_id(),
                identity.sign_pk(),
                *identity.channel_key().public_bytes(),
                &format!("device {n}"),
            )
            .unwrap();
        let path = dir.join(format!("device-{n}.zpvault"));
        let vault = Vault::join(&path, identity, grant, PASSWORD, None, options("x")).unwrap();
        all.push(Device { path, vault });
    }
    all
}

fn daemon(path: &Path, network: &LoopbackNetwork) -> SyncDaemon<Store, LoopbackTransport> {
    SyncDaemon::new(Store::open(path).unwrap(), network.endpoint(), fast())
}

/// Stops the daemon threads when the test ends, also when it ends by a failed
/// assertion: otherwise the scope would wait for them forever.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Polls until `check` holds or five seconds have passed.
fn eventually(mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn has(vault: &mut Vault, id: ItemId, password: &str) -> bool {
    vault
        .get::<Login>(id)
        .is_ok_and(|item| item.password == password)
}

/// The acceptance test of P2-13 (on the loopback transport): a change made on
/// one device shows up on the other within seconds, in both directions, while
/// the daemons only ever see the locked files.
#[test]
fn changes_propagate_between_two_running_daemons() {
    let dir = tempfile::tempdir().unwrap();
    let network = LoopbackNetwork::new();
    let mut all = devices(dir.path(), 1);
    let (pc, phone) = all.split_at_mut(1);
    let (pc, phone) = (&mut pc[0], &mut phone[0]);
    let stop = AtomicBool::new(false);

    thread::scope(|scope| {
        let _stop = StopOnDrop(&stop);
        let mut events: Vec<thread::ScopedJoinHandle<'_, Vec<Event>>> = Vec::new();
        for path in [&pc.path, &phone.path] {
            let (network, stop) = (&network, &stop);
            events.push(scope.spawn(move || {
                let mut daemon = daemon(path, network);
                let mut events = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    events.extend(daemon.step().unwrap());
                }
                events
            }));
        }

        // PC → phone.
        let started = Instant::now();
        let from_pc = pc.vault.insert(login("written on the PC")).unwrap();
        assert!(eventually(|| has(
            &mut phone.vault,
            from_pc,
            "written on the PC"
        )));
        eprintln!("PC → phone took {:?}", started.elapsed());

        // Phone → PC, including an update and a deletion.
        let from_phone = phone.vault.insert(login("written on the phone")).unwrap();
        phone
            .vault
            .update(from_pc, login("changed on the phone"))
            .unwrap();
        assert!(eventually(|| has(
            &mut pc.vault,
            from_phone,
            "written on the phone"
        )));
        assert!(eventually(|| has(
            &mut pc.vault,
            from_pc,
            "changed on the phone"
        )));
        phone.vault.delete::<Password>(from_phone).unwrap();
        assert!(eventually(|| pc.vault.get::<Login>(from_phone).is_err()));

        // The daemons keep working while the vaults are locked.
        pc.vault.lock_all();
        let later = phone
            .vault
            .insert(login("while the PC was locked"))
            .unwrap();
        assert!(eventually(|| {
            Store::open(&pc.path).unwrap().version_vector().unwrap()
                == phone.vault.version_vector().unwrap()
        }));
        pc.vault.unlock_password(PASSWORD).unwrap();
        assert!(has(&mut pc.vault, later, "while the PC was locked"));

        stop.store(true, Ordering::Relaxed);
        let all_events: Vec<Event> = events
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect();
        let synced = all_events
            .iter()
            .filter(|event| matches!(event, Event::Synced { .. }))
            .count();
        let failed = all_events
            .iter()
            .filter(|event| matches!(event, Event::Failed { .. }))
            .count();
        assert!(synced >= 4, "{synced} sessions");
        assert_eq!(failed, 0, "{all_events:?}");
        // Within a pair, one side always dials and the other always answers.
        let dialled = |by_me: bool| {
            all_events
                .iter()
                .filter(
                    |event| matches!(event, Event::Synced { initiated, .. } if *initiated == by_me),
                )
                .count()
        };
        assert_eq!(dialled(true), dialled(false));
    });
}

#[test]
fn three_devices_converge_through_the_loop() {
    let dir = tempfile::tempdir().unwrap();
    let network = LoopbackNetwork::new();
    let mut all = devices(dir.path(), 2);
    let stop = AtomicBool::new(false);
    let paths: Vec<PathBuf> = all.iter().map(|device| device.path.clone()).collect();

    thread::scope(|scope| {
        let _stop = StopOnDrop(&stop);
        for path in &paths {
            let (network, stop) = (&network, &stop);
            scope.spawn(move || {
                let mut daemon = daemon(path, network);
                while !stop.load(Ordering::Relaxed) {
                    daemon.step().unwrap();
                }
            });
        }
        // Each device writes something; devices 1 and 2 have never met.
        let ids: Vec<ItemId> = all
            .iter_mut()
            .enumerate()
            .map(|(n, device)| {
                device
                    .vault
                    .insert(login(&format!("from device {n}")))
                    .unwrap()
            })
            .collect();
        for device in &mut all {
            for (n, id) in ids.iter().enumerate() {
                assert!(eventually(|| has(
                    &mut device.vault,
                    *id,
                    &format!("from device {n}")
                )));
            }
            assert_eq!(device.vault.registry().unwrap().active().count(), 3);
        }
        stop.store(true, Ordering::Relaxed);
    });
}

#[test]
fn a_device_alone_on_the_network_just_waits() {
    let dir = tempfile::tempdir().unwrap();
    let network = LoopbackNetwork::new();
    let all = devices(dir.path(), 0);
    let mut daemon = daemon(&all[0].path, &network);
    let events = daemon
        .run_until(Instant::now() + Duration::from_millis(300), |_| false)
        .unwrap();
    assert!(events.is_empty());
    assert_eq!(daemon.store().device_id(), all[0].vault.device_id());
}
