//! Fault injection for the sync drivers (plan task P2-18): what a connection
//! that dies in the middle of a session leaves behind, how the next one carries
//! on, and a link much slower than the idle timeout.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use zp_crypto::{InsecureSoftwareKeyStore, KdfParams, Password};
use zp_sync::SessionReport;
use zp_transport::{
    DriveConfig, DriveError, Link, MemoryLink, sync_as_initiator, sync_as_responder,
};
use zp_vault::model::Login;
use zp_vault::{CreateOptions, JoinIdentity, KdfChoice, Store, Vault};

const PASSWORD: &str = "a master password for the tests";
const ITEMS: usize = 600;

fn options(name: &str) -> CreateOptions {
    CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
        device_name: Some(name.to_owned()),
    }
}

fn config() -> DriveConfig {
    DriveConfig {
        // Generous: the receiver sends nothing while it writes one batch to
        // disk, and shared CI machines can be slow at that.
        idle_timeout: Duration::from_secs(120),
        ..DriveConfig::default()
    }
}

/// A link that carries a limited number of bytes from this side and then
/// breaks, like a radio connection going out of range.
struct FailingLink {
    inner: Box<dyn Link>,
    budget: Arc<AtomicUsize>,
}

struct FailingWriter {
    inner: Box<dyn Write + Send>,
    budget: Arc<AtomicUsize>,
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let left = self.budget.load(Ordering::Relaxed);
        if left < bytes.len() {
            self.budget.store(0, Ordering::Relaxed);
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.budget.store(left - bytes.len(), Ordering::Relaxed);
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Link for FailingLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let (reader, writer) = self.inner.split()?;
        let writer = FailingWriter {
            inner: writer,
            budget: self.budget,
        };
        Ok((reader, Box::new(writer)))
    }

    fn peer(&self) -> String {
        self.inner.peer()
    }
}

struct Pair {
    _dir: tempfile::TempDir,
    full: PathBuf,
    empty: PathBuf,
    empty_vault: Vault,
}

/// Two devices of one vault: one holds `items` logins of about 1 kB each ([`ITEMS`] is most of a
/// megabyte, so several batches), the other has just joined and holds none.
fn pair() -> Pair {
    pair_with(ITEMS)
}

fn pair_with(items: usize) -> Pair {
    let dir = tempfile::tempdir().unwrap();
    let (full, empty) = (
        dir.path().join("full.zpvault"),
        dir.path().join("empty.zpvault"),
    );
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let mut vault = Vault::create(&full, PASSWORD, Some(&hardware), options("full")).unwrap();
    vault
        .insert_many((0..items).map(|n| {
            let mut login = Login::new(format!("Login {n}"), "alice", "secret");
            login.notes = "n".repeat(1000);
            login
        }))
        .unwrap();

    let identity = JoinIdentity::generate().unwrap();
    let grant = vault
        .grant(
            identity.device_id(),
            identity.sign_pk(),
            *identity.channel_key().public_bytes(),
            "empty",
        )
        .unwrap();
    let empty_vault =
        Vault::join(&empty, identity, grant, PASSWORD, None, options("empty")).unwrap();
    Pair {
        _dir: dir,
        full,
        empty,
        empty_vault,
    }
}

type Outcome = Result<SessionReport, DriveError>;

/// One sync between the two vault files; the full device may send at most
/// `budget` bytes before its link breaks.
fn sync(full: &Path, empty: &Path, budget: usize) -> (Outcome, Outcome) {
    let (to_empty, to_full) = MemoryLink::pair();
    let failing = FailingLink {
        inner: Box::new(to_empty),
        budget: Arc::new(AtomicUsize::new(budget)),
    };
    let mut full_store = Store::open(full).unwrap();
    let mut empty_store = Store::open(empty).unwrap();
    let full_key = full_store.channel_key().unwrap();
    let empty_key = empty_store.channel_key().unwrap();
    let remote = *full_key.public_bytes();

    thread::scope(|scope| {
        let responder = scope.spawn(move || {
            sync_as_responder(Box::new(failing), &mut full_store, &full_key, &config())
        });
        let initiator = sync_as_initiator(
            Box::new(to_full),
            &mut empty_store,
            &empty_key,
            &remote,
            &config(),
        );
        (responder.join().unwrap(), initiator)
    })
}

#[test]
fn a_connection_lost_mid_sync_keeps_what_arrived_and_the_next_one_finishes() {
    let mut devices = pair();
    let author = Store::open(&devices.full).unwrap().device_id();
    let held = |path: &Path| {
        Store::open(path)
            .unwrap()
            .version_vector()
            .unwrap()
            .get(&author)
    };
    assert_eq!(held(&devices.empty), 0);

    // The link breaks after about 400 kB.
    let (full_side, empty_side) = sync(&devices.full, &devices.empty, 400_000);
    assert!(full_side.is_err(), "the sender must notice the broken link");
    assert!(
        empty_side.is_err(),
        "the receiver must notice the broken link"
    );

    // Whole batches arrived and are kept; nothing is half-written.
    let partial = held(&devices.empty) as usize;
    assert!(
        partial > 0 && partial < ITEMS,
        "{partial} of {ITEMS} arrived"
    );
    let readable = devices.empty_vault.list::<Password>().unwrap();
    assert_eq!(readable.len(), partial);

    // The next session sends only the rest.
    let (full_side, empty_side) = sync(&devices.full, &devices.empty, usize::MAX);
    assert_eq!(full_side.unwrap().sent, ITEMS - partial);
    assert_eq!(empty_side.unwrap().received.applied, ITEMS - partial);
    assert_eq!(devices.empty_vault.list::<Password>().unwrap().len(), ITEMS);
    assert_eq!(held(&devices.empty) as usize, ITEMS);
}

#[test]
fn a_connection_lost_before_anything_arrived_changes_nothing() {
    let mut devices = pair();
    // Not even the handshake gets through.
    let (full_side, empty_side) = sync(&devices.full, &devices.empty, 10);
    assert!(full_side.is_err() && empty_side.is_err());
    assert!(devices.empty_vault.list::<Password>().unwrap().is_empty());

    let (full_side, empty_side) = sync(&devices.full, &devices.empty, usize::MAX);
    assert_eq!(full_side.unwrap().sent, ITEMS);
    assert_eq!(empty_side.unwrap().received.applied, ITEMS);
}

/// A link whose writes return at once but reach the peer slowly, like Bluetooth
/// on Windows: the OS queues the packets and sends them over the radio at its
/// own pace (`docs/spec/ble.md` §5.2).
struct SlowLink {
    inner: Box<dyn Link>,
    bytes_per_second: usize,
}

struct QueueWriter {
    queue: mpsc::Sender<Vec<u8>>,
}

impl Write for QueueWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.queue
            .send(bytes.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Link for SlowLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        const PIECE: usize = 4096;
        let (reader, mut writer) = self.inner.split()?;
        let (queue, queued) = mpsc::channel::<Vec<u8>>();
        let pause = Duration::from_secs_f64(PIECE as f64 / self.bytes_per_second as f64);
        // Ends once the writer is dropped and the queue is drained.
        thread::spawn(move || {
            for bytes in queued {
                for piece in bytes.chunks(PIECE) {
                    thread::sleep(pause);
                    if writer.write_all(piece).is_err() {
                        return;
                    }
                }
            }
        });
        Ok((reader, Box::new(QueueWriter { queue })))
    }

    fn peer(&self) -> String {
        self.inner.peer()
    }
}

#[test]
fn a_transfer_slower_than_the_idle_timeout_completes_on_both_sides() {
    // The full device hands all its ops to the link at once and then waits for
    // the other side's Done while they trickle through for more than twice the
    // idle timeout. The receiving side's Progress messages keep it waiting.
    const LOGINS: usize = 100;
    let mut devices = pair_with(LOGINS);
    let config = DriveConfig {
        idle_timeout: Duration::from_secs(2),
        progress_interval: Duration::from_millis(250),
    };
    let (to_empty, to_full) = MemoryLink::pair();
    let slow = SlowLink {
        inner: Box::new(to_empty),
        bytes_per_second: 24 * 1024,
    };
    let mut full_store = Store::open(&devices.full).unwrap();
    let mut empty_store = Store::open(&devices.empty).unwrap();
    let full_key = full_store.channel_key().unwrap();
    let empty_key = empty_store.channel_key().unwrap();
    let remote = *full_key.public_bytes();

    let started = Instant::now();
    let (full_side, empty_side) = thread::scope(|scope| {
        let responder =
            scope.spawn(|| sync_as_responder(Box::new(slow), &mut full_store, &full_key, &config));
        let initiator = sync_as_initiator(
            Box::new(to_full),
            &mut empty_store,
            &empty_key,
            &remote,
            &config,
        );
        (responder.join().unwrap(), initiator)
    });
    let took = started.elapsed();
    assert!(took > 2 * config.idle_timeout, "only took {took:?}");
    assert_eq!(full_side.unwrap().sent, LOGINS);
    assert_eq!(empty_side.unwrap().received.applied, LOGINS);
    assert_eq!(
        devices.empty_vault.list::<Password>().unwrap().len(),
        LOGINS
    );
}
