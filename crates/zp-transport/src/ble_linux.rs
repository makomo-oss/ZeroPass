//! The Bluetooth LE peripheral for Linux (`docs/spec/ble.md`), built on BlueZ
//! over D-Bus (`bluer`).
//!
//! The roles are those of Windows (`ble_windows.rs`): the desktop publishes
//! the ZeroPass service and advertises it; a central that subscribes to `Tx`
//! opens a link, and bytes written to `Rx` and notified on `Tx` form it.
//!
//! BlueZ is reached asynchronously. The peripheral runs a single-threaded
//! Tokio runtime on a thread of its own, and the synchronous [`Transport`]
//! waits on it. Single-threaded on purpose: BlueZ hands over every packet
//! written to `Rx` as a D-Bus call, `bluer` starts a task per call, and only
//! a single thread runs those tasks in the order the calls arrived.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use bluer::adv::{Advertisement, AdvertisementHandle, Type};
use bluer::gatt::CharacteristicWriter;
use bluer::gatt::local::{
    Application, ApplicationHandle, Characteristic, CharacteristicControl,
    CharacteristicControlEvent, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod, Service,
    characteristic_control,
};
use bluer::{Adapter, Session, Uuid};
use futures_util::{FutureExt, StreamExt};
use tokio::runtime::Handle;
use tokio::sync::oneshot;

use crate::ble::{RX_UUID, SERVICE_UUID, TAG_UUID, TAG_VALUE_LEN, TX_UUID, tag_value};
use crate::discovery::Tag;
use crate::link::{ChannelReader, Link};
use crate::transport::{Address, Discovered, Transport};

fn bt(error: bluer::Error) -> io::Error {
    io::Error::other(error.to_string())
}

/// What the GATT handlers and the transport share.
struct Shared {
    /// The current value of the `Tag` characteristic.
    tag_value: [u8; TAG_VALUE_LEN],
    /// The link in progress, by its number, and where bytes written to `Rx`
    /// go: its reader.
    active: Option<(u64, Sender<Vec<u8>>)>,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Ends link `id`, if it is the one in progress: its reader sees the end of
/// the stream, and the next subscription opens a new link.
fn end(shared: &Mutex<Shared>, id: u64) {
    let mut shared = lock(shared);
    if shared
        .active
        .as_ref()
        .is_some_and(|(active, _)| *active == id)
    {
        shared.active = None;
    }
}

/// A link to the central that subscribed to `Tx`.
pub struct BleLink {
    incoming: Receiver<Vec<u8>>,
    writer: NotifyWriter,
}

/// The writing half: notifies the subscribed central, one packet at a time.
struct NotifyWriter {
    id: u64,
    /// The socket BlueZ gave for the notifications of this subscription
    /// (`AcquireNotify`); it closes when the central unsubscribes or leaves.
    notify: Arc<CharacteristicWriter>,
    runtime: Handle,
    shared: Arc<Mutex<Shared>>,
}

impl Write for NotifyWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // The largest notification for the central's ATT MTU.
        let packet = self.notify.mtu();
        if packet == 0 {
            return Err(io::Error::other(
                "the central's MTU leaves no room for data",
            ));
        }
        let notify = &self.notify;
        // Each packet waits for room in the socket, which BlueZ empties as it
        // queues the notifications (`ble.md` §4: like Windows, not a
        // back-pressure from the radio).
        self.runtime.block_on(async {
            for chunk in bytes.chunks(packet) {
                notify.send(chunk).await?;
            }
            Ok::<_, io::Error>(())
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for NotifyWriter {
    fn drop(&mut self) {
        end(&self.shared, self.id);
    }
}

impl Link for BleLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let BleLink { incoming, writer } = *self;
        Ok((Box::new(ChannelReader::new(incoming)), Box::new(writer)))
    }

    fn peer(&self) -> String {
        "ble:central".to_owned()
    }
}

/// Turns the subscriptions to `Tx` into links, one at a time.
async fn open_links(
    mut control: CharacteristicControl,
    shared: Arc<Mutex<Shared>>,
    opened: Sender<BleLink>,
    runtime: Handle,
) {
    let mut next = 0u64;
    while let Some(event) = control.next().await {
        let CharacteristicControlEvent::Notify(notify) = event else {
            continue;
        };
        next += 1;
        let id = next;
        let notify = Arc::new(notify);
        {
            let mut state = lock(&shared);
            if state.active.is_some() {
                // One central at a time (`ble.md` §2): dropping the socket
                // ends this one's subscription.
                continue;
            }
            let (sender, incoming) = mpsc::channel();
            state.active = Some((id, sender));
            let link = BleLink {
                incoming,
                writer: NotifyWriter {
                    id,
                    notify: Arc::clone(&notify),
                    runtime: runtime.clone(),
                    shared: Arc::clone(&shared),
                },
            };
            if opened.send(link).is_err() {
                return;
            }
        }
        // The central unsubscribed or left: end the link.
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = notify.closed().await;
            end(&shared, id);
        });
    }
}

/// The parts of the GATT service, with the handlers that answer for it.
fn application(shared: &Arc<Mutex<Shared>>) -> (Application, CharacteristicControl) {
    // Tag: answer reads with the current tags.
    let state = Arc::clone(shared);
    let tag = Characteristic {
        uuid: Uuid::from_u128(TAG_UUID),
        read: Some(CharacteristicRead {
            read: true,
            fun: Box::new(move |_| {
                let value = lock(&state).tag_value.to_vec();
                async move { Ok(value) }.boxed()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    // Rx: pass written bytes to the link in progress. This runs when the task
    // of the call starts, so in the order of the calls (see the module).
    let state = Arc::clone(shared);
    let rx = Characteristic {
        uuid: Uuid::from_u128(RX_UUID),
        write: Some(CharacteristicWrite {
            write: true,
            write_without_response: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |bytes, _| {
                if let Some((_, link)) = &lock(&state).active {
                    // The link may just have ended; then the bytes are dropped.
                    let _ = link.send(bytes);
                }
                async { Ok(()) }.boxed()
            })),
            ..Default::default()
        }),
        ..Default::default()
    };
    // Tx: a subscription hands over a socket for the notifications.
    let (control, control_handle) = characteristic_control();
    let tx = Characteristic {
        uuid: Uuid::from_u128(TX_UUID),
        notify: Some(CharacteristicNotify {
            notify: true,
            method: CharacteristicNotifyMethod::Io,
            ..Default::default()
        }),
        control_handle,
        ..Default::default()
    };
    // No BLE-level encryption or authentication on any of them: Noise runs on
    // top.
    let application = Application {
        services: vec![Service {
            uuid: Uuid::from_u128(SERVICE_UUID),
            primary: true,
            characteristics: vec![tag, rx, tx],
            ..Default::default()
        }],
        ..Default::default()
    };
    (application, control)
}

/// The Bluetooth LE peripheral transport.
pub struct BlePeripheral {
    runtime: Handle,
    /// Ends the thread that runs the runtime.
    stop: Option<oneshot::Sender<()>>,
    driver: Option<JoinHandle<()>>,
    _session: Session,
    adapter: Adapter,
    application: Option<ApplicationHandle>,
    /// The advertisement, while one is wanted.
    advertisement: Option<AdvertisementHandle>,
    shared: Arc<Mutex<Shared>>,
    opened: Receiver<BleLink>,
    sync_tag: Option<Tag>,
    pairing_tag: Option<Tag>,
}

/// Starts a runtime on a thread of its own, which runs it until `stop` is
/// sent or dropped.
fn start_runtime() -> io::Result<(Handle, oneshot::Sender<()>, JoinHandle<()>)> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let handle = runtime.handle().clone();
    let (stop, stopped) = oneshot::channel::<()>();
    let driver = std::thread::Builder::new()
        .name("zp-ble".to_owned())
        .spawn(move || {
            runtime.block_on(async {
                let _ = stopped.await;
            });
        })?;
    Ok((handle, stop, driver))
}

/// The default adapter, if BlueZ has one and it is switched on.
async fn powered_adapter(session: &Session) -> io::Result<Adapter> {
    let adapter = session.default_adapter().await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("no Bluetooth adapter: {error}"),
        )
    })?;
    if !adapter.is_powered().await.map_err(bt)? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bluetooth is switched off",
        ));
    }
    Ok(adapter)
}

impl BlePeripheral {
    /// Whether this machine has a Bluetooth adapter that BlueZ can use, and
    /// it is switched on.
    pub fn is_supported() -> bool {
        let Ok((runtime, _stop, _driver)) = start_runtime() else {
            return false;
        };
        runtime.block_on(async {
            match Session::new().await {
                Ok(session) => powered_adapter(&session).await.is_ok(),
                Err(_) => false,
            }
        })
    }

    /// Publishes the GATT service. Advertising starts with
    /// [`Transport::advertise`] or [`Self::set_pairing_tag`].
    pub fn new() -> io::Result<Self> {
        let (runtime, stop, driver) = start_runtime()?;
        let shared = Arc::new(Mutex::new(Shared {
            tag_value: tag_value(None, None),
            active: None,
        }));
        let (opened_sender, opened) = mpsc::channel();
        let (session, adapter, application) = runtime.block_on(async {
            let session = Session::new().await.map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("BlueZ is not reachable: {error}"),
                )
            })?;
            let adapter = powered_adapter(&session).await?;
            let (application, control) = application(&shared);
            let application = adapter
                .serve_gatt_application(application)
                .await
                .map_err(bt)?;
            tokio::spawn(open_links(
                control,
                Arc::clone(&shared),
                opened_sender,
                Handle::current(),
            ));
            Ok::<_, io::Error>((session, adapter, application))
        })?;
        Ok(Self {
            runtime,
            stop: Some(stop),
            driver: Some(driver),
            _session: session,
            adapter,
            application: Some(application),
            advertisement: None,
            shared,
            opened,
            sync_tag: None,
            pairing_tag: None,
        })
    }

    fn publish_tags(&mut self) -> io::Result<()> {
        lock(&self.shared).tag_value = tag_value(self.sync_tag, self.pairing_tag);
        let wanted = self.sync_tag.is_some() || self.pairing_tag.is_some();
        if wanted && self.advertisement.is_none() {
            // The flags and the service UUID only; no device name (`ble.md` §3).
            let advertisement = Advertisement {
                advertisement_type: Type::Peripheral,
                service_uuids: [Uuid::from_u128(SERVICE_UUID)].into(),
                discoverable: Some(true),
                ..Default::default()
            };
            let handle = self
                .runtime
                .block_on(self.adapter.advertise(advertisement))
                .map_err(bt)?;
            self.advertisement = Some(handle);
        } else if !wanted {
            // Dropping the handle withdraws the advertisement. The `Tag` value
            // above already reads as zeros, as on Windows.
            self.advertisement = None;
        }
        Ok(())
    }

    /// Shows (or, with `None`, withdraws) the tag of a pairing offer, so that the
    /// device that scanned the QR code can find this peripheral
    /// ([`crate::ble::pairing_tag`]).
    pub fn set_pairing_tag(&mut self, tag: Option<Tag>) -> io::Result<()> {
        self.pairing_tag = tag;
        self.publish_tags()
    }

    /// Whether the service is currently being advertised.
    pub fn is_advertising(&self) -> io::Result<bool> {
        Ok(self.advertisement.is_some())
    }
}

impl Transport for BlePeripheral {
    fn name(&self) -> &'static str {
        "ble"
    }

    fn advertise(&mut self, tag: Tag) -> io::Result<()> {
        self.sync_tag = Some(tag);
        self.publish_tags()
    }

    fn stop_advertising(&mut self) -> io::Result<()> {
        self.sync_tag = None;
        self.publish_tags()
    }

    fn announce_pairing(&mut self, tag: Option<Tag>) -> io::Result<()> {
        self.set_pairing_tag(tag)
    }

    /// A peripheral does not scan: the central finds it.
    fn discover(&mut self, _wait: Duration) -> io::Result<Vec<Discovered>> {
        Ok(Vec::new())
    }

    /// A peripheral cannot open links: the central connects.
    fn connect(&mut self, _address: &Address) -> io::Result<Box<dyn Link>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a BLE peripheral cannot connect",
        ))
    }

    fn accept(&mut self, wait: Duration) -> io::Result<Option<Box<dyn Link>>> {
        match self.opened.recv_timeout(wait) {
            Ok(link) => Ok(Some(Box::new(link))),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

impl Drop for BlePeripheral {
    fn drop(&mut self) {
        self.advertisement = None;
        self.application = None;
        // Stopping the runtime closes the D-Bus connection, and BlueZ drops
        // whatever this process registered with it.
        drop(self.stop.take());
        if let Some(driver) = self.driver.take() {
            let _ = driver.join();
        }
    }
}

impl core::fmt::Debug for BlePeripheral {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlePeripheral")
            .field("advertising", &self.advertisement.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Publishes the service with BlueZ and advertises it. Needs a Bluetooth
    /// adapter that is switched on:
    ///
    /// ```text
    /// cargo test -p zp-transport -- --ignored ble
    /// ```
    #[test]
    #[ignore = "needs a Bluetooth adapter that is switched on"]
    fn the_service_is_published_and_advertised() {
        assert!(BlePeripheral::is_supported(), "no usable adapter");
        let mut peripheral = BlePeripheral::new().unwrap();
        assert!(!peripheral.is_advertising().unwrap());

        peripheral.advertise([0x11; 8]).unwrap();
        assert!(peripheral.is_advertising().unwrap());
        assert_eq!(lock(&peripheral.shared).tag_value[..8], [0x11; 8]);
        assert_eq!(lock(&peripheral.shared).tag_value[8..], [0; 8]);

        peripheral.set_pairing_tag(Some([0x22; 8])).unwrap();
        assert_eq!(lock(&peripheral.shared).tag_value[8..], [0x22; 8]);
        peripheral.set_pairing_tag(None).unwrap();

        assert!(
            peripheral
                .accept(Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
        assert!(peripheral.connect(&Address::Ble("x".into())).is_err());

        peripheral.stop_advertising().unwrap();
        assert!(!peripheral.is_advertising().unwrap());
        assert_eq!(lock(&peripheral.shared).tag_value, [0; TAG_VALUE_LEN]);

        peripheral.advertise([0x33; 8]).unwrap();
        assert!(peripheral.is_advertising().unwrap());
    }

    /// Without BlueZ (as on most CI machines), creating the peripheral fails
    /// with a reason, and does not hang or panic.
    #[test]
    fn without_bluez_the_peripheral_reports_why() {
        if BlePeripheral::is_supported() {
            return;
        }
        let error = BlePeripheral::new().unwrap_err();
        assert!(!error.to_string().is_empty());
    }
}
