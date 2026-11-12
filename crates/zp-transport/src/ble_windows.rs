//! The Bluetooth LE peripheral for Windows (`docs/spec/ble.md`), built on the
//! WinRT GATT server (`GattServiceProvider`).
//!
//! The desktop is the GATT peripheral: it advertises the ZeroPass service and
//! waits for a mobile device (the central) to connect and subscribe to `Tx`.
//! From then on bytes written to `Rx` and notified on `Tx` form the link.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristicProperties, GattCommunicationStatus, GattLocalCharacteristic,
    GattLocalCharacteristicParameters, GattLocalService, GattProtectionLevel,
    GattReadRequestedEventArgs, GattServiceProvider, GattServiceProviderAdvertisementStatus,
    GattServiceProviderAdvertisingParameters, GattWriteOption, GattWriteRequestedEventArgs,
};
use windows::Devices::Bluetooth::{BluetoothAdapter, BluetoothError};
use windows::Foundation::TypedEventHandler;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use windows::core::{Array, GUID, IInspectable};

use crate::ble::{
    DEFAULT_PACKET_LEN, RX_UUID, SERVICE_UUID, TAG_UUID, TAG_VALUE_LEN, TX_UUID, tag_value,
};
use crate::discovery::Tag;
use crate::link::{ChannelReader, Link};
use crate::transport::{Address, Discovered, Transport};

fn win(error: windows::core::Error) -> io::Error {
    io::Error::other(error.message())
}

fn buffer_of(bytes: &[u8]) -> windows::core::Result<IBuffer> {
    CryptographicBuffer::CreateFromByteArray(bytes)
}

fn bytes_of(buffer: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buffer, &mut bytes)?;
    Ok(bytes.to_vec())
}

/// What the GATT event handlers and the transport share.
struct Shared {
    /// The current value of the `Tag` characteristic.
    tag_value: [u8; TAG_VALUE_LEN],
    /// Where bytes written to `Rx` go: the reader of the link in progress.
    active: Option<Sender<Vec<u8>>>,
    /// Links opened by a central, waiting to be accepted.
    opened: Sender<BleLink>,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A link to the central that subscribed to `Tx`.
pub struct BleLink {
    incoming: Receiver<Vec<u8>>,
    tx: GattLocalCharacteristic,
    shared: Arc<Mutex<Shared>>,
}

/// The writing half: notifies the subscribed central, one packet at a time.
struct NotifyWriter {
    tx: GattLocalCharacteristic,
    shared: Arc<Mutex<Shared>>,
}

impl NotifyWriter {
    fn notify(&self, bytes: &[u8]) -> windows::core::Result<bool> {
        let clients = self.tx.SubscribedClients()?;
        if clients.Size()? == 0 {
            return Ok(false);
        }
        // The largest notification the central negotiated (ATT MTU − 3).
        let packet = usize::from(clients.GetAt(0)?.MaxNotificationSize()?).max(DEFAULT_PACKET_LEN);
        for chunk in bytes.chunks(packet) {
            // Waiting for each notification is the back-pressure: the next packet
            // is only handed to the stack once it took the previous one.
            let results = self.tx.NotifyValueAsync(&buffer_of(chunk)?)?.join()?;
            for result in results {
                if result.Status()? != GattCommunicationStatus::Success {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl Write for NotifyWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.notify(bytes).map_err(win)? {
            Ok(bytes.len())
        } else {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for NotifyWriter {
    fn drop(&mut self) {
        // The link is over: stop routing `Rx` writes to it, so that the next
        // subscription opens a new link.
        lock(&self.shared).active = None;
    }
}

impl Link for BleLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let reader = ChannelReader::new(self.incoming);
        Ok((
            Box::new(reader),
            Box::new(NotifyWriter {
                tx: self.tx,
                shared: self.shared,
            }),
        ))
    }

    fn peer(&self) -> String {
        "ble:central".to_owned()
    }
}

fn characteristic(
    service: &GattLocalService,
    uuid: u128,
    properties: GattCharacteristicProperties,
) -> io::Result<GattLocalCharacteristic> {
    let create = || -> windows::core::Result<_> {
        let parameters = GattLocalCharacteristicParameters::new()?;
        parameters.SetCharacteristicProperties(properties)?;
        // No BLE-level encryption or authentication: Noise runs on top.
        parameters.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
        parameters.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;
        service
            .CreateCharacteristicAsync(GUID::from_u128(uuid), &parameters)?
            .join()
    };
    let result = create().map_err(win)?;
    if result.Error().map_err(win)? != BluetoothError::Success {
        return Err(io::Error::other(
            "the GATT characteristic could not be created",
        ));
    }
    result.Characteristic().map_err(win)
}

/// The Bluetooth LE peripheral transport.
pub struct BlePeripheral {
    provider: GattServiceProvider,
    shared: Arc<Mutex<Shared>>,
    opened: Receiver<BleLink>,
    sync_tag: Option<Tag>,
    pairing_tag: Option<Tag>,
    /// Whether advertising was requested and not withdrawn since.
    advertising: bool,
}

impl BlePeripheral {
    /// Whether this machine has a Bluetooth adapter that can act as a
    /// peripheral.
    pub fn is_supported() -> bool {
        BluetoothAdapter::GetDefaultAsync()
            .and_then(|operation| operation.join())
            .and_then(|adapter| adapter.IsPeripheralRoleSupported())
            .unwrap_or(false)
    }

    /// Publishes the GATT service. Advertising starts with
    /// [`Transport::advertise`] or [`Self::set_pairing_tag`].
    pub fn new() -> io::Result<Self> {
        if !Self::is_supported() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no Bluetooth adapter that supports the peripheral role",
            ));
        }
        let created = GattServiceProvider::CreateAsync(GUID::from_u128(SERVICE_UUID))
            .and_then(|operation| operation.join())
            .map_err(win)?;
        if created.Error().map_err(win)? != BluetoothError::Success {
            return Err(io::Error::other("the GATT service could not be created"));
        }
        let provider = created.ServiceProvider().map_err(win)?;
        let service = provider.Service().map_err(win)?;

        let tag = characteristic(&service, TAG_UUID, GattCharacteristicProperties::Read)?;
        let rx = characteristic(
            &service,
            RX_UUID,
            GattCharacteristicProperties::Write
                | GattCharacteristicProperties::WriteWithoutResponse,
        )?;
        let tx = characteristic(&service, TX_UUID, GattCharacteristicProperties::Notify)?;

        let (opened_sender, opened) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Shared {
            tag_value: tag_value(None, None),
            active: None,
            opened: opened_sender,
        }));

        // Tag: answer reads with the current tags.
        let state = Arc::clone(&shared);
        tag.ReadRequested(&TypedEventHandler::<
            GattLocalCharacteristic,
            GattReadRequestedEventArgs,
        >::new(move |_, args| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let deferral = args.GetDeferral()?;
            let request = args.GetRequestAsync()?.join()?;
            let value = lock(&state).tag_value;
            request.RespondWithValue(&buffer_of(&value)?)?;
            deferral.Complete()
        }))
        .map_err(win)?;

        // Rx: pass written bytes to the link in progress.
        let state = Arc::clone(&shared);
        rx.WriteRequested(&TypedEventHandler::<
            GattLocalCharacteristic,
            GattWriteRequestedEventArgs,
        >::new(move |_, args| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let deferral = args.GetDeferral()?;
            let request = args.GetRequestAsync()?.join()?;
            let bytes = bytes_of(&request.Value()?)?;
            if request.Option()? == GattWriteOption::WriteWithResponse {
                request.Respond()?;
            }
            if let Some(link) = &lock(&state).active {
                // The link may just have ended; then the bytes are dropped.
                let _ = link.send(bytes);
            }
            deferral.Complete()
        }))
        .map_err(win)?;

        // Tx: a subscription opens a link, the end of it closes the link.
        let state = Arc::clone(&shared);
        tx.SubscribedClientsChanged(
            &TypedEventHandler::<GattLocalCharacteristic, IInspectable>::new(move |sender, _| {
                let Some(tx) = sender.as_ref() else {
                    return Ok(());
                };
                let subscribed = tx.SubscribedClients()?.Size()?;
                let mut shared = lock(&state);
                if subscribed == 0 {
                    // Dropping the sender ends the link's incoming stream.
                    shared.active = None;
                } else if shared.active.is_none() {
                    let (sender, incoming) = mpsc::channel();
                    shared.active = Some(sender);
                    let link = BleLink {
                        incoming,
                        tx: tx.clone(),
                        shared: Arc::clone(&state),
                    };
                    let _ = shared.opened.send(link);
                }
                Ok(())
            }),
        )
        .map_err(win)?;

        Ok(Self {
            provider,
            shared,
            opened,
            sync_tag: None,
            pairing_tag: None,
            advertising: false,
        })
    }

    fn publish_tags(&mut self) -> io::Result<()> {
        lock(&self.shared).tag_value = tag_value(self.sync_tag, self.pairing_tag);
        let wanted = self.sync_tag.is_some() || self.pairing_tag.is_some();
        if wanted && !self.advertising {
            let start = || -> windows::core::Result<()> {
                let parameters = GattServiceProviderAdvertisingParameters::new()?;
                parameters.SetIsConnectable(true)?;
                parameters.SetIsDiscoverable(true)?;
                self.provider.StartAdvertisingWithParameters(&parameters)
            };
            start().map_err(win)?;
            self.advertising = true;
        } else if !wanted && self.advertising {
            // A request only: on the machine this was developed on (Windows 11
            // build 26300) the stack kept reporting the advertisement as started
            // afterwards. What withdraws the device for certain is the `Tag`
            // value above, which now reads as zeros, so that a central that still
            // finds the service disconnects without sending anything. Dropping
            // the peripheral releases the service altogether.
            self.provider.StopAdvertising().map_err(win)?;
            self.advertising = false;
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

    /// Whether the service is currently being advertised, according to the
    /// Bluetooth stack.
    pub fn is_advertising(&self) -> io::Result<bool> {
        let status = self.provider.AdvertisementStatus().map_err(win)?;
        Ok(status == GattServiceProviderAdvertisementStatus::Started
            || status == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData)
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
        if self.advertising {
            let _ = self.provider.StopAdvertising();
        }
    }
}

impl core::fmt::Debug for BlePeripheral {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlePeripheral")
            .field("advertising", &self.advertising)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    /// Publishes the service on this machine's Bluetooth adapter and checks that
    /// the stack reports it as advertised. Needs Bluetooth to be switched on:
    ///
    /// ```text
    /// cargo test -p zp-transport -- --ignored ble
    /// ```
    #[test]
    #[ignore = "needs a Bluetooth adapter that is switched on"]
    fn the_service_is_published_and_advertised() {
        assert!(
            BlePeripheral::is_supported(),
            "no adapter with the peripheral role"
        );
        let mut peripheral = BlePeripheral::new().unwrap();
        assert!(!peripheral.is_advertising().unwrap());

        peripheral.advertise([0x11; 8]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !peripheral.is_advertising().unwrap() {
            assert!(Instant::now() < deadline, "advertising did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(lock(&peripheral.shared).tag_value[..8], [0x11; 8]);
        assert_eq!(lock(&peripheral.shared).tag_value[8..], [0; 8]);

        // A pairing tag is shown next to the sync tag and withdrawn again.
        peripheral.set_pairing_tag(Some([0x22; 8])).unwrap();
        assert_eq!(lock(&peripheral.shared).tag_value[8..], [0x22; 8]);
        peripheral.set_pairing_tag(None).unwrap();

        // Nobody connects in this test, and a peripheral finds nobody itself.
        assert!(
            peripheral
                .accept(Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
        assert!(
            peripheral
                .discover(Duration::from_millis(10))
                .unwrap()
                .is_empty()
        );
        assert!(peripheral.connect(&Address::Ble("x".into())).is_err());

        // Without a tag the characteristic reads as zeros, whatever the stack
        // does about the advertisement (see `publish_tags`).
        peripheral.stop_advertising().unwrap();
        assert_eq!(lock(&peripheral.shared).tag_value, [0; TAG_VALUE_LEN]);

        // Announcing again after a withdrawal works.
        peripheral.advertise([0x33; 8]).unwrap();
        assert_eq!(lock(&peripheral.shared).tag_value[..8], [0x33; 8]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !peripheral.is_advertising().unwrap() {
            assert!(Instant::now() < deadline, "advertising did not restart");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
