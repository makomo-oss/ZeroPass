//! The transport abstraction: how devices find each other and open links.
//!
//! A transport announces this device under an anonymous [`Tag`], reports the
//! tags it sees nearby, and opens or accepts [`Link`]s. It does not know which
//! vault or device a tag belongs to, and it sees only ciphertext on its links.
//! Implementations: [`LoopbackTransport`] (in memory), the LAN transport, and
//! Bluetooth LE.

use core::fmt;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::discovery::Tag;
use crate::link::{Link, MemoryLink};

/// Where a discovered device can be reached. Opaque to everything but the
/// transport that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// An endpoint of the loopback transport.
    Loopback(u64),
    /// A TCP endpoint on the local network.
    Socket(SocketAddr),
    /// A Bluetooth LE device, by its platform identifier.
    Ble(String),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Loopback(id) => write!(f, "loopback:{id}"),
            Address::Socket(address) => write!(f, "{address}"),
            Address::Ble(id) => write!(f, "ble:{id}"),
        }
    }
}

/// A device seen nearby.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// The anonymous tag it announces.
    pub tag: Tag,
    /// Where to reach it.
    pub address: Address,
}

/// A way for devices to find and reach each other.
pub trait Transport: Send {
    /// A short name for logs ("lan", "ble", "loopback").
    fn name(&self) -> &'static str;

    /// Announces this device under `tag` and starts accepting links. Calling it
    /// again replaces the tag (tags rotate).
    fn advertise(&mut self, tag: Tag) -> io::Result<()>;

    /// Stops announcing this device.
    fn stop_advertising(&mut self) -> io::Result<()>;

    /// Shows (or, with `None`, withdraws) the tag of an open pairing offer, on
    /// transports where the joining device has to pick this one out among
    /// others nearby (Bluetooth LE; see [`crate::ble::pairing_tag`]). On the
    /// local network the pairing code carries the address, so the default does
    /// nothing.
    fn announce_pairing(&mut self, _tag: Option<Tag>) -> io::Result<()> {
        Ok(())
    }

    /// The devices currently announced nearby, after listening for up to `wait`.
    fn discover(&mut self, wait: Duration) -> io::Result<Vec<Discovered>>;

    /// Opens a link to a discovered device.
    fn connect(&mut self, address: &Address) -> io::Result<Box<dyn Link>>;

    /// Waits up to `wait` for an incoming link.
    fn accept(&mut self, wait: Duration) -> io::Result<Option<Box<dyn Link>>>;
}

struct Node {
    tag: Tag,
    incoming: Sender<MemoryLink>,
}

/// An in-memory "network" for tests: endpoints created from the same network
/// see each other's announcements and can connect.
#[derive(Clone, Default)]
pub struct LoopbackNetwork {
    nodes: Arc<Mutex<HashMap<u64, Node>>>,
    next_id: Arc<Mutex<u64>>,
}

impl LoopbackNetwork {
    /// An empty network.
    pub fn new() -> Self {
        Self::default()
    }

    /// A new endpoint on this network.
    pub fn endpoint(&self) -> LoopbackTransport {
        let mut next = self.next_id.lock().unwrap_or_else(PoisonError::into_inner);
        *next += 1;
        let (sender, receiver) = mpsc::channel();
        LoopbackTransport {
            network: self.clone(),
            id: *next,
            sender,
            receiver,
        }
    }
}

/// One endpoint of a [`LoopbackNetwork`].
pub struct LoopbackTransport {
    network: LoopbackNetwork,
    id: u64,
    sender: Sender<MemoryLink>,
    receiver: Receiver<MemoryLink>,
}

impl LoopbackTransport {
    fn nodes(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Node>> {
        self.network
            .nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Transport for LoopbackTransport {
    fn name(&self) -> &'static str {
        "loopback"
    }

    fn advertise(&mut self, tag: Tag) -> io::Result<()> {
        let node = Node {
            tag,
            incoming: self.sender.clone(),
        };
        self.nodes().insert(self.id, node);
        Ok(())
    }

    fn stop_advertising(&mut self) -> io::Result<()> {
        self.nodes().remove(&self.id);
        Ok(())
    }

    fn discover(&mut self, _wait: Duration) -> io::Result<Vec<Discovered>> {
        let mut found: Vec<Discovered> = self
            .nodes()
            .iter()
            .filter(|(id, _)| **id != self.id)
            .map(|(id, node)| Discovered {
                tag: node.tag,
                address: Address::Loopback(*id),
            })
            .collect();
        found.sort_by_key(|discovered| match discovered.address {
            Address::Loopback(id) => id,
            _ => 0,
        });
        Ok(found)
    }

    fn connect(&mut self, address: &Address) -> io::Result<Box<dyn Link>> {
        let Address::Loopback(id) = address else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a loopback address",
            ));
        };
        let (mine, theirs) = MemoryLink::pair();
        self.nodes()
            .get(id)
            .ok_or(io::ErrorKind::NotFound)?
            .incoming
            .send(theirs)
            .map_err(|_| io::ErrorKind::ConnectionRefused)?;
        Ok(Box::new(mine))
    }

    fn accept(&mut self, wait: Duration) -> io::Result<Option<Box<dyn Link>>> {
        match self.receiver.recv_timeout(wait) {
            Ok(link) => Ok(Some(Box::new(link))),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

impl Drop for LoopbackTransport {
    fn drop(&mut self) {
        self.nodes().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    const WAIT: Duration = Duration::from_millis(200);

    #[test]
    fn endpoints_see_announcements_and_connect() {
        let network = LoopbackNetwork::new();
        let (mut a, mut b, mut c) = (network.endpoint(), network.endpoint(), network.endpoint());
        assert!(a.discover(WAIT).unwrap().is_empty());

        b.advertise([2; 8]).unwrap();
        c.advertise([3; 8]).unwrap();
        let found = a.discover(WAIT).unwrap();
        assert_eq!(
            found.iter().map(|d| d.tag).collect::<Vec<_>>(),
            [[2; 8], [3; 8]]
        );
        // A device does not discover itself.
        assert_eq!(b.discover(WAIT).unwrap().len(), 1);

        let link = a.connect(&found[0].address).unwrap();
        let accepted = b.accept(WAIT).unwrap().unwrap();
        assert!(c.accept(Duration::from_millis(20)).unwrap().is_none());

        let (_, mut writer) = link.split().unwrap();
        let (mut reader, _) = accepted.split().unwrap();
        writer.write_all(b"ping").unwrap();
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"ping");
    }

    #[test]
    fn tags_rotate_and_announcements_stop() {
        let network = LoopbackNetwork::new();
        let (mut a, mut b) = (network.endpoint(), network.endpoint());
        b.advertise([1; 8]).unwrap();
        b.advertise([2; 8]).unwrap();
        assert_eq!(a.discover(WAIT).unwrap()[0].tag, [2; 8]);

        b.stop_advertising().unwrap();
        assert!(a.discover(WAIT).unwrap().is_empty());
        b.advertise([3; 8]).unwrap();
        let address = a.discover(WAIT).unwrap()[0].address.clone();
        drop(b);
        // A device that left can no longer be discovered or reached.
        assert!(a.discover(WAIT).unwrap().is_empty());
        assert!(a.connect(&address).is_err());
        assert!(a.connect(&Address::Ble("x".into())).is_err());
    }
}
