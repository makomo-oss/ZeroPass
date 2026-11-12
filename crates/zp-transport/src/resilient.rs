//! The LAN transport kept alive across network changes.
//!
//! A [`LanTransport`] is bound to the local addresses the machine had when it
//! was opened. When Wi-Fi goes away, comes back or changes network, those
//! addresses change and the transport is of no use any more. [`ResilientLan`]
//! notices that and opens a fresh one, so that a long-running sync loop moves
//! between "local network available" and "not available" on its own while the
//! other transports (Bluetooth LE) carry on.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::discovery::Tag;
use crate::lan::LanTransport;
use crate::link::Link;
use crate::local_net::local_ipv4_addresses;
use crate::transport::{Address, Discovered, Transport};

/// How often the machine's addresses are compared with those in use.
const CHECK_INTERVAL: Duration = Duration::from_secs(3);

/// What opens the transport on the machine's current addresses.
type Opener = Box<dyn FnMut() -> io::Result<LanTransport> + Send>;
/// What reports the machine's current local addresses.
type Addresses = Box<dyn FnMut() -> io::Result<Vec<Ipv4Addr>> + Send>;

/// A [`LanTransport`] that is re-opened whenever this machine's local addresses
/// change, and that is simply quiet while there is no local network.
pub struct ResilientLan {
    inner: Option<LanTransport>,
    /// The tag to announce, kept so that a fresh transport announces it too.
    tag: Option<Tag>,
    checked: Option<Instant>,
    /// Why there is no transport right now, for the user.
    problem: Option<String>,
    open: Opener,
    addresses: Addresses,
    interval: Duration,
}

impl ResilientLan {
    /// Opens the local network transport if there is a local network now, and
    /// keeps watching otherwise.
    pub fn new() -> Self {
        Self::with(
            Box::new(LanTransport::new),
            Box::new(local_ipv4_addresses),
            CHECK_INTERVAL,
        )
    }

    fn with(open: Opener, addresses: Addresses, interval: Duration) -> Self {
        let mut lan = Self {
            inner: None,
            tag: None,
            checked: None,
            problem: None,
            open,
            addresses,
            interval,
        };
        lan.refresh();
        lan
    }

    /// Whether the local network is usable right now.
    pub fn is_up(&self) -> bool {
        self.inner.is_some()
    }

    /// Where this device listens on the local network; empty while it is down.
    pub fn endpoints(&self) -> Vec<SocketAddr> {
        self.inner.as_ref().map_or_else(Vec::new, |lan| {
            lan.addresses()
                .iter()
                .map(|address| SocketAddr::new((*address).into(), lan.port()))
                .collect()
        })
    }

    /// Why the local network is not usable, if it is not.
    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Re-opens the transport if the machine's addresses are no longer the ones
    /// it was opened on. Cheap enough to call before every operation: it looks
    /// at the addresses at most once per interval.
    fn refresh(&mut self) {
        if self
            .checked
            .is_some_and(|checked| checked.elapsed() < self.interval)
        {
            return;
        }
        self.checked = Some(Instant::now());
        let mut current = match (self.addresses)() {
            Ok(addresses) => addresses,
            Err(error) => {
                self.down(&error);
                return;
            }
        };
        current.sort();
        let mut in_use = self
            .inner
            .as_ref()
            .map_or_else(Vec::new, |lan| lan.addresses().to_vec());
        in_use.sort();
        if self.inner.is_some() && in_use == current {
            return;
        }

        // Close the old one first: it holds the port and the mDNS sockets.
        self.inner = None;
        if current.is_empty() {
            self.problem = Some("this device is not connected to a local network".to_owned());
            return;
        }
        match (self.open)() {
            Ok(mut lan) => {
                let announced = match self.tag {
                    Some(tag) => lan.advertise(tag),
                    None => Ok(()),
                };
                match announced {
                    Ok(()) => {
                        self.inner = Some(lan);
                        self.problem = None;
                    }
                    Err(error) => self.down(&error),
                }
            }
            Err(error) => self.down(&error),
        }
    }

    /// Gives up the current transport after it failed; the next check opens a
    /// new one if the network is there.
    fn down(&mut self, error: &io::Error) {
        self.inner = None;
        self.problem = Some(error.to_string());
    }

    /// Runs `operation` on the transport, if there is one. A failure takes the
    /// transport down instead of reaching the caller: a lost network must not
    /// stop the other transports.
    fn attempt<T>(
        &mut self,
        operation: impl FnOnce(&mut LanTransport) -> io::Result<T>,
    ) -> Option<T> {
        self.refresh();
        let result = operation(self.inner.as_mut()?);
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.down(&error);
                None
            }
        }
    }
}

impl Default for ResilientLan {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for ResilientLan {
    fn name(&self) -> &'static str {
        "lan"
    }

    fn advertise(&mut self, tag: Tag) -> io::Result<()> {
        self.tag = Some(tag);
        self.attempt(|lan| lan.advertise(tag));
        Ok(())
    }

    fn stop_advertising(&mut self) -> io::Result<()> {
        self.tag = None;
        if let Some(lan) = self.inner.as_mut() {
            let _ = lan.stop_advertising();
        }
        Ok(())
    }

    fn discover(&mut self, wait: Duration) -> io::Result<Vec<Discovered>> {
        Ok(self.attempt(|lan| lan.discover(wait)).unwrap_or_default())
    }

    fn connect(&mut self, address: &Address) -> io::Result<Box<dyn Link>> {
        self.refresh();
        match self.inner.as_mut() {
            // A refused connection says nothing about the network as a whole.
            Some(lan) => lan.connect(address),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the local network is not available",
            )),
        }
    }

    fn accept(&mut self, wait: Duration) -> io::Result<Option<Box<dyn Link>>> {
        if !self.is_up() {
            self.refresh();
        }
        if !self.is_up() {
            // Wait like a transport without visitors would, so that a caller in
            // a loop does not spin.
            std::thread::sleep(wait);
            return Ok(None);
        }
        Ok(self.attempt(|lan| lan.accept(wait)).flatten())
    }
}

impl core::fmt::Debug for ResilientLan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResilientLan")
            .field("up", &self.is_up())
            .field("problem", &self.problem)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    type Shared<T> = Arc<Mutex<T>>;

    /// A machine whose set of local addresses the test controls. The transport
    /// is opened for real, on the loopback address.
    fn machine() -> (ResilientLan, Shared<Vec<Ipv4Addr>>, Shared<u32>) {
        let addresses = Arc::new(Mutex::new(Vec::new()));
        let opened = Arc::new(Mutex::new(0));
        let (reported, count) = (Arc::clone(&addresses), Arc::clone(&opened));
        let lan = ResilientLan::with(
            Box::new(move || {
                *count.lock().unwrap() += 1;
                LanTransport::on_addresses(vec![Ipv4Addr::LOCALHOST])
            }),
            Box::new(move || Ok(reported.lock().unwrap().clone())),
            Duration::ZERO,
        );
        (lan, addresses, opened)
    }

    #[test]
    #[allow(clippy::unwrap_used, reason = "test")]
    fn it_follows_the_network_coming_and_going() {
        let (mut lan, addresses, opened) = machine();
        // No network: quiet, not failing.
        assert!(!lan.is_up());
        assert!(lan.problem().is_some());
        lan.advertise([7; 8]).unwrap();
        assert!(lan.discover(Duration::from_millis(1)).unwrap().is_empty());
        assert!(lan.accept(Duration::from_millis(1)).unwrap().is_none());
        assert!(lan.connect(&Address::Loopback(1)).is_err());
        assert!(lan.endpoints().is_empty());
        assert_eq!(*opened.lock().unwrap(), 0);

        // The network appears: the transport opens and announces the tag that
        // was asked for while it was down.
        *addresses.lock().unwrap() = vec![Ipv4Addr::LOCALHOST];
        assert!(lan.accept(Duration::from_millis(1)).unwrap().is_none());
        assert!(lan.is_up());
        assert_eq!(lan.problem(), None);
        assert_eq!(lan.endpoints().len(), 1);
        assert_eq!(*opened.lock().unwrap(), 1);
        let first_port = lan.endpoints()[0].port();

        // Nothing changes: the same transport stays.
        lan.advertise([8; 8]).unwrap();
        assert_eq!(*opened.lock().unwrap(), 1);
        assert_eq!(lan.endpoints()[0].port(), first_port);

        // The network goes away, then another one comes: a fresh transport.
        addresses.lock().unwrap().clear();
        lan.advertise([8; 8]).unwrap();
        assert!(!lan.is_up());
        *addresses.lock().unwrap() = vec![Ipv4Addr::LOCALHOST];
        lan.advertise([8; 8]).unwrap();
        assert!(lan.is_up());
        assert_eq!(*opened.lock().unwrap(), 2);
    }
}
