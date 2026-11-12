//! Several transports used as one: the local network and Bluetooth LE side by
//! side.
//!
//! A device announces itself on every transport, sees the union of what they
//! discover, and answers a link from whichever brings one. Which transport an
//! address belongs to is decided by the transports themselves: each refuses
//! addresses that are not its own.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::discovery::Tag;
use crate::lan::LanTransport;
use crate::link::Link;
use crate::transport::{Address, Discovered, Transport};

/// A set of transports behind the [`Transport`] interface.
pub struct MultiTransport {
    transports: Vec<Box<dyn Transport>>,
}

impl MultiTransport {
    /// Combines `transports`. Earlier ones are asked first.
    pub fn new(transports: Vec<Box<dyn Transport>>) -> Self {
        Self { transports }
    }

    /// The names of the transports in use ("lan", "ble").
    pub fn names(&self) -> Vec<&'static str> {
        self.transports
            .iter()
            .map(|transport| transport.name())
            .collect()
    }

    /// The time each transport gets out of a total of `wait`.
    fn share(&self, wait: Duration) -> Duration {
        wait / u32::try_from(self.transports.len().max(1)).unwrap_or(u32::MAX)
    }
}

impl Transport for MultiTransport {
    fn name(&self) -> &'static str {
        "multi"
    }

    fn advertise(&mut self, tag: Tag) -> io::Result<()> {
        self.transports
            .iter_mut()
            .try_for_each(|transport| transport.advertise(tag))
    }

    fn stop_advertising(&mut self) -> io::Result<()> {
        // Stop all of them even if one fails.
        let mut result = Ok(());
        for transport in &mut self.transports {
            if let Err(error) = transport.stop_advertising() {
                result = Err(error);
            }
        }
        result
    }

    fn announce_pairing(&mut self, tag: Option<Tag>) -> io::Result<()> {
        self.transports
            .iter_mut()
            .try_for_each(|transport| transport.announce_pairing(tag))
    }

    fn discover(&mut self, wait: Duration) -> io::Result<Vec<Discovered>> {
        let share = self.share(wait);
        let mut found = Vec::new();
        for transport in &mut self.transports {
            found.extend(transport.discover(share)?);
        }
        Ok(found)
    }

    fn connect(&mut self, address: &Address) -> io::Result<Box<dyn Link>> {
        let mut last = io::Error::new(io::ErrorKind::Unsupported, "no transport is available");
        for transport in &mut self.transports {
            match transport.connect(address) {
                Ok(link) => return Ok(link),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    fn accept(&mut self, wait: Duration) -> io::Result<Option<Box<dyn Link>>> {
        let share = self.share(wait);
        for transport in &mut self.transports {
            if let Some(link) = transport.accept(share)? {
                return Ok(Some(link));
            }
        }
        Ok(None)
    }
}

impl core::fmt::Debug for MultiTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MultiTransport({:?})", self.names())
    }
}

/// The transports of a desktop device, as far as this machine has them.
#[derive(Debug)]
pub struct Nearby {
    /// The local network and Bluetooth LE, whichever are available.
    pub transport: MultiTransport,
    /// Where this device listens on the local network; empty without one.
    pub lan_endpoints: Vec<SocketAddr>,
    /// Whether Bluetooth LE is in use.
    pub ble: bool,
    /// Why a transport is missing, for the user.
    pub problems: Vec<String>,
}

/// Opens the local network transport and, where this machine can act as a
/// Bluetooth LE peripheral, that too. Either may be missing (no network, no
/// adapter); it is an error only if both are.
///
pub fn open_nearby() -> io::Result<Nearby> {
    let mut transports: Vec<Box<dyn Transport>> = Vec::new();
    let mut lan_endpoints = Vec::new();
    let mut problems = Vec::new();

    match LanTransport::new() {
        Ok(lan) => {
            let port = lan.port();
            lan_endpoints = lan
                .addresses()
                .iter()
                .map(|address| SocketAddr::new((*address).into(), port))
                .collect();
            transports.push(Box::new(lan));
        }
        Err(error) => problems.push(format!("local network: {error}")),
    }

    let ble = open_ble(&mut transports, &mut problems);

    if transports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            format!("no way to reach other devices ({})", problems.join("; ")),
        ));
    }
    Ok(Nearby {
        transport: MultiTransport::new(transports),
        lan_endpoints,
        ble,
        problems,
    })
}

#[cfg(windows)]
fn open_ble(transports: &mut Vec<Box<dyn Transport>>, problems: &mut Vec<String>) -> bool {
    use crate::ble_windows::BlePeripheral;

    match BlePeripheral::new() {
        Ok(ble) => {
            transports.push(Box::new(ble));
            true
        }
        Err(error) => {
            problems.push(format!("Bluetooth: {error}"));
            false
        }
    }
}

#[cfg(not(windows))]
fn open_ble(_transports: &mut Vec<Box<dyn Transport>>, problems: &mut Vec<String>) -> bool {
    problems.push("Bluetooth: not implemented for this system yet".to_owned());
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::LoopbackNetwork;

    #[test]
    fn links_arrive_from_any_of_the_transports() {
        let (first, second) = (LoopbackNetwork::new(), LoopbackNetwork::new());
        let mut multi = MultiTransport::new(vec![
            Box::new(first.endpoint()),
            Box::new(second.endpoint()),
        ]);
        assert_eq!(multi.names(), ["loopback", "loopback"]);
        multi.advertise([7; 8]).unwrap();

        // A device on each network finds this one and reaches it.
        for network in [&first, &second] {
            let mut other = network.endpoint();
            let found = other.discover(Duration::from_millis(10)).unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].tag, [7; 8]);
            let _link = other.connect(&found[0].address).unwrap();
            assert!(multi.accept(Duration::from_millis(200)).unwrap().is_some());
        }
        assert!(multi.accept(Duration::from_millis(20)).unwrap().is_none());

        // In the other direction, it sees and reaches devices on both.
        // (Loopback addresses are only unique within a network; real transports
        // have addresses of their own kind. Keep the two apart here.)
        let _spare = second.endpoint();
        let mut peers = [first.endpoint(), second.endpoint()];
        peers[0].advertise([1; 8]).unwrap();
        peers[1].advertise([2; 8]).unwrap();
        let mut found = multi.discover(Duration::from_millis(20)).unwrap();
        found.sort_by_key(|discovered| discovered.tag);
        assert_eq!(found.len(), 2);
        for (discovered, peer) in found.iter().zip(&mut peers) {
            let _link = multi.connect(&discovered.address).unwrap();
            assert!(peer.accept(Duration::from_millis(200)).unwrap().is_some());
        }

        multi.stop_advertising().unwrap();
        assert!(
            peers[0]
                .discover(Duration::from_millis(10))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn without_transports_nothing_is_found_or_reached() {
        let mut multi = MultiTransport::new(Vec::new());
        multi.advertise([1; 8]).unwrap();
        assert!(multi.discover(Duration::from_millis(1)).unwrap().is_empty());
        assert!(multi.accept(Duration::from_millis(1)).unwrap().is_none());
        assert!(multi.connect(&Address::Loopback(1)).is_err());
    }
}
