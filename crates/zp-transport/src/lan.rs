//! The LAN transport: discovery with mDNS / DNS-SD and links over TCP.
//!
//! * **Announcement.** The device registers a DNS-SD service of type
//!   `_zeropass._tcp.local.` whose instance name and host name are the hex form
//!   of its current anonymous tag ([`crate::discovery`]). Nothing that identifies
//!   the user, the device or the vault is published; the tag changes every
//!   15 minutes. (The device's IP and MAC address are visible to the local
//!   network regardless, as for any device on it.)
//! * **Local only.** The transport listens only on this machine's private and
//!   link-local IPv4 addresses, and connects to and accepts from local addresses
//!   only ([`crate::local_net`]).
//! * **No trust in the network.** mDNS answers can be forged by anyone on the
//!   LAN. They are only hints for where to connect: the Noise handshake on the
//!   link decides whether the other end is the device it claims to be.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mdns_sd::{IfKind, Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::discovery::{TAG_LEN, Tag};
use crate::link::{Link, READ_POLL};
use crate::local_net::{is_local, local_ipv4_addresses};
use crate::transport::{Address, Discovered, Transport};

/// The DNS-SD service type.
pub const SERVICE_TYPE: &str = "_zeropass._tcp.local.";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(20);

fn other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

fn tag_to_hex(tag: &Tag) -> String {
    tag.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Parses the instance name of a full service name back into a tag.
fn tag_from_fullname(fullname: &str) -> Option<Tag> {
    let instance = fullname.strip_suffix(SERVICE_TYPE)?.strip_suffix('.')?;
    if instance.len() != TAG_LEN * 2 || !instance.is_ascii() {
        return None;
    }
    let mut tag = [0u8; TAG_LEN];
    for (index, byte) in tag.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&instance[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(tag)
}

/// A TCP connection as a [`Link`].
#[derive(Debug)]
pub struct TcpLink {
    stream: TcpStream,
}

impl TcpLink {
    fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        Ok(Self { stream })
    }
}

/// The writing half; closing it tells the peer that the link is finished.
struct TcpWriter(TcpStream);

impl Write for TcpWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Drop for TcpWriter {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

impl Link for TcpLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let reader = self.stream.try_clone()?;
        // Wake up regularly so the reading thread notices a dropped connection.
        reader.set_read_timeout(Some(READ_POLL))?;
        Ok((Box::new(reader), Box::new(TcpWriter(self.stream))))
    }

    fn peer(&self) -> String {
        self.stream
            .peer_addr()
            .map_or_else(|_| "tcp:?".to_owned(), |address| address.to_string())
    }
}

/// The LAN transport.
pub struct LanTransport {
    daemon: ServiceDaemon,
    listeners: Vec<TcpListener>,
    addresses: Vec<Ipv4Addr>,
    port: u16,
    /// The full name of the service currently registered, if any.
    registered: Option<String>,
    browser: Option<Receiver<ServiceEvent>>,
    /// What discovery has resolved so far, by full service name.
    seen: HashMap<String, Discovered>,
}

impl LanTransport {
    /// Opens the transport on this machine's private and link-local IPv4
    /// addresses. Fails with `NotConnected` if the machine has none, i.e. it is
    /// not on a local network.
    pub fn new() -> io::Result<Self> {
        let addresses = local_ipv4_addresses()?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "this device is not connected to a local network",
            ));
        }
        Self::on_addresses(addresses)
    }

    /// Opens the transport on the given addresses (which must belong to this
    /// machine).
    fn on_addresses(addresses: Vec<Ipv4Addr>) -> io::Result<Self> {
        // One port on every address: the first bind picks it.
        let mut listeners: Vec<TcpListener> = Vec::new();
        let mut port = 0;
        let mut bound = Vec::new();
        for address in addresses {
            match TcpListener::bind(SocketAddrV4::new(address, port)) {
                Ok(listener) => {
                    port = listener.local_addr()?.port();
                    listener.set_nonblocking(true)?;
                    listeners.push(listener);
                    bound.push(address);
                }
                // An interface that went away, or the port being taken there.
                Err(_) if !listeners.is_empty() => {}
                Err(error) => return Err(error),
            }
        }

        let daemon = ServiceDaemon::new().map_err(other)?;
        // IPv4 only for now; see the module documentation of `local_net`.
        daemon.disable_interface(IfKind::IPv6).map_err(other)?;
        Ok(Self {
            daemon,
            listeners,
            addresses: bound,
            port,
            registered: None,
            browser: None,
            seen: HashMap::new(),
        })
    }

    /// The TCP port the transport listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The addresses the transport listens on.
    pub fn addresses(&self) -> &[Ipv4Addr] {
        &self.addresses
    }

    fn unregister(&mut self) {
        if let Some(fullname) = self.registered.take() {
            // The receiver reports completion; nothing to wait for.
            let _ = self.daemon.unregister(&fullname);
        }
    }

    fn handle_event(&mut self, event: ServiceEvent) {
        match event {
            ServiceEvent::ServiceResolved(service) => {
                if self.registered.as_deref() == Some(service.fullname.as_str()) {
                    return;
                }
                let Some(tag) = tag_from_fullname(&service.fullname) else {
                    return;
                };
                // Prefer the lowest local address; ignore anything not local.
                let mut addresses: Vec<Ipv4Addr> = service
                    .get_addresses_v4()
                    .into_iter()
                    .filter(|address| is_local(IpAddr::V4(*address)))
                    .collect();
                addresses.sort();
                if let Some(address) = addresses.first() {
                    let address = Address::Socket(SocketAddr::new((*address).into(), service.port));
                    self.seen
                        .insert(service.fullname.clone(), Discovered { tag, address });
                }
            }
            ServiceEvent::ServiceRemoved(_, fullname) => {
                self.seen.remove(&fullname);
            }
            _ => {}
        }
    }
}

impl Transport for LanTransport {
    fn name(&self) -> &'static str {
        "lan"
    }

    fn advertise(&mut self, tag: Tag) -> io::Result<()> {
        let name = tag_to_hex(&tag);
        // The host name is derived from the tag too: the machine's real host
        // name would identify the device.
        let host = format!("zp-{name}.local.");
        let addresses: Vec<IpAddr> = self
            .addresses
            .iter()
            .map(|address| (*address).into())
            .collect();
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &name,
            &host,
            addresses.as_slice(),
            self.port,
            None::<HashMap<String, String>>,
        )
        .map_err(other)?;
        let fullname = service.get_fullname().to_owned();
        if self.registered.as_deref() == Some(fullname.as_str()) {
            return Ok(());
        }
        self.unregister();
        self.daemon.register(service).map_err(other)?;
        self.registered = Some(fullname);
        Ok(())
    }

    fn stop_advertising(&mut self) -> io::Result<()> {
        self.unregister();
        Ok(())
    }

    fn discover(&mut self, wait: Duration) -> io::Result<Vec<Discovered>> {
        if self.browser.is_none() {
            self.browser = Some(self.daemon.browse(SERVICE_TYPE).map_err(other)?);
        }
        let deadline = Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(browser) = &self.browser else { break };
            match browser.recv_timeout(remaining) {
                Ok(event) => self.handle_event(event),
                Err(_) => break,
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        let mut found: Vec<Discovered> = self.seen.values().cloned().collect();
        found.sort_by_key(|discovered| discovered.tag);
        Ok(found)
    }

    fn connect(&mut self, address: &Address) -> io::Result<Box<dyn Link>> {
        let Address::Socket(address) = address else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a network address",
            ));
        };
        if !is_local(address.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to connect outside the local network",
            ));
        }
        let stream = TcpStream::connect_timeout(address, CONNECT_TIMEOUT)?;
        Ok(Box::new(TcpLink::new(stream)?))
    }

    fn accept(&mut self, wait: Duration) -> io::Result<Option<Box<dyn Link>>> {
        let deadline = Instant::now() + wait;
        loop {
            for listener in &self.listeners {
                match listener.accept() {
                    // A connection from outside the local network is dropped.
                    Ok((stream, peer)) if is_local(peer.ip()) => {
                        return Ok(Some(Box::new(TcpLink::new(stream)?)));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(ACCEPT_POLL);
        }
    }
}

impl Drop for LanTransport {
    fn drop(&mut self) {
        self.unregister();
        let _ = self.daemon.shutdown();
    }
}

impl core::fmt::Debug for LanTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LanTransport")
            .field("addresses", &self.addresses)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::Connection;

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn tags_survive_the_service_name() {
        let tag = [0x00, 0x1f, 0xa0, 0xff, 0x12, 0x34, 0x56, 0x78];
        let fullname = format!("{}.{SERVICE_TYPE}", tag_to_hex(&tag));
        assert_eq!(fullname, "001fa0ff12345678._zeropass._tcp.local.");
        assert_eq!(tag_from_fullname(&fullname), Some(tag));

        for bad in [
            "001fa0ff12345678._http._tcp.local.",
            "001fa0ff1234567._zeropass._tcp.local.",
            "001fa0ff123456789a._zeropass._tcp.local.",
            "zzzzzzzzzzzzzzzz._zeropass._tcp.local.",
            "ｚｚｚｚｚｚｚｚ._zeropass._tcp.local.",
            "_zeropass._tcp.local.",
            "",
        ] {
            assert_eq!(tag_from_fullname(bad), None, "{bad:?}");
        }
    }

    /// The TCP part on the loopback interface, which every machine has.
    fn loopback_transport() -> LanTransport {
        LanTransport::on_addresses(vec![Ipv4Addr::LOCALHOST]).unwrap()
    }

    #[test]
    fn tcp_links_carry_bytes_both_ways() {
        let (mut a, mut b) = (loopback_transport(), loopback_transport());
        assert_ne!(a.port(), b.port());
        let address = Address::Socket(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), a.port()));

        let outgoing = b.connect(&address).unwrap();
        let incoming = a.accept(WAIT).unwrap().expect("a connection was made");
        assert!(a.accept(Duration::from_millis(30)).unwrap().is_none());
        assert!(incoming.peer().starts_with("127.0.0.1:"));

        let mut b_side = Connection::open(outgoing, WAIT).unwrap();
        let mut a_side = Connection::open(incoming, WAIT).unwrap();
        b_side.send(b"hello over tcp").unwrap();
        let mut received = Vec::new();
        while received.len() < 14 {
            received.extend(a_side.receive().unwrap());
        }
        assert_eq!(received, b"hello over tcp");
        a_side.send(b"and back").unwrap();
        assert_eq!(b_side.receive().unwrap(), b"and back");

        // Dropping one side closes the link for the other.
        drop(a_side);
        assert!(matches!(b_side.receive(), Err(crate::DriveError::Closed)));
    }

    #[test]
    fn connections_beyond_the_local_network_are_refused_before_dialling() {
        let mut transport = loopback_transport();
        for address in ["8.8.8.8:443", "[2001:4860:4860::8888]:443", "100.64.0.1:80"] {
            let error = transport
                .connect(&Address::Socket(address.parse().unwrap()))
                .err()
                .expect("must be refused");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{address}");
        }
        assert!(transport.connect(&Address::Loopback(1)).is_err());
    }

    /// Discovery over real mDNS. Needs a network interface with a private
    /// address and working multicast, which CI machines do not reliably have:
    ///
    /// ```text
    /// cargo test -p zp-transport -- --ignored mdns
    /// ```
    #[test]
    #[ignore = "needs a local network interface with multicast"]
    fn devices_find_each_other_with_mdns_and_connect() {
        let (mut a, mut b) = (LanTransport::new().unwrap(), LanTransport::new().unwrap());
        let (tag_a, tag_b) = ([0xA1; TAG_LEN], [0xB2; TAG_LEN]);
        a.advertise(tag_a).unwrap();
        b.advertise(tag_b).unwrap();

        let find = |transport: &mut LanTransport, wanted: Tag| -> Option<Discovered> {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                let found = transport.discover(Duration::from_millis(500)).unwrap();
                if let Some(discovered) = found.into_iter().find(|d| d.tag == wanted) {
                    return Some(discovered);
                }
            }
            None
        };
        let b_seen_by_a = find(&mut a, tag_b).expect("a discovers b");
        let a_seen_by_b = find(&mut b, tag_a).expect("b discovers a");
        // A device does not list itself.
        assert!(
            a.discover(Duration::from_millis(100))
                .unwrap()
                .iter()
                .all(|d| d.tag != tag_a)
        );
        let Address::Socket(address) = &a_seen_by_b.address else {
            panic!("a socket address")
        };
        assert!(is_local(address.ip()) && !address.ip().is_loopback());
        assert_eq!(address.port(), a.port());

        // Connect using only what discovery returned.
        let outgoing = a.connect(&b_seen_by_a.address).unwrap();
        let incoming = b.accept(WAIT).unwrap().expect("b accepts");
        let mut a_side = Connection::open(outgoing, WAIT).unwrap();
        let mut b_side = Connection::open(incoming, WAIT).unwrap();
        a_side.send(b"found you").unwrap();
        assert_eq!(b_side.receive().unwrap(), b"found you");

        // A rotated tag replaces the old announcement.
        let rotated = [0xA3; TAG_LEN];
        a.advertise(rotated).unwrap();
        assert!(find(&mut b, rotated).is_some());
    }
}
