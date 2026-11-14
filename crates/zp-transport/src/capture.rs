//! Checking a packet capture against the promise of `docs/spec/lan.md`: nothing
//! this device sends for ZeroPass leaves the local link.
//!
//! The capture is a pcapng file taken on this machine's network interface while
//! ZeroPass pairs and syncs, restricted by the capturing tool to the ports
//! ZeroPass uses (`scripts/check-lan-capture.ps1`). [`analyse`] looks at every
//! IPv4 packet in it that was sent from one of this machine's addresses and
//! reports those that break a rule:
//!
//! * the destination must be on the local link (private, link-local, or the
//!   link-local multicast range used by mDNS);
//! * a TCP packet must carry a hop limit (TTL) of 1.
//!
//! This is a verification aid, not part of the product: it parses just enough
//! of pcapng, Ethernet, IEEE 802.11 and IPv4 for that.
//!
//! On a Wi-Fi adapter, Windows' Packet Monitor records the frames the driver
//! handles: IEEE 802.11 data frames, not Ethernet. It still labels the whole
//! capture Ethernet, so a frame labelled Ethernet is first tried as an 802.11
//! data frame that carries IPv4, and read as Ethernet only if it is not one.

use std::net::{IpAddr, Ipv4Addr};

use crate::local_net::is_local;

const BLOCK_SECTION_HEADER: u32 = 0x0A0D_0D0A;
const BLOCK_INTERFACE: u32 = 1;
const BLOCK_ENHANCED_PACKET: u32 = 6;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const LINKTYPE_ETHERNET: u16 = 1;
const LINKTYPE_RAW: u16 = 101;
const LINKTYPE_IEEE802_11: u16 = 105;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;
/// The LLC/SNAP header in front of an Ethernet type in an 802.11 data frame.
const LLC_SNAP: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

/// Why a capture could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// The file is not a pcapng capture this tool understands.
    #[error("not a readable pcapng capture: {0}")]
    Malformed(&'static str),
}

/// A packet this machine sent that breaks a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Where the packet came from (one of this machine's addresses).
    pub source: Ipv4Addr,
    /// Where it was going.
    pub destination: Ipv4Addr,
    /// Its hop limit.
    pub ttl: u8,
    /// The IP protocol number (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Source and destination port, for TCP and UDP.
    pub ports: Option<(u16, u16)>,
    /// What is wrong with it.
    pub reason: &'static str,
}

/// What a capture contained.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureReport {
    /// Packets in the file.
    pub packets: usize,
    /// IPv4 packets sent from one of this machine's addresses.
    pub sent: usize,
    /// Of those, TCP packets.
    pub sent_tcp: usize,
    /// Of those, UDP packets.
    pub sent_udp: usize,
    /// The distinct destinations of the packets sent.
    pub destinations: Vec<Ipv4Addr>,
    /// The packets that break a rule.
    pub violations: Vec<Violation>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    big_endian: bool,
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let raw: [u8; 2] = self.bytes.get(at..at + 2)?.try_into().ok()?;
        Some(if self.big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let raw: [u8; 4] = self.bytes.get(at..at + 4)?.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    }
}

/// The IPv4 packet inside a captured frame, if it is one.
fn ipv4_of(frame: &[u8], link_type: u16) -> Option<&[u8]> {
    match link_type {
        LINKTYPE_RAW => Some(frame),
        LINKTYPE_IEEE802_11 => ipv4_of_802_11(frame),
        // An Ethernet frame that carries IPv4 cannot pass for an 802.11 one: it
        // would need the LLC/SNAP bytes where its IPv4 header has its checksum
        // and addresses.
        LINKTYPE_ETHERNET => ipv4_of_802_11(frame).or_else(|| ipv4_of_ethernet(frame)),
        _ => None,
    }
}

fn ipv4_of_ethernet(frame: &[u8]) -> Option<&[u8]> {
    let mut offset = 12;
    let mut ether_type = u16::from_be_bytes(frame.get(offset..offset + 2)?.try_into().ok()?);
    if ether_type == ETHERTYPE_VLAN {
        offset += 4;
        ether_type = u16::from_be_bytes(frame.get(offset..offset + 2)?.try_into().ok()?);
    }
    (ether_type == ETHERTYPE_IPV4)
        .then(|| frame.get(offset + 2..))
        .flatten()
}

/// The IPv4 packet in an unencrypted IEEE 802.11 data frame, behind its MAC
/// header and an LLC/SNAP header.
fn ipv4_of_802_11(frame: &[u8]) -> Option<&[u8]> {
    let (&control, &flags) = (frame.first()?, frame.get(1)?);
    let is_data = (control >> 2) & 0b11 == 2;
    let protected = flags & 0x40 != 0;
    if !is_data || protected {
        return None;
    }
    // 24 bytes, plus a fourth address between access points, plus QoS
    // control in a QoS data frame, plus HT control when such a frame has the
    // order bit.
    let qos = control & 0x80 != 0;
    let mut header_len = 24;
    if flags & 0b11 == 0b11 {
        header_len += 6;
    }
    if qos {
        header_len += 2;
        if flags & 0x80 != 0 {
            header_len += 4;
        }
    }
    let llc = frame.get(header_len..header_len + 8)?;
    (llc[..6] == LLC_SNAP && llc[6..] == ETHERTYPE_IPV4.to_be_bytes())
        .then(|| frame.get(header_len + 8..))
        .flatten()
}

/// Whether a packet to `destination` stays on the local link.
fn stays_local(destination: Ipv4Addr) -> bool {
    // 224.0.0.0/24 is never forwarded by routers; mDNS uses 224.0.0.251.
    let [a, b, c, _] = destination.octets();
    is_local(IpAddr::V4(destination)) || (a, b, c) == (224, 0, 0) || destination.is_broadcast()
}

fn inspect(packet: &[u8], local: &[Ipv4Addr], report: &mut CaptureReport) {
    // Version 4, and a header of at least 20 bytes that is all there.
    let Some(&first) = packet.first() else { return };
    let header_len = usize::from(first & 0x0F) * 4;
    if first >> 4 != 4 || header_len < 20 || packet.len() < header_len {
        return;
    }
    let ttl = packet[8];
    let protocol = packet[9];
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if !local.contains(&source) {
        return;
    }
    report.sent += 1;
    match protocol {
        PROTOCOL_TCP => report.sent_tcp += 1,
        PROTOCOL_UDP => report.sent_udp += 1,
        _ => {}
    }
    if !report.destinations.contains(&destination) {
        report.destinations.push(destination);
    }
    let ports = matches!(protocol, PROTOCOL_TCP | PROTOCOL_UDP)
        .then(|| packet.get(header_len..header_len + 4))
        .flatten()
        .map(|bytes| {
            (
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            )
        });
    let mut violation = |reason| {
        report.violations.push(Violation {
            source,
            destination,
            ttl,
            protocol,
            ports,
            reason,
        });
    };
    if !stays_local(destination) {
        violation("the destination is not on the local link");
    } else if protocol == PROTOCOL_TCP && ttl != 1 {
        violation("a TCP packet with a hop limit other than 1");
    }
}

/// Reads a pcapng capture and checks every IPv4 packet sent from one of the
/// `local` addresses.
pub fn analyse(capture: &[u8], local: &[Ipv4Addr]) -> Result<CaptureReport, CaptureError> {
    let mut report = CaptureReport::default();
    let mut reader = Reader {
        bytes: capture,
        big_endian: false,
    };
    // The link type of each interface of the current section, in order.
    let mut link_types: Vec<u16> = Vec::new();
    let mut offset = 0;
    let mut seen_section = false;

    while offset < capture.len() {
        let malformed = CaptureError::Malformed("a block is cut off");
        let mut block_type = reader.u32(offset).ok_or(malformed.clone())?;
        if block_type == BLOCK_SECTION_HEADER {
            // The byte order of a section is declared inside its header.
            let magic: [u8; 4] = capture
                .get(offset + 8..offset + 12)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(malformed.clone())?;
            reader.big_endian = match (u32::from_le_bytes(magic), u32::from_be_bytes(magic)) {
                (BYTE_ORDER_MAGIC, _) => false,
                (_, BYTE_ORDER_MAGIC) => true,
                _ => return Err(CaptureError::Malformed("unknown byte order")),
            };
            link_types.clear();
            seen_section = true;
            block_type = BLOCK_SECTION_HEADER;
        } else if !seen_section {
            return Err(CaptureError::Malformed(
                "it does not start with a section header",
            ));
        }
        let length = reader.u32(offset + 4).ok_or(malformed.clone())? as usize;
        if length < 12 || !length.is_multiple_of(4) || offset + length > capture.len() {
            return Err(CaptureError::Malformed("a block has an impossible length"));
        }
        let body = offset + 8;

        match block_type {
            BLOCK_INTERFACE => link_types.push(reader.u16(body).ok_or(malformed)?),
            BLOCK_ENHANCED_PACKET => {
                let interface = reader.u32(body).ok_or(malformed.clone())? as usize;
                let captured = reader.u32(body + 12).ok_or(malformed.clone())? as usize;
                let frame = capture
                    .get(body + 20..body + 20 + captured)
                    .ok_or(malformed)?;
                report.packets += 1;
                let link_type = link_types
                    .get(interface)
                    .copied()
                    .unwrap_or(LINKTYPE_ETHERNET);
                if let Some(packet) = ipv4_of(frame, link_type) {
                    inspect(packet, local, &mut report);
                }
            }
            _ => {}
        }
        offset += length;
    }
    if !seen_section {
        return Err(CaptureError::Malformed("the file is empty"));
    }
    report.destinations.sort();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HERE: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 10);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 20);
    const MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
    const FAR: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
        let padded = body.len().div_ceil(4) * 4;
        let length = (padded + 12) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&block_type.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(body);
        bytes.resize(8 + padded, 0);
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes
    }

    fn header() -> Vec<u8> {
        header_with(LINKTYPE_ETHERNET)
    }

    fn header_with(link_type: u16) -> Vec<u8> {
        let mut section = Vec::new();
        section.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        section.extend_from_slice(&[1, 0, 0, 0]); // version 1.0
        section.extend_from_slice(&u64::MAX.to_le_bytes()); // section length unknown
        let mut interface = Vec::new();
        interface.extend_from_slice(&link_type.to_le_bytes());
        interface.extend_from_slice(&[0, 0]);
        interface.extend_from_slice(&96u32.to_le_bytes());
        let mut bytes = block(BLOCK_SECTION_HEADER, &section);
        bytes.extend(block(BLOCK_INTERFACE, &interface));
        bytes
    }

    fn ip(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, ttl: u8) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0, 0, ttl, protocol, 0, 0];
        ip.extend_from_slice(&source.octets());
        ip.extend_from_slice(&destination.octets());
        ip.extend_from_slice(&47000u16.to_be_bytes());
        ip.extend_from_slice(&51000u16.to_be_bytes());
        ip.extend_from_slice(&[0; 16]);
        ip
    }

    fn captured(frame: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // interface
        body.extend_from_slice(&[0; 8]); // timestamp
        body.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        body.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        body.extend_from_slice(frame);
        block(BLOCK_ENHANCED_PACKET, &body)
    }

    fn packet(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, ttl: u8) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend(ip(source, destination, protocol, ttl));
        captured(&frame)
    }

    /// An 802.11 data frame with the given frame control bytes, carrying `ip`
    /// (or an IPv6 packet if `ip` is `None`).
    fn wifi_frame(control: [u8; 2], ip: Option<Vec<u8>>) -> Vec<u8> {
        let mut frame = control.to_vec();
        frame.extend_from_slice(&[0, 0]); // duration
        frame.extend_from_slice(&[0x0a; 18]); // three addresses
        frame.extend_from_slice(&[0, 0]); // sequence control
        if control[1] & 0b11 == 0b11 {
            frame.extend_from_slice(&[0x0b; 6]); // fourth address
        }
        if control[0] & 0x80 != 0 {
            frame.extend_from_slice(&[0, 0]); // QoS control
            if control[1] & 0x80 != 0 {
                frame.extend_from_slice(&[0; 4]); // HT control
            }
        }
        frame.extend_from_slice(&LLC_SNAP);
        match ip {
            Some(ip) => {
                frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                frame.extend(ip);
            }
            None => {
                frame.extend_from_slice(&0x86DDu16.to_be_bytes());
                frame.extend_from_slice(&[0x60; 40]);
            }
        }
        frame
    }

    #[test]
    fn local_traffic_with_hop_limit_one_passes() {
        let mut capture = header();
        capture.extend(packet(HERE, PEER, PROTOCOL_TCP, 1));
        capture.extend(packet(HERE, MDNS, PROTOCOL_UDP, 1));
        // mDNS replies from other software may use another hop limit.
        capture.extend(packet(HERE, MDNS, PROTOCOL_UDP, 255));
        // What others send is not this machine's doing.
        capture.extend(packet(PEER, HERE, PROTOCOL_TCP, 64));
        capture.extend(packet(FAR, HERE, PROTOCOL_TCP, 50));

        let report = analyse(&capture, &[HERE]).unwrap();
        assert_eq!(report.packets, 5);
        assert_eq!((report.sent, report.sent_tcp, report.sent_udp), (3, 1, 2));
        assert_eq!(report.destinations, [PEER, MDNS]);
        assert_eq!(report.violations, []);
    }

    #[test]
    fn anything_leaving_the_link_is_reported() {
        let mut capture = header();
        capture.extend(packet(HERE, FAR, PROTOCOL_TCP, 1));
        capture.extend(packet(HERE, FAR, PROTOCOL_UDP, 64));
        capture.extend(packet(HERE, PEER, PROTOCOL_TCP, 64));

        let report = analyse(&capture, &[HERE]).unwrap();
        assert_eq!(report.violations.len(), 3);
        assert_eq!(report.violations[0].destination, FAR);
        assert_eq!(report.violations[0].ports, Some((47000, 51000)));
        assert!(
            report.violations[0]
                .reason
                .contains("not on the local link")
        );
        assert!(
            report.violations[1]
                .reason
                .contains("not on the local link")
        );
        assert_eq!(report.violations[2].ttl, 64);
        assert!(report.violations[2].reason.contains("hop limit"));
    }

    #[test]
    fn other_blocks_vlan_tags_and_non_ip_frames_are_skipped() {
        let mut capture = header();
        capture.extend(block(5, &[1, 2, 3, 4, 5])); // an interface statistics block
        // An ARP frame.
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0; 28]);
        let mut body = vec![0u8; 12];
        body.extend_from_slice(&(arp.len() as u32).to_le_bytes());
        body.extend_from_slice(&(arp.len() as u32).to_le_bytes());
        body.extend(arp);
        capture.extend(block(BLOCK_ENHANCED_PACKET, &body));
        capture.extend(packet(HERE, PEER, PROTOCOL_TCP, 1));

        let report = analyse(&capture, &[HERE]).unwrap();
        assert_eq!((report.packets, report.sent), (2, 1));
        assert!(report.violations.is_empty());
    }

    #[test]
    fn wifi_frames_are_read_even_when_labelled_ethernet() {
        // Frame control: data to the access point (as Packet Monitor recorded
        // mDNS), QoS data to it (unicast), QoS data with HT control, data
        // between access points, and data from the access point.
        let frames = [
            wifi_frame([0x08, 0x01], Some(ip(HERE, MDNS, PROTOCOL_UDP, 255))),
            wifi_frame([0x88, 0x01], Some(ip(HERE, PEER, PROTOCOL_TCP, 1))),
            wifi_frame([0x88, 0x81], Some(ip(HERE, FAR, PROTOCOL_TCP, 1))),
            wifi_frame([0x08, 0x03], Some(ip(HERE, PEER, PROTOCOL_TCP, 64))),
            wifi_frame([0x88, 0x02], Some(ip(PEER, HERE, PROTOCOL_TCP, 64))),
            // Not counted: IPv6, a protected frame, a management frame.
            wifi_frame([0x88, 0x01], None),
            wifi_frame([0x88, 0x41], Some(ip(HERE, FAR, PROTOCOL_TCP, 1))),
            wifi_frame([0x80, 0x00], Some(ip(HERE, FAR, PROTOCOL_TCP, 1))),
        ];
        for link_type in [LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11] {
            let mut capture = header_with(link_type);
            for frame in &frames {
                capture.extend(captured(frame));
            }
            let report = analyse(&capture, &[HERE]).unwrap();
            assert_eq!(report.packets, 8);
            assert_eq!((report.sent, report.sent_tcp, report.sent_udp), (4, 3, 1));
            assert_eq!(report.destinations, [FAR, PEER, MDNS]);
            let reasons: Vec<_> = report.violations.iter().map(|v| v.reason).collect();
            assert_eq!(reasons.len(), 2);
            assert!(reasons[0].contains("not on the local link"));
            assert!(reasons[1].contains("hop limit"));
        }
        // Ethernet frames in an 802.11 capture are not misread.
        let mut capture = header_with(LINKTYPE_IEEE802_11);
        capture.extend(packet(HERE, FAR, PROTOCOL_TCP, 1));
        assert_eq!(analyse(&capture, &[HERE]).unwrap().sent, 0);
    }

    #[test]
    fn files_that_are_not_captures_are_refused() {
        assert!(analyse(b"", &[HERE]).is_err());
        assert!(analyse(b"this is not a capture file at all", &[HERE]).is_err());
        let mut cut = header();
        cut.extend(packet(HERE, PEER, PROTOCOL_TCP, 1));
        cut.truncate(cut.len() - 6);
        assert!(analyse(&cut, &[HERE]).is_err());
    }
}
