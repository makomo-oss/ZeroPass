//! Telling a pairing from a sync on a link a peer opened.
//!
//! A device takes both on the same listener (the same TCP port, the same
//! Bluetooth LE service). The first frame of the handshake says which one the
//! peer started ([`Opening`]); reading its 2-byte length is enough, and those
//! two bytes are handed back with the link.

use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};

use zp_pairing::Opening;

use crate::link::Link;

/// A link whose first bytes were already read; they come first again.
struct Replayed {
    prefix: Vec<u8>,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    peer: String,
}

impl Link for Replayed {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let reader = Cursor::new(self.prefix).chain(self.reader);
        Ok((Box::new(reader), self.writer))
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// Reads the beginning of the first handshake message on `link`, which a peer
/// opened, and tells which handshake it starts: `None` for neither. Waits at
/// most `wait` for it, and fails if the link ends first.
///
/// The returned link yields the bytes that were read before anything else, so
/// the handshake can run on it as if nothing had been read.
pub fn read_opening(
    link: Box<dyn Link>,
    wait: Duration,
) -> io::Result<(Option<Opening>, Box<dyn Link>)> {
    let peer = link.peer();
    let (mut reader, writer) = link.split()?;
    let mut prefix = [0u8; 2];
    let mut filled = 0;
    let deadline = Instant::now() + wait;
    while filled < prefix.len() {
        match reader.read(&mut prefix[filled..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => filled += count,
            // Links wake their reader up regularly when nothing arrives.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
            Err(error) => return Err(error),
        }
    }
    let opening = Opening::from_first_message_len(usize::from(u16::from_be_bytes(prefix)));
    let replayed = Replayed {
        prefix: prefix.to_vec(),
        reader,
        writer,
        peer,
    };
    Ok((opening, Box::new(replayed)))
}

#[cfg(test)]
mod tests {
    use zp_crypto::{ChannelKey, VaultId};
    use zp_pairing::Handshake;
    use zp_pairing::noise::PSK_LEN;

    use super::*;
    use crate::link::MemoryLink;

    /// Sends `first` from one end of a fresh link and classifies the other end.
    fn classify(first: &[u8]) -> (Option<Opening>, Vec<u8>) {
        let (near, far) = MemoryLink::pair();
        let (_, mut writer) = Box::new(near).split().unwrap();
        writer.write_all(first).unwrap();
        writer.write_all(b"and more").unwrap();
        let (opening, link) = read_opening(Box::new(far), Duration::from_secs(5)).unwrap();
        // Everything that was sent comes out of the returned link, in order.
        let (mut reader, _) = link.split().unwrap();
        let mut received = Vec::new();
        let mut buffer = [0u8; 256];
        while received.len() < first.len() + 8 {
            match reader.read(&mut buffer) {
                Ok(count) => received.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(error) => panic!("{error}"),
            }
        }
        (opening, received)
    }

    #[test]
    fn a_pairing_and_a_sync_are_told_apart_and_nothing_is_lost() {
        let (a, b) = (
            ChannelKey::generate().unwrap(),
            ChannelKey::generate().unwrap(),
        );
        let pairing = Handshake::pairing(true, &a, &[3; PSK_LEN])
            .unwrap()
            .step(&[])
            .unwrap();
        let sync = Handshake::sync_initiator(&a, b.public_bytes(), &VaultId::from_bytes([9; 16]))
            .unwrap()
            .step(&[])
            .unwrap();
        for (first, expected) in [
            (pairing, Some(Opening::Pairing)),
            (sync, Some(Opening::Sync)),
            (vec![0, 5, 1, 2, 3, 4, 5], None),
        ] {
            let (opening, received) = classify(&first);
            assert_eq!(opening, expected);
            let mut sent = first.clone();
            sent.extend_from_slice(b"and more");
            assert_eq!(received, sent);
        }
    }

    #[test]
    fn a_silent_or_closed_link_is_an_error() {
        let (near, far) = MemoryLink::pair();
        let started = Instant::now();
        let silent = read_opening(Box::new(far), Duration::from_millis(300));
        assert_eq!(silent.err().unwrap().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(300));
        drop(near);

        let (near, far) = MemoryLink::pair();
        drop(near);
        let closed = read_opening(Box::new(far), Duration::from_secs(5));
        assert_eq!(closed.err().unwrap().kind(), io::ErrorKind::UnexpectedEof);
    }
}
