//! Links: reliable, ordered byte streams between two devices, and the
//! [`Connection`] the protocol drivers run on.
//!
//! A link knows nothing about encryption; the Noise channel runs on top of it.
//! A [`Connection`] reads the link on a background thread, so the driver can
//! keep writing while the peer is writing too (neither side can block the
//! other by filling a buffer).

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use crate::DriveError;

/// How often a blocked reader wakes up to see whether its connection was dropped.
pub const READ_POLL: Duration = Duration::from_millis(200);

/// A byte stream to one peer.
pub trait Link: Send {
    /// Splits the link into its reading and writing halves.
    ///
    /// The reader must return from `read` at least every [`READ_POLL`] with
    /// `TimedOut` or `WouldBlock` when nothing arrives, so that the reading
    /// thread can notice that the connection was dropped.
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)>;

    /// A short description of the far end, for logs ("192.168.1.20:47000").
    fn peer(&self) -> String;
}

/// An in-memory link, for tests and the loopback transport.
#[derive(Debug)]
pub struct MemoryLink {
    reader: ChannelReader,
    writer: MemoryWriter,
    peer: String,
}

/// Reads, as one byte stream, the chunks delivered through a channel. For links
/// whose bytes arrive by callback or from another thread.
#[derive(Debug)]
pub struct ChannelReader {
    incoming: Receiver<Vec<u8>>,
    pending: Vec<u8>,
}

#[derive(Debug)]
struct MemoryWriter {
    outgoing: Sender<Vec<u8>>,
}

impl MemoryLink {
    /// Two connected links: what one writes, the other reads.
    pub fn pair() -> (Self, Self) {
        let (to_b, from_a) = mpsc::channel();
        let (to_a, from_b) = mpsc::channel();
        let link = |incoming, outgoing, peer: &str| Self {
            reader: ChannelReader::new(incoming),
            writer: MemoryWriter { outgoing },
            peer: peer.to_owned(),
        };
        (
            link(from_b, to_b, "memory:b"),
            link(from_a, to_a, "memory:a"),
        )
    }
}

impl ChannelReader {
    /// A reader over byte chunks delivered through a channel; the stream ends when
    /// the sending side is dropped.
    pub fn new(incoming: Receiver<Vec<u8>>) -> Self {
        Self {
            incoming,
            pending: Vec::new(),
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            match self.incoming.recv_timeout(READ_POLL) {
                Ok(bytes) => self.pending = bytes,
                Err(RecvTimeoutError::Timeout) => return Err(io::ErrorKind::TimedOut.into()),
                // The other end was dropped: end of stream.
                Err(RecvTimeoutError::Disconnected) => return Ok(0),
            }
        }
        let count = buffer.len().min(self.pending.len());
        buffer[..count].copy_from_slice(&self.pending[..count]);
        self.pending.drain(..count);
        Ok(count)
    }
}

impl Write for MemoryWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.outgoing
            .send(bytes.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Link for MemoryLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        Ok((Box::new(self.reader), Box::new(self.writer)))
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// A link being driven: incoming bytes are collected by a reader thread.
pub struct Connection {
    incoming: Receiver<io::Result<Vec<u8>>>,
    writer: Box<dyn Write + Send>,
    idle_timeout: Duration,
    /// Tells the reader thread to stop.
    closed: Arc<AtomicBool>,
    peer: String,
}

impl Connection {
    /// Starts driving `link`. An operation fails with [`DriveError::Timeout`]
    /// if the peer stays silent for `idle_timeout`.
    pub fn open(link: Box<dyn Link>, idle_timeout: Duration) -> Result<Self, DriveError> {
        let peer = link.peer();
        let (mut reader, writer) = link.split()?;
        let (sender, incoming) = mpsc::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&closed);

        std::thread::Builder::new()
            .name("zp-link-reader".into())
            .spawn(move || {
                let mut buffer = vec![0u8; 64 * 1024];
                while !stop.load(Ordering::Relaxed) {
                    let message = match reader.read(&mut buffer) {
                        Ok(count) => Ok(buffer[..count].to_vec()),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::TimedOut
                                    | io::ErrorKind::WouldBlock
                                    | io::ErrorKind::Interrupted
                            ) =>
                        {
                            continue;
                        }
                        Err(error) => Err(error),
                    };
                    // An empty read is the end of the stream; an error ends it too.
                    let last = !matches!(&message, Ok(bytes) if !bytes.is_empty());
                    if sender.send(message).is_err() || last {
                        break;
                    }
                }
            })?;

        Ok(Self {
            incoming,
            writer,
            idle_timeout,
            closed,
            peer,
        })
    }

    /// The far end, for logs.
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Writes `bytes` to the peer.
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), DriveError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// How long the peer may stay silent.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Waits for the next bytes from the peer, failing with
    /// [`DriveError::Timeout`] after the idle timeout.
    pub fn receive(&mut self) -> Result<Vec<u8>, DriveError> {
        self.receive_within(self.idle_timeout)?
            .ok_or(DriveError::Timeout)
    }

    /// Waits at most `wait` for the next bytes from the peer: `None` if nothing
    /// arrived in that time. The caller keeps track of the idle timeout.
    pub fn receive_within(&mut self, wait: Duration) -> Result<Option<Vec<u8>>, DriveError> {
        match self.incoming.recv_timeout(wait) {
            Ok(Ok(bytes)) if bytes.is_empty() => Err(DriveError::Closed),
            Ok(Ok(bytes)) => Ok(Some(bytes)),
            Ok(Err(error)) => Err(error.into()),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(DriveError::Closed),
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Connection({})", self.peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connections(idle: Duration) -> (Connection, Connection) {
        let (a, b) = MemoryLink::pair();
        (
            Connection::open(Box::new(a), idle).unwrap(),
            Connection::open(Box::new(b), idle).unwrap(),
        )
    }

    #[test]
    fn bytes_flow_both_ways_in_order() {
        let (mut a, mut b) = connections(Duration::from_secs(5));
        a.send(b"hello ").unwrap();
        a.send(b"world").unwrap();
        b.send(b"!").unwrap();

        let mut received = Vec::new();
        while received.len() < 11 {
            received.extend(b.receive().unwrap());
        }
        assert_eq!(received, b"hello world");
        assert_eq!(a.receive().unwrap(), b"!");
        assert_eq!(a.peer(), "memory:b");
    }

    #[test]
    fn both_sides_can_write_a_lot_before_either_reads() {
        // Neither side reads until it has written everything: this must not
        // deadlock, however much is in flight.
        let (mut a, mut b) = connections(Duration::from_secs(5));
        let chunk = vec![0x5A; 64 * 1024];
        for _ in 0..64 {
            a.send(&chunk).unwrap();
            b.send(&chunk).unwrap();
        }
        for connection in [&mut a, &mut b] {
            let mut total = 0;
            while total < 64 * chunk.len() {
                total += connection.receive().unwrap().len();
            }
            assert_eq!(total, 64 * chunk.len());
        }
    }

    #[test]
    fn a_silent_peer_times_out() {
        let (mut a, _b) = connections(Duration::from_millis(100));
        assert!(matches!(a.receive(), Err(DriveError::Timeout)));
    }

    #[test]
    fn a_dropped_peer_is_reported_as_closed() {
        let (mut a, b) = connections(Duration::from_secs(5));
        drop(b);
        assert!(matches!(a.receive(), Err(DriveError::Closed)));
        // Writing to a peer that is gone fails as well (possibly not at once).
        let failed = (0..50).any(|_| {
            std::thread::sleep(Duration::from_millis(20));
            a.send(b"x").is_err()
        });
        assert!(failed);
    }
}
