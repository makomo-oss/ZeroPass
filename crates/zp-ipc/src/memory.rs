//! A connected pair of byte streams in memory: a client and a daemon in the
//! same process, as in the tests of an embedded daemon (`docs/spec/ipc.md`
//! §14), on platforms without socket pairs.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// The bytes going one way.
#[derive(Default)]
struct Pipe {
    state: Mutex<PipeState>,
    changed: Condvar,
}

#[derive(Default)]
struct PipeState {
    bytes: VecDeque<u8>,
    closed: bool,
}

impl Pipe {
    fn state(&self) -> MutexGuard<'_, PipeState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn close(&self) {
        self.state().closed = true;
        self.changed.notify_all();
    }
}

/// One end of a connected pair of byte streams in memory ([`memory_pair`]).
/// What is written to one end is read from the other. Dropping an end closes
/// the pair: the other end reads the end of the stream and cannot write.
pub struct MemoryStream {
    incoming: Arc<Pipe>,
    outgoing: Arc<Pipe>,
}

/// Two connected [`MemoryStream`]s.
pub fn memory_pair() -> (MemoryStream, MemoryStream) {
    let one_way = Arc::new(Pipe::default());
    let other_way = Arc::new(Pipe::default());
    (
        MemoryStream {
            incoming: Arc::clone(&one_way),
            outgoing: Arc::clone(&other_way),
        },
        MemoryStream {
            incoming: other_way,
            outgoing: one_way,
        },
    )
}

impl Read for MemoryStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut state = self.incoming.state();
        while state.bytes.is_empty() && !state.closed {
            state = self
                .incoming
                .changed
                .wait(state)
                .unwrap_or_else(|poison| poison.into_inner());
        }
        let count = buffer.len().min(state.bytes.len());
        for (slot, byte) in buffer.iter_mut().zip(state.bytes.drain(..count)) {
            *slot = byte;
        }
        Ok(count)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.outgoing.state();
        if state.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        state.bytes.extend(bytes);
        drop(state);
        self.outgoing.changed.notify_all();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for MemoryStream {
    fn drop(&mut self) {
        self.incoming.close();
        self.outgoing.close();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn bytes_go_both_ways_and_the_end_is_seen() {
        let (mut left, mut right) = memory_pair();
        let echo = thread::spawn(move || {
            let mut buffer = [0u8; 5];
            right.read_exact(&mut buffer).unwrap();
            right.write_all(&buffer).unwrap();
            // Reads the end once the other side is gone.
            let mut rest = Vec::new();
            right.read_to_end(&mut rest).unwrap();
            rest
        });
        left.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        left.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        left.write_all(b"!").unwrap();
        drop(left);
        assert_eq!(echo.join().unwrap(), b"!");
    }

    #[test]
    fn writing_to_a_closed_pair_fails() {
        let (mut left, right) = memory_pair();
        drop(right);
        assert_eq!(
            left.write(b"x").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut buffer = [0u8; 1];
        assert_eq!(left.read(&mut buffer).unwrap(), 0);
    }
}
