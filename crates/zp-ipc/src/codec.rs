//! Framing: a 4-byte little-endian length followed by one Protocol Buffers
//! message (`docs/spec/ipc.md` §2.3).

use std::io::{self, Read, Write};

use prost::Message;
use zeroize::Zeroizing;

use crate::IpcError;

/// The longest message body that is sent or accepted.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Writes one message as a frame.
pub(crate) fn write_frame<W: Write, M: Message>(
    writer: &mut W,
    message: &M,
) -> Result<(), IpcError> {
    let len = message.encoded_len();
    if len > MAX_FRAME {
        return Err(IpcError::FrameTooLarge(len));
    }
    // One buffer and one write, so that a frame is not interleaved or split
    // across pipe writes more than necessary. It may hold secrets.
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + len));
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    message
        .encode(&mut *frame)
        .map_err(|_| IpcError::Malformed)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

/// Reads one frame. Returns `None` if the other side closed the connection
/// before the start of a frame.
pub(crate) fn read_frame<R: Read, M: Message + Default>(
    reader: &mut R,
) -> Result<Option<M>, IpcError> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if filled == 0 && is_disconnect(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(IpcError::FrameTooLarge(len));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body)?;
    M::decode(body.as_slice())
        .map(Some)
        .map_err(|_| IpcError::Malformed)
}

/// Whether an I/O error means the other side went away.
fn is_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::proto::{Hello, Request, request};

    fn hello() -> Request {
        Request {
            body: Some(request::Body::Hello(Hello {
                protocol: 1,
                client: "test".into(),
            })),
        }
    }

    #[test]
    fn frames_round_trip() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &hello()).unwrap();
        write_frame(&mut wire, &Request { body: None }).unwrap();
        let mut reader = Cursor::new(wire);
        assert_eq!(
            read_frame::<_, Request>(&mut reader).unwrap(),
            Some(hello())
        );
        assert_eq!(
            read_frame::<_, Request>(&mut reader).unwrap(),
            Some(Request { body: None })
        );
        assert_eq!(read_frame::<_, Request>(&mut reader).unwrap(), None);
    }

    #[test]
    fn an_oversized_length_is_rejected_before_the_body_is_read() {
        let mut wire = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(&[0; 8]);
        let mut reader = Cursor::new(wire);
        assert!(matches!(
            read_frame::<_, Request>(&mut reader),
            Err(IpcError::FrameTooLarge(_))
        ));
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn a_truncated_frame_is_an_error() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &hello()).unwrap();
        for cut in [2, wire.len() - 1] {
            let mut reader = Cursor::new(&wire[..cut]);
            assert!(matches!(
                read_frame::<_, Request>(&mut reader),
                Err(IpcError::Io(_))
            ));
        }
    }

    #[test]
    fn garbage_is_malformed() {
        let mut wire = 3u32.to_le_bytes().to_vec();
        wire.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        assert!(matches!(
            read_frame::<_, Request>(&mut Cursor::new(wire)),
            Err(IpcError::Malformed)
        ));
    }
}
