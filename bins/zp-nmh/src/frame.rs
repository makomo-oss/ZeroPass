//! Native Messaging framing: a 4-byte length in this machine's byte order,
//! then that many bytes of UTF-8 JSON.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

/// The longest message accepted from the browser. Requests are small; a
/// longer one is not from the extension.
pub(crate) const MAX_INCOMING: usize = 64 * 1024;

/// The longest message the browser accepts from a host (Chrome: 1 MiB).
pub(crate) const MAX_OUTGOING: usize = 1024 * 1024;

/// Reads one message; `None` when the browser has closed the stream.
pub(crate) fn read(input: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut length = [0u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_INCOMING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a message of {length} bytes is longer than {MAX_INCOMING}"),
        ));
    }
    let mut body = Zeroizing::new(vec![0u8; length]);
    input.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Writes one message.
pub(crate) fn write(output: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_OUTGOING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "an answer is longer than the browser accepts",
        ));
    }
    let length = u32::try_from(body.len()).map_err(io::Error::other)?;
    output.write_all(&length.to_ne_bytes())?;
    output.write_all(body)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let mut stream = Vec::new();
        write(&mut stream, br#"{"id":1}"#).unwrap();
        write(&mut stream, b"{}").unwrap();
        let mut reader = &stream[..];
        assert_eq!(&**read(&mut reader).unwrap().unwrap(), br#"{"id":1}"#);
        assert_eq!(&**read(&mut reader).unwrap().unwrap(), b"{}");
        assert!(read(&mut reader).unwrap().is_none());
    }

    #[test]
    fn overlong_and_truncated_messages_are_refused() {
        let mut stream = ((MAX_INCOMING + 1) as u32).to_ne_bytes().to_vec();
        stream.extend(vec![b' '; 16]);
        assert!(read(&mut &stream[..]).is_err());
        let truncated = [8u32.to_ne_bytes().as_slice(), b"{}"].concat();
        assert!(read(&mut &truncated[..]).is_err());
        assert!(write(&mut Vec::new(), &vec![b' '; MAX_OUTGOING + 1]).is_err());
    }
}
