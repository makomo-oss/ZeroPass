//! Message framing on a byte stream (`docs/spec/sync.md` §7):
//!
//! ```text
//! frame = length(4, big-endian) ‖ message
//! ```
//!
//! The secure channel delivers an ordered stream of bytes; this turns it back
//! into messages. A length above [`MAX_MESSAGE_LEN`] is refused before anything
//! is buffered for it.

use crate::SyncError;
use crate::wire::MAX_MESSAGE_LEN;

const LENGTH_PREFIX: usize = 4;

/// Prefixes `message` with its length.
pub fn encode_frame(message: &[u8]) -> Result<Vec<u8>, SyncError> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(SyncError::MessageTooLarge);
    }
    let mut frame = Vec::with_capacity(LENGTH_PREFIX + message.len());
    // The limit above keeps the length well within 32 bits.
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}

/// Reassembles messages from a byte stream delivered in arbitrary pieces.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// A decoder with nothing buffered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes received from the channel.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Takes the next complete message, if one has arrived.
    ///
    /// After an error the stream is unusable: the caller must close the channel.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>, SyncError> {
        let Some(prefix) = self.buffer.first_chunk::<LENGTH_PREFIX>() else {
            return Ok(None);
        };
        let length = u32::from_be_bytes(*prefix) as usize;
        if length > MAX_MESSAGE_LEN {
            return Err(SyncError::MessageTooLarge);
        }
        if self.buffer.len() < LENGTH_PREFIX + length {
            return Ok(None);
        }
        let message = self.buffer[LENGTH_PREFIX..LENGTH_PREFIX + length].to_vec();
        self.buffer.drain(..LENGTH_PREFIX + length);
        Ok(Some(message))
    }

    /// Whether bytes of an incomplete message are waiting. A channel that closes
    /// in this state was cut off mid-message.
    pub fn has_partial(&self) -> bool {
        !self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn messages_survive_any_fragmentation() {
        let messages: [&[u8]; 4] = [b"", b"a", b"hello world", &[0xAB; 1000]];
        let stream: Vec<u8> = messages
            .iter()
            .flat_map(|message| encode_frame(message).unwrap())
            .collect();

        for chunk_len in [1, 2, 3, 5, 7, 64, stream.len()] {
            let mut decoder = FrameDecoder::new();
            let mut decoded = Vec::new();
            for chunk in stream.chunks(chunk_len) {
                decoder.push(chunk);
                while let Some(message) = decoder.next_message().unwrap() {
                    decoded.push(message);
                }
            }
            assert_eq!(decoded, messages);
            assert!(!decoder.has_partial());
        }
    }

    #[test]
    fn incomplete_frames_wait_for_more_bytes() {
        let frame = encode_frame(b"hello").unwrap();
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.next_message().unwrap(), None);
        decoder.push(&frame[..3]);
        assert_eq!(decoder.next_message().unwrap(), None);
        decoder.push(&frame[3..8]);
        assert_eq!(decoder.next_message().unwrap(), None);
        assert!(decoder.has_partial());
        decoder.push(&frame[8..]);
        assert_eq!(
            decoder.next_message().unwrap().as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(decoder.next_message().unwrap(), None);
    }

    #[test]
    fn oversized_frames_are_refused_before_buffering() {
        assert_eq!(
            encode_frame(&vec![0; MAX_MESSAGE_LEN + 1]),
            Err(SyncError::MessageTooLarge)
        );
        assert!(encode_frame(&vec![0; MAX_MESSAGE_LEN]).is_ok());

        let mut decoder = FrameDecoder::new();
        // Only the length prefix is needed to refuse a 4 GiB "message".
        decoder.push(&u32::MAX.to_be_bytes());
        assert_eq!(decoder.next_message(), Err(SyncError::MessageTooLarge));
        let mut decoder = FrameDecoder::new();
        decoder.push(&(MAX_MESSAGE_LEN as u32 + 1).to_be_bytes());
        assert_eq!(decoder.next_message(), Err(SyncError::MessageTooLarge));
    }

    proptest! {
        #[test]
        fn decoding_inverts_encoding(
            messages in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 0..12),
            cuts in proptest::collection::vec(1usize..50, 1..40),
        ) {
            let stream: Vec<u8> =
                messages.iter().flat_map(|message| encode_frame(message).unwrap()).collect();
            let mut decoder = FrameDecoder::new();
            let mut decoded = Vec::new();
            let mut offset = 0;
            let mut cut = cuts.iter().cycle();
            while offset < stream.len() {
                let end = (offset + cut.next().unwrap()).min(stream.len());
                decoder.push(&stream[offset..end]);
                offset = end;
                while let Some(message) = decoder.next_message().unwrap() {
                    decoded.push(message);
                }
            }
            prop_assert_eq!(decoded, messages);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut decoder = FrameDecoder::new();
            decoder.push(&bytes);
            while let Ok(Some(_)) = decoder.next_message() {}
        }
    }
}
