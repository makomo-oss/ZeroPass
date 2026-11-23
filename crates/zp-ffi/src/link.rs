//! The byte stream the app moves over its radio (`docs/spec/ble.md` §5).

use std::io::{self, Read, Write};
use std::sync::Arc;

use zp_transport::Link;

/// How often a blocked reader gives the driver a chance to notice that the
/// connection was dropped.
const READ_POLL_MS: u32 = 200;

/// Why a [`ByteLink`] or [`crate::VaultConnector`] call failed.
///
/// The app raises it and Rust receives it, so it must not be a flat error:
/// UniFFI cannot bring a flat error back into Rust and aborts the process.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LinkError {
    /// The connection is gone.
    #[error("the link is closed")]
    Closed,
    /// The app's implementation threw something unexpected.
    #[error("the link failed: {reason}")]
    Unexpected {
        /// What the app reported.
        reason: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for LinkError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unexpected {
            reason: error.reason,
        }
    }
}

/// A reliable, ordered byte stream to one nearby device, implemented by the app
/// on top of its radio (`docs/spec/ble.md` §5). Only ciphertext passes through.
#[uniffi::export(with_foreign)]
pub trait ByteLink: Send + Sync {
    /// The next bytes from the other device, in order. Returns an empty array if
    /// nothing arrived within `timeout_ms`, and fails once the link is closed.
    fn read(&self, timeout_ms: u32) -> Result<Vec<u8>, LinkError>;

    /// Sends `bytes`, returning when the radio has taken them.
    fn write(&self, bytes: Vec<u8>) -> Result<(), LinkError>;
}

/// A [`ByteLink`] as the drivers of the core see a link.
pub(crate) struct AppLink(pub(crate) Arc<dyn ByteLink>);

struct AppReader {
    link: Arc<dyn ByteLink>,
    pending: Vec<u8>,
}

struct AppWriter(Arc<dyn ByteLink>);

impl Read for AppReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            match self.link.read(READ_POLL_MS) {
                Ok(bytes) if bytes.is_empty() => return Err(io::ErrorKind::TimedOut.into()),
                Ok(bytes) => self.pending = bytes,
                // End of stream.
                Err(_) => return Ok(0),
            }
        }
        let count = buffer.len().min(self.pending.len());
        buffer[..count].copy_from_slice(&self.pending[..count]);
        self.pending.drain(..count);
        Ok(count)
    }
}

impl Write for AppWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .write(bytes.to_vec())
            .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error.to_string()))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Link for AppLink {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let reader = AppReader {
            link: Arc::clone(&self.0),
            pending: Vec::new(),
        };
        Ok((Box::new(reader), Box::new(AppWriter(self.0))))
    }

    fn peer(&self) -> String {
        "app link".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use uniffi::{Lift, Lower, RustBuffer};

    use super::LinkError;

    /// What happens when the app's `ByteLink` throws: the error comes back
    /// through a buffer and has to be lifted (this aborted with a flat error).
    fn through_the_boundary(error: LinkError) -> LinkError {
        let buffer: RustBuffer =
            <LinkError as Lower<crate::UniFfiTag>>::lower_into_rust_buffer(error);
        <LinkError as Lift<crate::UniFfiTag>>::try_lift_from_rust_buffer(buffer)
            .expect("the error lifts")
    }

    #[test]
    fn errors_raised_by_the_app_can_be_lifted() {
        assert!(matches!(
            through_the_boundary(LinkError::Closed),
            LinkError::Closed
        ));
        assert!(matches!(
            through_the_boundary(LinkError::Unexpected { reason: "boom".into() }),
            LinkError::Unexpected { reason } if reason == "boom"
        ));
    }
}
