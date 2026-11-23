//! The image host of a vault kept in memory (`docs/spec/ipc.md` §14.2): the
//! app process that stores the vault file for the vault process of the
//! Android app, which may not open files (ADR-0012).
//!
//! The host connects like any client and keeps a relay open. It first sends
//! the image it has stored; afterwards, every new image goes down the relay
//! and the host says when it is on disk.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use zp_ipc::RelayEnd;
use zp_ipc::proto::{self, ErrorCode, IMAGE_CHUNK, request, response};

use crate::service::{Revision, Service};

/// How long the host has to write an image to disk.
const STORE_TIMEOUT: Duration = Duration::from_secs(60);

/// The longest image accepted from the host: SQLite's own limit for a
/// database in memory is far above what a vault of a phone reaches.
const MAX_IMAGE: usize = 1 << 30;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn internal(message: impl Into<String>) -> proto::Error {
    proto::Error::new(ErrorCode::Internal, message)
}

/// One attached host.
struct Attached {
    generation: u64,
    to_host: Mutex<Sender<response::Body>>,
    stored: Mutex<Receiver<proto::ImageStored>>,
    /// What the host has on disk.
    saved: Mutex<Option<Revision>>,
}

/// The image host that is attached at the moment, if any.
#[derive(Default)]
pub(crate) struct ImageHost {
    attached: Mutex<Option<Arc<Attached>>>,
    generations: AtomicU64,
    /// One store at a time, so that images reach the disk in order.
    storing: Mutex<()>,
}

impl ImageHost {
    /// Whether a host is attached, and so the vault (or that there is none)
    /// is known.
    pub(crate) fn is_attached(&self) -> bool {
        lock(&self.attached).is_some()
    }

    /// Uses the host at the other end of `relay` until it goes away: opens the
    /// image it sends in `service`, then stores what changes. A newer host
    /// replaces an older one. When the host goes away, the vault is closed
    /// and every key wiped.
    pub(crate) fn attach(&self, relay: RelayEnd, service: &Service) -> response::Body {
        let RelayEnd { incoming, outgoing } = relay;
        let mut image = Vec::new();
        let loaded = loop {
            match incoming.recv() {
                Ok(request::Body::ImageChunk(chunk)) => {
                    if image.len() + chunk.data.len() > MAX_IMAGE {
                        break Err(internal("the stored vault file is too large"));
                    }
                    image.extend_from_slice(&chunk.data);
                    if chunk.last {
                        break service.load_image(&image).and_then(|()| service.revision());
                    }
                }
                Ok(_) => {}
                Err(_) => break Err(internal("the image host left before the image was sent")),
            }
        };
        drop(image);
        let saved = match loaded {
            Ok(saved) => saved,
            Err(error) => return response::Body::Error(error),
        };

        let generation = self.generations.fetch_add(1, Ordering::SeqCst) + 1;
        let (stored_tx, stored_rx) = mpsc::channel();
        *lock(&self.attached) = Some(Arc::new(Attached {
            generation,
            to_host: Mutex::new(outgoing.clone()),
            stored: Mutex::new(stored_rx),
            saved: Mutex::new(saved),
        }));
        if outgoing
            .send(response::Body::Listening(proto::Listening {}))
            .is_ok()
        {
            for message in incoming {
                if let request::Body::ImageStored(stored) = message
                    && stored_tx.send(stored).is_err()
                {
                    break;
                }
            }
        }
        let mut attached = lock(&self.attached);
        if attached
            .as_ref()
            .is_some_and(|host| host.generation == generation)
        {
            *attached = None;
            // Nobody stores what changes any more: close the vault.
            service.reset();
        }
        response::Body::Done(proto::Done {})
    }

    /// Has the host store the vault if it changed since the host last stored
    /// it. Returns once the image is on disk.
    pub(crate) fn store(&self, service: &Service) -> Result<(), proto::Error> {
        let _in_order = lock(&self.storing);
        let Some(host) = lock(&self.attached).clone() else {
            return Err(proto::Error::new(
                ErrorCode::NotReady,
                "nothing stores the vault: attach an image host",
            ));
        };
        let Some((revision, image)) = service.image_if_changed(*lock(&host.saved))? else {
            return Ok(());
        };
        let gone = || internal("the image host went away; the change is not stored");
        {
            let to_host = lock(&host.to_host);
            let mut chunks = image.chunks(IMAGE_CHUNK).peekable();
            while let Some(data) = chunks.next() {
                let chunk = proto::ImageChunk {
                    data: data.to_vec(),
                    last: chunks.peek().is_none(),
                };
                to_host
                    .send(response::Body::ImageChunk(chunk))
                    .map_err(|_| gone())?;
            }
        }
        drop(image);
        let stored = match lock(&host.stored).recv_timeout(STORE_TIMEOUT) {
            Ok(stored) => stored,
            Err(RecvTimeoutError::Timeout) => {
                return Err(internal("the app did not store the vault in time"));
            }
            Err(RecvTimeoutError::Disconnected) => return Err(gone()),
        };
        if !stored.error.is_empty() {
            return Err(internal(format!(
                "the app could not store the vault: {}",
                stored.error
            )));
        }
        *lock(&host.saved) = Some(revision);
        Ok(())
    }
}
