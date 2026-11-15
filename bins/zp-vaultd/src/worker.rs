//! A process behind the front (ADR-0007): takes its orders from standard
//! input and answers on standard output (`wire`).
//!
//! It ends when its input closes, that is, when the front lets go of it or
//! is gone itself.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use zp_ipc::proto::{
    self, ErrorCode, KeyStoreProblem, key_agent_reply::Outcome, key_agent_request::Ask, request,
    response,
};
use zp_ipc::{RelayEnd, read_frame, write_frame};

use crate::convert::{domain_from_proto, domain_to_proto};
use crate::port::{KeyAgentPort, failed};
use crate::service::{KeyStoreChoice, Scope, Service};
use crate::wire::{Down, ImportKey, KeyTransfer, Up, down, up};

/// How often idle domains are checked for their timeout.
const TICK: Duration = Duration::from_secs(1);

/// How long the front has to bring the key agent's answer. The front gives
/// up on the agent earlier and says so.
const AGENT_TIMEOUT: Duration = Duration::from_secs(240);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// The way up to the front.
pub(crate) struct Output<W> {
    writer: Mutex<W>,
}

impl<W: Write> Output<W> {
    fn send(&self, body: up::Body) -> io::Result<()> {
        write_frame(&mut *lock(&self.writer), &Up { body: Some(body) }).map_err(io::Error::other)
    }

    fn reply(&self, body: response::Body) -> io::Result<()> {
        self.send(up::Body::Reply(proto::Response { body: Some(body) }))
    }
}

/// Reaches the key agent through the front.
pub(crate) struct FrontPort<W> {
    output: Arc<Output<W>>,
    /// Locked for a whole question: one at a time.
    replies: Mutex<Receiver<proto::KeyAgentReply>>,
    questions: AtomicU64,
}

impl<W: Write + Send> KeyAgentPort for FrontPort<W> {
    fn ask(&self, ask: Ask) -> Outcome {
        let gone = || failed(KeyStoreProblem::Platform, "the vault daemon is stopping");
        let replies = lock(&self.replies);
        let id = self.questions.fetch_add(1, Ordering::SeqCst) + 1;
        let question = proto::KeyAgentRequest { id, ask: Some(ask) };
        if self.output.send(up::Body::AgentRequest(question)).is_err() {
            return gone();
        }
        loop {
            match replies.recv_timeout(AGENT_TIMEOUT) {
                Ok(reply) if reply.id != id => {}
                Ok(reply) => {
                    return reply.outcome.unwrap_or_else(|| {
                        failed(KeyStoreProblem::Platform, "the key agent gave no answer")
                    });
                }
                Err(RecvTimeoutError::Timeout) => {
                    return failed(
                        KeyStoreProblem::UserCancelled,
                        "the key agent did not answer in time",
                    );
                }
                Err(RecvTimeoutError::Disconnected) => return gone(),
            }
        }
    }
}

/// An order of the front, as the reading thread hands it on.
struct Order {
    body: down::Body,
    /// For a relay: what the client sends on its uplink. Opened when the
    /// order was read, so that what came right behind it is kept.
    uplink: Option<Receiver<request::Body>>,
}

/// What the reading thread hands on.
struct Inbox {
    /// Orders, one at a time.
    orders: Receiver<Order>,
    /// Where the messages of the client's uplink go while a relay runs.
    uplink: Arc<Mutex<Option<Sender<request::Body>>>>,
}

/// The two ends that connect this process to the front.
pub(crate) struct Wiring<W> {
    pub(crate) output: Arc<Output<W>>,
    pub(crate) port: Arc<FrontPort<W>>,
    inbox: Inbox,
}

/// Starts reading `input`. Orders are queued; the key agent's answers and
/// the messages of a relay go straight to who waits for them, because the
/// order that needs them is still being worked on.
pub(crate) fn connect<R, W>(mut input: R, output: W) -> Wiring<W>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let output = Arc::new(Output {
        writer: Mutex::new(output),
    });
    let (orders_tx, orders) = mpsc::channel();
    let (replies_tx, replies) = mpsc::channel();
    let uplink: Arc<Mutex<Option<Sender<request::Body>>>> = Arc::default();
    {
        let uplink = Arc::clone(&uplink);
        thread::spawn(move || {
            // Ends with the input; dropping the senders ends the rest.
            while let Ok(Some(Down { body: Some(body) })) = read_frame(&mut input) {
                match body {
                    down::Body::AgentReply(reply) => {
                        let _ = replies_tx.send(reply);
                    }
                    down::Body::RelayData(message) => {
                        if let (Some(uplink), Some(body)) = (lock(&uplink).as_ref(), message.body) {
                            let _ = uplink.send(body);
                        }
                    }
                    down::Body::RelayClosed(_) => {
                        lock(&uplink).take();
                    }
                    body => {
                        let relay = if matches!(body, down::Body::Relay(_)) {
                            let (sender, receiver) = mpsc::channel();
                            *lock(&uplink) = Some(sender);
                            Some(receiver)
                        } else {
                            None
                        };
                        let order = Order {
                            body,
                            uplink: relay,
                        };
                        if orders_tx.send(order).is_err() {
                            break;
                        }
                    }
                }
            }
            lock(&uplink).take();
        });
    }
    let port = Arc::new(FrontPort {
        output: Arc::clone(&output),
        replies: Mutex::new(replies),
        questions: AtomicU64::new(0),
    });
    Wiring {
        output,
        port,
        inbox: Inbox { orders, uplink },
    }
}

fn error(code: ErrorCode, message: &str) -> response::Body {
    response::Body::Error(proto::Error::new(code, message))
}

fn outcome(result: Result<(), proto::Error>) -> response::Body {
    match result {
        Ok(()) => response::Body::Done(proto::Done {}),
        Err(error) => response::Body::Error(error),
    }
}

/// Runs a relay: the client's messages come through `incoming`, the
/// service's go up as they are made, and the service's last word is returned
/// once everything before it is on its way.
fn relay<W: Write + Send + 'static>(
    service: &Service,
    output: &Arc<Output<W>>,
    uplink: &Mutex<Option<Sender<request::Body>>>,
    incoming: Receiver<request::Body>,
    request: &request::Body,
) -> response::Body {
    let (outgoing, to_front) = mpsc::channel::<response::Body>();
    let (finished_tx, finished) = mpsc::channel::<()>();
    let carrier = {
        let output = Arc::clone(output);
        thread::spawn(move || {
            let forward = |message: response::Body| {
                let _ = output.send(up::Body::RelayData(proto::Response {
                    body: Some(message),
                }));
            };
            loop {
                match to_front.recv_timeout(Duration::from_millis(50)) {
                    Ok(message) => forward(message),
                    Err(RecvTimeoutError::Disconnected) => return,
                    Err(RecvTimeoutError::Timeout) => {
                        // The service is done: what it sent before that is
                        // queued, what its threads send later is not waited for.
                        if !matches!(finished.try_recv(), Err(TryRecvError::Empty)) {
                            while let Ok(message) = to_front.try_recv() {
                                forward(message);
                            }
                            return;
                        }
                    }
                }
            }
        })
    };
    let last = service.relay(request, RelayEnd { incoming, outgoing });
    lock(uplink).take();
    drop(finished_tx);
    let _ = carrier.join();
    last
}

/// Works through the front's orders until the input closes.
pub(crate) fn serve<W: Write + Send + 'static>(service: &Service, wiring: Wiring<W>) {
    let Wiring { output, inbox, .. } = wiring;
    for Order { body, uplink } in inbox.orders {
        let sent = match body {
            down::Body::Call(proto::Request { body: Some(body) }) => {
                output.reply(service.serve(body))
            }
            down::Body::Relay(proto::Request { body: Some(body) }) => {
                let incoming = uplink.unwrap_or_else(|| mpsc::channel().1);
                let last = relay(service, &output, &inbox.uplink, incoming, &body);
                output.reply(last)
            }
            down::Body::Call(_) | down::Body::Relay(_) => {
                output.reply(error(ErrorCode::BadRequest, "unknown or empty request"))
            }
            down::Body::ImportKey(_) => output.send(up::Body::ImportKey(ImportKey {
                key: service.import_key().to_vec(),
            })),
            down::Body::Import(transfer) => {
                let imported = domain_from_proto(transfer.domain)
                    .and_then(|domain| service.import(domain, transfer.epoch, &transfer.sealed));
                output.reply(outcome(imported))
            }
            down::Body::Export(export) => {
                let exported = domain_from_proto(export.domain).and_then(|domain| {
                    let to = export.to.as_slice().try_into().map_err(|_| {
                        proto::Error::new(ErrorCode::BadRequest, "malformed receiving key")
                    })?;
                    let (epoch, sealed) = service.export(domain, to)?;
                    Ok(KeyTransfer {
                        domain: domain_to_proto(domain) as i32,
                        epoch,
                        sealed,
                    })
                });
                match exported {
                    Ok(transfer) => output.send(up::Body::Exported(transfer)),
                    Err(error) => output.reply(response::Body::Error(error)),
                }
            }
            down::Body::Reset(_) => {
                service.reset();
                output.reply(outcome(Ok(())))
            }
            // Handled by the reading thread.
            down::Body::AgentReply(_) | down::Body::RelayData(_) | down::Body::RelayClosed(_) => {
                Ok(())
            }
        };
        if sent.is_err() {
            break;
        }
    }
}

/// Runs one of the processes behind the front: holds what `scope` allows,
/// takes orders from `input` and answers on `output` until `input` closes.
pub(crate) fn run<R, W>(
    vault: std::path::PathBuf,
    key_store: KeyStoreChoice,
    scope: Scope,
    input: R,
    output: W,
) -> Result<(), proto::Error>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let wiring = connect(input, output);
    let service = Arc::new(Service::new(vault, key_store, scope, wiring.port.clone())?);
    {
        // Ends with the service.
        let service = Arc::downgrade(&service);
        thread::spawn(move || {
            loop {
                thread::sleep(TICK);
                match service.upgrade() {
                    Some(service) => service.tick(),
                    None => return,
                }
            }
        });
    }
    serve(&service, wiring);
    service.lock_all();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Empty;

    fn frame(body: down::Body) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &Down { body: Some(body) }).unwrap();
        bytes
    }

    /// The front sends the client's first bytes right behind the order that
    /// starts a relay: they must not be lost while the order waits its turn.
    #[test]
    fn what_follows_a_relay_order_at_once_reaches_the_relay() {
        let data = |byte: u8| {
            down::Body::RelayData(proto::Request {
                body: Some(request::Body::LinkData(proto::LinkData {
                    data: vec![byte],
                })),
            })
        };
        let mut wire = frame(down::Body::Relay(proto::Request {
            body: Some(request::Body::PairAdmit(proto::PairAdmit {})),
        }));
        wire.extend(frame(data(1)));
        wire.extend(frame(data(2)));
        wire.extend(frame(down::Body::RelayClosed(Empty {})));
        // Data without a relay goes nowhere.
        wire.extend(frame(data(3)));
        wire.extend(frame(down::Body::Reset(Empty {})));

        let wiring = connect(std::io::Cursor::new(wire), std::io::sink());
        let first = wiring.inbox.orders.recv().unwrap();
        assert!(matches!(first.body, down::Body::Relay(_)));
        let uplink = first.uplink.unwrap();
        let received: Vec<Vec<u8>> = uplink
            .iter()
            .map(|message| match message {
                request::Body::LinkData(chunk) => chunk.data,
                other => panic!("unexpected: {other:?}"),
            })
            .collect();
        assert_eq!(received, [vec![1], vec![2]]);
        let second = wiring.inbox.orders.recv().unwrap();
        assert!(matches!(second.body, down::Body::Reset(_)));
        assert!(second.uplink.is_none());
        assert!(wiring.inbox.orders.recv().is_err());
    }
}
