//! The daemon's side: accepts clients, checks who they are and runs the
//! request–response conversation.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use crate::codec::{read_frame, write_frame};
use crate::peer::{ClientPolicy, Peer, PeerProcess};
use crate::proto::{
    Done, Error, ErrorCode, HelloReply, PROTOCOL_VERSION, RelayOpened, Request, Response, request,
    response,
};
use crate::{Endpoint, IpcError, sys};

/// Answers the requests of admitted clients.
pub trait Handler: Send + Sync + 'static {
    /// Answers one request. `Hello` never arrives here.
    fn handle(&self, peer: &Peer, request: request::Body) -> response::Body;

    /// Called when a connection from a process that is not admitted was closed.
    fn rejected(&self, process: &PeerProcess) {
        let _ = process;
    }

    /// Whether `request` starts a relay (`docs/spec/ipc.md` §11) instead of
    /// being answered once. Such a request goes to [`Self::relay`].
    fn starts_relay(&self, request: &request::Body) -> bool {
        let _ = request;
        false
    }

    /// Runs a relay: exchanges messages with the client through `relay` for as
    /// long as it takes and returns the last message, after which the
    /// connection is closed.
    fn relay(&self, peer: &Peer, request: request::Body, relay: RelayEnd) -> response::Body {
        let _ = (peer, request, relay);
        response::Body::Error(Error::new(ErrorCode::BadRequest, "not a relay request"))
    }
}

/// The daemon's end of a relay.
///
/// A relay uses two connections, each in one direction only, so that neither
/// side can block the other: the connection the request arrived on carries the
/// daemon's messages to the client, and a second connection, which the client
/// attaches, carries the client's messages to the daemon.
pub struct RelayEnd {
    /// What the client sends. Ends when the client closes its uplink.
    pub incoming: Receiver<request::Body>,
    /// What to send to the client. May be cloned for other threads; the relay
    /// is over when every clone is dropped and the handler has returned.
    pub outgoing: Sender<response::Body>,
}

/// The relays that wait for, or have, their uplink.
#[derive(Default)]
struct Relays {
    next_id: AtomicU64,
    waiting: Mutex<HashMap<u64, Sender<request::Body>>>,
}

impl Relays {
    fn waiting(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Sender<request::Body>>> {
        self.waiting
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Registers a new relay and returns its name and where its uplink's
    /// messages will arrive.
    fn open(&self) -> (u64, Receiver<request::Body>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (sender, receiver) = mpsc::channel();
        self.waiting().insert(id, sender);
        (id, receiver)
    }

    /// Hands the uplink of relay `id` its sender; each relay has one uplink.
    fn attach(&self, id: u64) -> Option<Sender<request::Body>> {
        self.waiting().remove(&id)
    }

    /// Forgets a relay whose uplink never came.
    fn close(&self, id: u64) {
        self.waiting().remove(&id);
    }
}

/// Stops a running [`Server`] from another thread.
#[derive(Clone)]
pub struct ShutdownHandle {
    // Weak, so that a handle held by a lingering connection does not keep the
    // endpoint taken after the server is gone.
    listener: Weak<sys::Listener>,
    stop: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Makes [`Server::serve`] return. Connections that are open are not waited for.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(listener) = self.listener.upgrade() {
            listener.wake();
        }
    }
}

/// A listening endpoint.
pub struct Server {
    listener: Arc<sys::Listener>,
    policy: ClientPolicy,
    stop: Arc<AtomicBool>,
    daemon_version: String,
    relays: Arc<Relays>,
}

impl Server {
    /// Starts listening on `endpoint`. Fails with [`IpcError::AlreadyRunning`]
    /// if another process already does.
    pub fn bind(
        endpoint: &Endpoint,
        policy: ClientPolicy,
        daemon_version: impl Into<String>,
    ) -> Result<Self, IpcError> {
        Ok(Self {
            listener: Arc::new(sys::Listener::bind(endpoint)?),
            policy,
            stop: Arc::new(AtomicBool::new(false)),
            daemon_version: daemon_version.into(),
            relays: Arc::default(),
        })
    }

    /// A handle that stops the server.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            listener: Arc::downgrade(&self.listener),
            stop: Arc::clone(&self.stop),
        }
    }

    /// Serves clients, one thread per connection, until a client's `Shutdown`
    /// request is answered with `Done` or [`ShutdownHandle::shutdown`] is called.
    pub fn serve<H: Handler>(self, handler: Arc<H>) {
        let shutdown = self.shutdown_handle();
        loop {
            let accepted = self.listener.accept();
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let (stream, process) = match accepted {
                Ok(accepted) => accepted,
                Err(_) => {
                    // A client that went away while connecting, or a transient
                    // failure. Do not spin on a persistent one.
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            let Some(role) = self.policy.admit(&process) else {
                // Nothing is read from a process that is not admitted. It is
                // told why, which helps with a broken installation and tells
                // an intruder nothing it could use. Best effort, and without
                // waiting for it to read: this is the thread that accepts.
                let mut stream = stream;
                let why = match &process.executable {
                    Some(path) => format!(
                        "{} is not a ZeroPass program installed with the daemon",
                        path.display()
                    ),
                    None => "the daemon could not tell which program is connecting".to_owned(),
                };
                let _ = write_frame(&mut stream, &error(ErrorCode::Denied, &why));
                drop(stream);
                handler.rejected(&process);
                continue;
            };
            let peer = Peer { process, role };
            let handler = Arc::clone(&handler);
            let shutdown = shutdown.clone();
            let daemon_version = self.daemon_version.clone();
            let relays = Arc::clone(&self.relays);
            thread::spawn(move || {
                let mut stream = stream;
                if let Ok(Conversation::Shutdown) =
                    converse(&mut stream, &peer, &*handler, &daemon_version, &relays)
                {
                    shutdown.shutdown();
                }
            });
        }
    }
}

/// How a conversation ended.
#[derive(Debug, PartialEq, Eq)]
enum Conversation {
    /// The client closed the connection.
    Closed,
    /// The client asked the daemon to stop and the handler agreed.
    Shutdown,
}

fn error(code: ErrorCode, message: &str) -> Response {
    Response {
        body: Some(response::Body::Error(Error::new(code, message))),
    }
}

/// Runs a relay on the connection its request arrived on: this thread writes
/// what the handler sends, while the handler runs on a thread of its own and
/// reads what the client's uplink delivers. Returns the handler's last message.
fn run_relay<S: Read + Write, H: Handler + ?Sized>(
    stream: &mut S,
    peer: &Peer,
    handler: &H,
    request: request::Body,
    relays: &Relays,
) -> Result<response::Body, IpcError> {
    let (id, incoming) = relays.open();
    let opened = Response {
        body: Some(response::Body::RelayOpened(RelayOpened { relay_id: id })),
    };
    if let Err(error) = write_frame(stream, &opened) {
        relays.close(id);
        return Err(error);
    }
    let (outgoing, to_write) = mpsc::channel();
    let last = thread::scope(|scope| {
        let job =
            scope.spawn(move || handler.relay(peer, request, RelayEnd { incoming, outgoing }));
        // Ends when the handler has returned and every clone of its sender is
        // gone. After a failed write, keep draining: nobody must block on us.
        let mut failed = false;
        for message in to_write {
            if !failed {
                failed = write_frame(
                    stream,
                    &Response {
                        body: Some(message),
                    },
                )
                .is_err();
            }
        }
        job.join()
    });
    relays.close(id);
    last.map_err(|_| IpcError::Protocol("the relay ended abnormally"))
}

/// Runs the conversation with one admitted client until it ends.
fn converse<S: Read + Write, H: Handler + ?Sized>(
    stream: &mut S,
    peer: &Peer,
    handler: &H,
    daemon_version: &str,
    relays: &Relays,
) -> Result<Conversation, IpcError> {
    // The first request must be Hello.
    let Some(first) = read_frame::<_, Request>(stream)? else {
        return Ok(Conversation::Closed);
    };
    let Some(request::Body::Hello(hello)) = first.body else {
        write_frame(
            stream,
            &error(ErrorCode::BadRequest, "the first request must be Hello"),
        )?;
        return Err(IpcError::Protocol("the first request was not Hello"));
    };
    if hello.protocol != PROTOCOL_VERSION {
        write_frame(
            stream,
            &error(
                ErrorCode::UnsupportedProtocol,
                "the client and the daemon are of different versions",
            ),
        )?;
        return Err(IpcError::Protocol("unsupported protocol version"));
    }
    write_frame(
        stream,
        &Response {
            body: Some(response::Body::Hello(HelloReply {
                protocol: PROTOCOL_VERSION,
                daemon_version: daemon_version.to_owned(),
                role: peer.role as i32,
            })),
        },
    )?;

    while let Some(request) = read_frame::<_, Request>(stream)? {
        let reply = match request.body {
            None => response::Body::Error(Error::new(
                ErrorCode::BadRequest,
                "unknown or empty request",
            )),
            Some(request::Body::Hello(_)) => {
                response::Body::Error(Error::new(ErrorCode::BadRequest, "Hello was already sent"))
            }
            Some(request::Body::RelayAttach(attach)) => {
                let Some(uplink) = relays.attach(attach.relay_id) else {
                    write_frame(
                        stream,
                        &error(ErrorCode::BadRequest, "there is no such relay"),
                    )?;
                    continue;
                };
                write_frame(
                    stream,
                    &Response {
                        body: Some(response::Body::Done(Done {})),
                    },
                )?;
                // From here on the client only sends, until it closes.
                while let Some(request) = read_frame::<_, Request>(stream)? {
                    if let Some(body) = request.body
                        && uplink.send(body).is_err()
                    {
                        // The relay is over.
                        break;
                    }
                }
                return Ok(Conversation::Closed);
            }
            Some(body) if handler.starts_relay(&body) => {
                let last = run_relay(stream, peer, handler, body, relays)?;
                write_frame(stream, &Response { body: Some(last) })?;
                // A relay is the last thing on its connection.
                return Ok(Conversation::Closed);
            }
            Some(body) => {
                let stops = matches!(body, request::Body::Shutdown(_));
                let reply = handler.handle(peer, body);
                if stops && matches!(reply, response::Body::Done(_)) {
                    // Answer first, so that the client learns it worked.
                    write_frame(stream, &Response { body: Some(reply) })?;
                    return Ok(Conversation::Shutdown);
                }
                reply
            }
        };
        write_frame(stream, &Response { body: Some(reply) })?;
    }
    Ok(Conversation::Closed)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use super::*;
    use crate::proto::{Done, Hello, Role, Shutdown, Status, StatusReply};

    /// The client's requests as a byte stream, and what the server wrote back.
    struct Wire {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Wire {
        fn with(requests: &[Request]) -> Self {
            let mut input = Vec::new();
            for request in requests {
                write_frame(&mut input, request).unwrap();
            }
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }

        fn replies(&self) -> Vec<response::Body> {
            let mut reader = Cursor::new(&self.output);
            let mut replies = Vec::new();
            while let Some(reply) = read_frame::<_, Response>(&mut reader).unwrap() {
                replies.push(reply.body.unwrap());
            }
            replies
        }
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Fixed;

    impl Handler for Fixed {
        fn handle(&self, peer: &Peer, request: request::Body) -> response::Body {
            match request {
                request::Body::Status(_) => response::Body::Status(StatusReply::default()),
                request::Body::Shutdown(_) if peer.role == Role::Ui => {
                    response::Body::Done(Done {})
                }
                _ => response::Body::Error(Error::new(ErrorCode::Denied, "no")),
            }
        }
    }

    fn peer(role: Role) -> Peer {
        Peer {
            process: PeerProcess {
                pid: None,
                executable: None,
            },
            role,
        }
    }

    fn request(body: request::Body) -> Request {
        Request { body: Some(body) }
    }

    fn hello(protocol: u32) -> Request {
        request(request::Body::Hello(Hello {
            protocol,
            client: "test".into(),
        }))
    }

    fn code(reply: &response::Body) -> ErrorCode {
        match reply {
            response::Body::Error(error) => ErrorCode::try_from(error.code).unwrap(),
            other => panic!("not an error: {other:?}"),
        }
    }

    #[test]
    fn a_conversation_starts_with_hello_and_answers_each_request() {
        let mut wire = Wire::with(&[
            hello(PROTOCOL_VERSION),
            request(request::Body::Status(Status {})),
            Request { body: None },
            hello(PROTOCOL_VERSION),
        ]);
        let end = converse(
            &mut wire,
            &peer(Role::Bridge),
            &Fixed,
            "1.2.3",
            &Relays::default(),
        )
        .unwrap();
        assert_eq!(end, Conversation::Closed);
        let replies = wire.replies();
        assert_eq!(replies.len(), 4);
        match &replies[0] {
            response::Body::Hello(reply) => {
                assert_eq!(reply.protocol, PROTOCOL_VERSION);
                assert_eq!(reply.daemon_version, "1.2.3");
                assert_eq!(reply.role, Role::Bridge as i32);
            }
            other => panic!("unexpected reply: {other:?}"),
        }
        assert!(matches!(replies[1], response::Body::Status(_)));
        assert_eq!(code(&replies[2]), ErrorCode::BadRequest);
        assert_eq!(code(&replies[3]), ErrorCode::BadRequest);
    }

    #[test]
    fn a_request_before_hello_ends_the_conversation() {
        let mut wire = Wire::with(&[
            request(request::Body::Status(Status {})),
            request(request::Body::Status(Status {})),
        ]);
        assert!(matches!(
            converse(&mut wire, &peer(Role::Ui), &Fixed, "", &Relays::default()),
            Err(IpcError::Protocol(_))
        ));
        let replies = wire.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(code(&replies[0]), ErrorCode::BadRequest);
    }

    #[test]
    fn another_protocol_version_is_refused() {
        let mut wire = Wire::with(&[
            hello(PROTOCOL_VERSION + 1),
            request(request::Body::Status(Status {})),
        ]);
        assert!(converse(&mut wire, &peer(Role::Ui), &Fixed, "", &Relays::default()).is_err());
        let replies = wire.replies();
        assert_eq!(replies.len(), 1);
        assert_eq!(code(&replies[0]), ErrorCode::UnsupportedProtocol);
    }

    #[test]
    fn shutdown_ends_the_conversation_only_if_the_handler_agrees() {
        let requests = [
            hello(PROTOCOL_VERSION),
            request(request::Body::Shutdown(Shutdown {})),
            request(request::Body::Status(Status {})),
        ];
        let mut wire = Wire::with(&requests);
        let end = converse(&mut wire, &peer(Role::Ui), &Fixed, "", &Relays::default()).unwrap();
        assert_eq!(end, Conversation::Shutdown);
        let replies = wire.replies();
        assert_eq!(replies.len(), 2);
        assert!(matches!(replies[1], response::Body::Done(_)));

        let mut wire = Wire::with(&requests);
        let end = converse(&mut wire, &peer(Role::Sync), &Fixed, "", &Relays::default()).unwrap();
        assert_eq!(end, Conversation::Closed);
        let replies = wire.replies();
        assert_eq!(replies.len(), 3);
        assert_eq!(code(&replies[1]), ErrorCode::Denied);
    }
}
