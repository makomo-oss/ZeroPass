//! The daemon's side: accepts clients, checks who they are and runs the
//! request–response conversation.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Duration;

use crate::codec::{read_frame, write_frame};
use crate::peer::{ClientPolicy, Peer, PeerProcess};
use crate::proto::{
    Error, ErrorCode, HelloReply, PROTOCOL_VERSION, Request, Response, request, response,
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
                // Closed without a word: nothing is read from, or told to, a
                // process that is not admitted.
                drop(stream);
                handler.rejected(&process);
                continue;
            };
            let peer = Peer { process, role };
            let handler = Arc::clone(&handler);
            let shutdown = shutdown.clone();
            let daemon_version = self.daemon_version.clone();
            thread::spawn(move || {
                let mut stream = stream;
                if let Ok(Conversation::Shutdown) =
                    converse(&mut stream, &peer, &*handler, &daemon_version)
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

/// Runs the conversation with one admitted client until it ends.
fn converse<S: Read + Write, H: Handler + ?Sized>(
    stream: &mut S,
    peer: &Peer,
    handler: &H,
    daemon_version: &str,
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
        let end = converse(&mut wire, &peer(Role::Bridge), &Fixed, "1.2.3").unwrap();
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
            converse(&mut wire, &peer(Role::Ui), &Fixed, ""),
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
        assert!(converse(&mut wire, &peer(Role::Ui), &Fixed, "").is_err());
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
        let end = converse(&mut wire, &peer(Role::Ui), &Fixed, "").unwrap();
        assert_eq!(end, Conversation::Shutdown);
        let replies = wire.replies();
        assert_eq!(replies.len(), 2);
        assert!(matches!(replies[1], response::Body::Done(_)));

        let mut wire = Wire::with(&requests);
        let end = converse(&mut wire, &peer(Role::Sync), &Fixed, "").unwrap();
        assert_eq!(end, Conversation::Closed);
        let replies = wire.replies();
        assert_eq!(replies.len(), 3);
        assert_eq!(code(&replies[1]), ErrorCode::Denied);
    }
}
