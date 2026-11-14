//! The client's side: connects to the daemon, checks that it is the daemon and
//! makes requests.

use crate::codec::{read_frame, write_frame};
use crate::peer::DaemonPolicy;
use crate::proto::{
    ErrorCode, Hello, PROTOCOL_VERSION, Request, Response, Role, request, response,
};
use crate::{Endpoint, IpcError, sys};

/// An open conversation with the daemon.
pub struct Client {
    stream: sys::Stream,
    role: Role,
    daemon_version: String,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("role", &self.role)
            .field("daemon_version", &self.daemon_version)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Connects to the daemon on `endpoint` and opens the conversation.
    ///
    /// Nothing is sent before the process serving the endpoint has passed
    /// `policy`. `name` identifies this client in the daemon's logs.
    pub fn connect(
        endpoint: &Endpoint,
        policy: &DaemonPolicy,
        name: &str,
    ) -> Result<Self, IpcError> {
        let (stream, process) = sys::connect(endpoint)?;
        if !policy.accepts(&process) {
            let who = match &process.executable {
                Some(path) => path.display().to_string(),
                None => "an unidentified process".to_owned(),
            };
            return Err(IpcError::UntrustedPeer(who));
        }
        let mut client = Self {
            stream,
            role: Role::Unspecified,
            daemon_version: String::new(),
        };
        let hello = request::Body::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            client: name.to_owned(),
        });
        // A daemon that does not admit this executable says why and closes the
        // connection without reading: the write may fail, and the reason may
        // still be there to read.
        let _ = write_frame(&mut client.stream, &Request { body: Some(hello) });
        let reply = match read_frame::<_, Response>(&mut client.stream) {
            Ok(Some(Response {
                body: Some(response::Body::Hello(reply)),
            })) => reply,
            Ok(Some(Response {
                body: Some(response::Body::Error(error)),
            })) if error.code == ErrorCode::Denied as i32 => {
                return Err(IpcError::Refused(error.message.clone()));
            }
            Ok(Some(Response {
                body: Some(response::Body::Error(error)),
            })) => return Err(IpcError::Remote(error)),
            Ok(Some(_)) => return Err(IpcError::Protocol("the daemon did not answer Hello")),
            Ok(None) | Err(IpcError::Io(_)) => return Err(IpcError::Refused(String::new())),
            Err(error) => return Err(error),
        };
        if reply.protocol != PROTOCOL_VERSION {
            return Err(IpcError::Protocol("unsupported protocol version"));
        }
        client.role = Role::try_from(reply.role).unwrap_or(Role::Unspecified);
        client.daemon_version = reply.daemon_version;
        Ok(client)
    }

    /// The role the daemon gave this connection.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The version of the daemon.
    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    /// Makes one request and waits for the answer. An error answer is returned
    /// as [`IpcError::Remote`].
    pub fn call(&mut self, body: request::Body) -> Result<response::Body, IpcError> {
        write_frame(&mut self.stream, &Request { body: Some(body) })?;
        let response: Response = read_frame(&mut self.stream)?
            .ok_or(IpcError::Protocol("the daemon closed the connection"))?;
        match response.body {
            Some(response::Body::Error(error)) => Err(IpcError::Remote(error)),
            Some(body) => Ok(body),
            None => Err(IpcError::Protocol("the daemon sent an unknown response")),
        }
    }
}

/// The client's reading end of a relay (`docs/spec/ipc.md` §11): the daemon's
/// messages arrive here, one after the other, until the last one.
pub struct Downlink {
    client: Client,
}

impl Downlink {
    /// Waits for the daemon's next message. An error message ends the relay
    /// and is returned as [`IpcError::Remote`].
    pub fn receive(&mut self) -> Result<response::Body, IpcError> {
        let response: Response = read_frame(&mut self.client.stream)?
            .ok_or(IpcError::Protocol("the daemon closed the relay"))?;
        match response.body {
            Some(response::Body::Error(error)) => Err(IpcError::Remote(error)),
            Some(body) => Ok(body),
            None => Err(IpcError::Protocol("the daemon sent an unknown response")),
        }
    }
}

/// The client's writing end of a relay: what is sent here reaches the daemon's
/// side of the relay. Dropping it tells the daemon that nothing more comes.
pub struct Uplink {
    client: Client,
}

impl Uplink {
    /// Sends one message. There is no answer.
    pub fn send(&mut self, body: request::Body) -> Result<(), IpcError> {
        write_frame(&mut self.client.stream, &Request { body: Some(body) })
    }
}

impl Client {
    /// Makes a request that starts a relay. This connection becomes the
    /// relay's downlink; the returned number names the relay for
    /// [`Self::attach_relay`] on a second connection.
    pub fn start_relay(mut self, request: request::Body) -> Result<(u64, Downlink), IpcError> {
        match self.call(request)? {
            response::Body::RelayOpened(opened) => Ok((opened.relay_id, Downlink { client: self })),
            _ => Err(IpcError::Protocol("the daemon did not open a relay")),
        }
    }

    /// Makes this connection the uplink of the relay `relay_id`.
    pub fn attach_relay(mut self, relay_id: u64) -> Result<Uplink, IpcError> {
        let attach = request::Body::RelayAttach(crate::proto::RelayAttach { relay_id });
        match self.call(attach)? {
            response::Body::Done(_) => Ok(Uplink { client: self }),
            _ => Err(IpcError::Protocol("the daemon did not attach the relay")),
        }
    }
}
