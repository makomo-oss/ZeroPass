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
