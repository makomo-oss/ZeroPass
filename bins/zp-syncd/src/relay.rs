//! Carrying the bytes of a link to another device over an IPC relay
//! (`docs/spec/ipc.md` §12). They are the pairing channel's ciphertext; this
//! process cannot read them.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use zp_ipc::RelayEnd;
use zp_ipc::proto::{self, ErrorCode, request, response};
use zp_transport::{Address, Transport};
use zp_transport::{LanTransport, Link};

fn ended(reason: impl Into<String>) -> response::Body {
    response::Body::LinkEnded(proto::LinkEnded {
        reason: reason.into(),
    })
}

/// Carries bytes both ways between `link` and the client at the other end of
/// `relay`, until either side ends.
///
/// The client is first told, with `Done`, that the link is up: the other device
/// is there, and the protocol can start.
pub(crate) fn carry(link: Box<dyn Link>, relay: RelayEnd) -> response::Body {
    let (mut from_device, mut to_device) = match link.split() {
        Ok(halves) => halves,
        Err(error) => return ended(error.to_string()),
    };
    let RelayEnd { incoming, outgoing } = relay;
    if outgoing.send(response::Body::Done(proto::Done {})).is_err() {
        return ended("the client went away");
    }
    let client_gone = Arc::new(AtomicBool::new(false));

    // Client → device. Ends when the client closes its uplink.
    {
        let client_gone = Arc::clone(&client_gone);
        thread::spawn(move || {
            for message in incoming {
                if let request::Body::LinkData(chunk) = message
                    && to_device
                        .write_all(&chunk.data)
                        .and_then(|()| to_device.flush())
                        .is_err()
                {
                    break;
                }
            }
            client_gone.store(true, Ordering::Relaxed);
            // Dropping `to_device` closes the link towards the device.
        });
    }

    // Device → client.
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        match from_device.read(&mut buffer) {
            Ok(0) => return ended(""),
            Ok(count) => {
                let data = buffer[..count].to_vec();
                if outgoing
                    .send(response::Body::LinkData(proto::LinkData { data }))
                    .is_err()
                {
                    return ended("the client went away");
                }
            }
            // Links wake their reader up regularly when nothing arrives.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                if client_gone.load(Ordering::Relaxed) {
                    return ended("");
                }
            }
            Err(error) => return ended(error.to_string()),
        }
    }
}

/// `PairConnect`: connects to the first of `addresses` that answers on the
/// local network and carries the link.
pub(crate) fn connect(addresses: &[String], relay: RelayEnd) -> response::Body {
    let failed = |message: String| {
        response::Body::Error(proto::Error::new(ErrorCode::InvalidInput, message))
    };
    let mut transport = match LanTransport::new() {
        Ok(transport) => transport,
        Err(error) => return failed(format!("cannot use the local network: {error}")),
    };
    let mut last_error = None;
    for address in addresses {
        let Ok(address) = address.parse::<SocketAddr>() else {
            last_error = Some(format!("{address} is not an address and a port"));
            continue;
        };
        match transport.connect(&Address::Socket(address)) {
            Ok(link) => return carry(link, relay),
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    failed(format!(
        "cannot reach the other device on the local network: {}",
        last_error.unwrap_or_else(|| "the code contains no address".to_owned())
    ))
}
