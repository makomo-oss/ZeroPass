//! Reports what the process it runs in can do: reach the network, open files,
//! serve the local IPC. The sandbox tests (`tests/sandbox.rs`) start it outside
//! and inside the sandbox and compare the two reports.
//!
//! Usage: `probe <directory> <tcp loopback> <tcp lan | none> <udp> <client exe>`
//!
//! The probe writes `report.txt` into the directory, one `key=value` line per
//! check, and then serves the IPC endpoint of `<directory>/probe.zpvault` until
//! it is told to shut down, admitting `<client exe>` as a user interface. While
//! it serves, it keeps a TCP listener open whose port is in the report.

use std::fmt::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use zp_ipc::proto::{self, Role, request, response};
use zp_ipc::{ClientPolicy, Endpoint, Handler, IpcError, Peer, Server};

const TIMEOUT: Duration = Duration::from_secs(2);

fn outcome<T, E: std::fmt::Display>(result: Result<T, E>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => format!("error: {error}").replace('\n', " "),
    }
}

/// Answers `Status` with what the server learned about the client.
struct Echo;

impl Handler for Echo {
    fn handle(&self, peer: &Peer, request: request::Body) -> response::Body {
        match request {
            request::Body::Shutdown(_) => response::Body::Done(proto::Done {}),
            _ => {
                let executable = peer
                    .process
                    .executable
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default();
                response::Body::Error(proto::Error::new(proto::ErrorCode::Internal, executable))
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, directory, loopback, lan, udp, client] = args.as_slice() else {
        std::process::exit(2);
    };
    let directory = PathBuf::from(directory);
    let mut report = String::new();
    let mut note = |key: &str, value: String| {
        let _ = writeln!(report, "{key}={value}");
    };

    note("sandboxed", zp_sandbox::is_sandboxed().to_string());

    // Network, outwards.
    for (key, address) in [("tcp_connect_loopback", loopback), ("tcp_connect_lan", lan)] {
        if address == "none" {
            continue;
        }
        let result = address
            .parse::<SocketAddr>()
            .map_err(|error| error.to_string())
            .and_then(|address| {
                TcpStream::connect_timeout(&address, TIMEOUT).map_err(|error| error.to_string())
            });
        note(key, outcome(result));
    }
    // A datagram: whether it arrives is for the receiver to say.
    let _ = UdpSocket::bind("0.0.0.0:0").and_then(|socket| socket.send_to(b"probe", udp));
    // Network, inwards: whether anyone can connect is for the test to try.
    let listener = TcpListener::bind("0.0.0.0:0").ok();
    let port = listener
        .as_ref()
        .and_then(|listener| listener.local_addr().ok())
        .map_or(0, |address| address.port());
    note("tcp_listen_port", port.to_string());

    // Files.
    let created = directory.join("created-by-probe.txt");
    note("file_create", outcome(std::fs::write(&created, b"x")));
    note("file_reopen", outcome(std::fs::read(&created)));
    note("file_delete", outcome(std::fs::remove_file(&created)));
    note(
        "file_granted",
        outcome(std::fs::read(directory.join("granted.txt"))),
    );
    note(
        "file_not_granted",
        outcome(std::fs::read(directory.join("not-granted.txt"))),
    );
    note("dir_list", outcome(std::fs::read_dir(&directory)));
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_default();
    note("dir_list_home", outcome(std::fs::read_dir(home)));

    // The local IPC.
    let policy = ClientPolicy::deny_all().allow(client, Role::Ui);
    let server = Endpoint::for_vault(&directory.join("probe.zpvault"))
        .map_err(IpcError::from)
        .and_then(|endpoint| Server::bind(&endpoint, policy, "probe"));
    note("ipc_bind", outcome(server.as_ref()));

    if std::fs::write(directory.join("report.txt"), &report).is_err() {
        std::process::exit(3);
    }
    if let Ok(server) = server {
        server.serve(Arc::new(Echo));
    }
    drop(listener);
}
