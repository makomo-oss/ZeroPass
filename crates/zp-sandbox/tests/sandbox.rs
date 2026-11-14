//! What the sandbox takes away, shown by running the same program
//! (`examples/probe.rs`) outside and inside it.
//!
//! The probe is an example of this package: `cargo test -p zp-sandbox` builds
//! it. With a narrower target selection (`--test sandbox`), build it first:
//! `cargo build -p zp-sandbox --examples`.

#![cfg(windows)]
#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use zp_ipc::proto::{Shutdown, Status, request};
use zp_ipc::{Client, DaemonPolicy, Endpoint, IpcError};
use zp_sandbox::Access;

const CONTAINER: &str = "ZeroPass.Test.Probe";

fn probe_exe() -> PathBuf {
    // target/<profile>/deps/<test>.exe -> target/<profile>/examples/probe.exe
    let test = std::env::current_exe().unwrap();
    let profile = test.parent().unwrap().parent().unwrap();
    profile.join("examples").join("probe.exe")
}

/// An address of this machine on its local network, if it has one.
fn lan_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // Connecting a datagram socket sends nothing; it only selects a route.
    socket.connect("192.0.2.1:9").ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

/// What one run of the probe showed.
struct Observation {
    /// The probe's own report.
    report: BTreeMap<String, String>,
    /// Whether the datagram the probe sent arrived.
    datagram_arrived: bool,
    /// Whether a connection to the probe's TCP listener succeeded.
    listener_reachable: bool,
    /// The executable the probe's IPC server saw connecting, or why the
    /// connection failed.
    ipc_client: Result<String, String>,
}

impl Observation {
    fn get(&self, key: &str) -> &str {
        self.report
            .get(key)
            .unwrap_or_else(|| panic!("the report has no {key}: {:?}", self.report))
    }

    fn ok(&self, key: &str) -> bool {
        self.get(key) == "ok"
    }
}

fn observe(sandboxed: bool) -> Observation {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    std::fs::write(path.join("granted.txt"), b"granted").unwrap();
    std::fs::write(path.join("not-granted.txt"), b"not granted").unwrap();
    if sandboxed {
        zp_sandbox::allow(CONTAINER, &probe_exe(), Access::ReadExecute).unwrap();
        zp_sandbox::allow(CONTAINER, path, Access::CreateFiles).unwrap();
        zp_sandbox::allow(CONTAINER, &path.join("granted.txt"), Access::Modify).unwrap();
    }

    let loopback = TcpListener::bind("127.0.0.1:0").unwrap();
    let lan = lan_address().and_then(|address| TcpListener::bind((address, 0)).ok());
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let args: Vec<OsString> = vec![
        path.into(),
        loopback.local_addr().unwrap().to_string().into(),
        lan.as_ref()
            .map_or_else(
                || "none".to_owned(),
                |l| l.local_addr().unwrap().to_string(),
            )
            .into(),
        udp.local_addr().unwrap().to_string().into(),
        std::env::current_exe().unwrap().into(),
    ];

    // Start it; it reports and then serves the IPC until told to stop.
    let mut plain = None;
    let mut contained = None;
    if sandboxed {
        contained = Some(zp_sandbox::spawn(CONTAINER, &probe_exe(), &args).unwrap());
    } else {
        plain = Some(Command::new(probe_exe()).args(&args).spawn().unwrap());
    }

    let report_path = path.join("report.txt");
    let deadline = Instant::now() + Duration::from_secs(30);
    let report: BTreeMap<String, String> = loop {
        if let Ok(text) = std::fs::read_to_string(&report_path)
            && text.contains("ipc_bind=")
        {
            break text
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect();
        }
        assert!(Instant::now() < deadline, "the probe wrote no report");
        std::thread::sleep(Duration::from_millis(50));
    };

    let mut buffer = [0u8; 16];
    let datagram_arrived = udp.recv_from(&mut buffer).is_ok();

    let port: u16 = report["tcp_listen_port"].parse().unwrap();
    let listener_reachable = port != 0
        && TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_secs(2),
        )
        .is_ok();

    // The probe's IPC endpoint, from this (unsandboxed) process.
    let endpoint = Endpoint::for_vault(&path.join("probe.zpvault"))
        .unwrap()
        .with_sandbox(CONTAINER);
    let policy = DaemonPolicy::default().allow(probe_exe());
    let deadline = Instant::now() + Duration::from_secs(10);
    let ipc_client = loop {
        match Client::connect(&endpoint, &policy, "test") {
            Ok(mut client) => {
                // The probe answers Status with an "error" that carries the
                // executable it saw connecting.
                let seen = match client.call(request::Body::Status(Status {})) {
                    Err(IpcError::Remote(error)) => Ok(error.message.clone()),
                    other => Err(format!("{other:?}")),
                };
                let _ = client.call(request::Body::Shutdown(Shutdown {}));
                break seen;
            }
            Err(IpcError::NotRunning)
                if report["ipc_bind"] == "ok" && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => break Err(error.to_string()),
        }
    };

    // Make sure it is gone before the directory is.
    if let Some(mut child) = plain {
        if ipc_client.is_err() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
    if let Some(child) = contained {
        if ipc_client.is_err() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    Observation {
        report,
        datagram_arrived,
        listener_reachable,
        ipc_client,
    }
}

/// The probe outside the sandbox: the control.
fn outside() -> &'static Observation {
    static OUTSIDE: OnceLock<Observation> = OnceLock::new();
    OUTSIDE.get_or_init(|| observe(false))
}

/// The probe inside the sandbox.
fn inside() -> &'static Observation {
    static INSIDE: OnceLock<Observation> = OnceLock::new();
    INSIDE.get_or_init(|| observe(true))
}

#[test]
fn the_probe_runs_in_the_sandbox_only_when_started_through_it() {
    assert_eq!(outside().get("sandboxed"), "false");
    assert_eq!(inside().get("sandboxed"), "true");
}

#[test]
fn a_sandboxed_process_cannot_use_the_network() {
    // The control: without the sandbox, all of this works on this machine.
    let outside = outside();
    assert!(outside.ok("tcp_connect_loopback"), "{:?}", outside.report);
    assert!(outside.datagram_arrived);
    assert!(outside.listener_reachable);

    let inside = inside();
    // Outgoing connections fail, to this machine itself ...
    assert!(!inside.ok("tcp_connect_loopback"), "{:?}", inside.report);
    // ... and to an address on the local network.
    if let Some(lan) = inside.report.get("tcp_connect_lan") {
        assert!(outside.ok("tcp_connect_lan"), "{:?}", outside.report);
        assert_ne!(lan, "ok");
    }
    // Datagrams do not leave.
    assert!(!inside.datagram_arrived);
    // Nobody can connect to a socket it listens on.
    assert!(!inside.listener_reachable);
}

#[test]
fn a_sandboxed_process_opens_only_what_it_was_granted() {
    let outside = outside();
    for key in [
        "file_create",
        "file_reopen",
        "file_delete",
        "file_granted",
        "file_not_granted",
        "dir_list",
        "dir_list_home",
    ] {
        assert!(outside.ok(key), "{key}: {:?}", outside.report);
    }

    let inside = inside();
    // In a directory granted with `CreateFiles`, it works with its own files
    // and with a file granted by name ...
    for key in ["file_create", "file_reopen", "file_delete", "file_granted"] {
        assert!(inside.ok(key), "{key}: {:?}", inside.report);
    }
    // ... but not with the other files there, and it cannot list the
    // directory, let alone the user's profile.
    for key in ["file_not_granted", "dir_list", "dir_list_home"] {
        assert!(!inside.ok(key), "{key}: {:?}", inside.report);
    }
}

#[test]
fn a_sandboxed_process_serves_the_local_ipc_and_sees_who_connects() {
    let this = std::env::current_exe().unwrap();
    for observation in [outside(), inside()] {
        assert!(observation.ok("ipc_bind"), "{:?}", observation.report);
        let seen = observation.ipc_client.as_ref().unwrap();
        assert_eq!(
            seen.to_lowercase(),
            this.display().to_string().to_lowercase()
        );
    }
}
