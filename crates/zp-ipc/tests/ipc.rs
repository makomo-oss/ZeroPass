//! The IPC over the real transport of this platform: a named pipe on Windows,
//! a Unix domain socket elsewhere. Client and server are threads of this test
//! process, so "the executable at the other end" is the test binary itself.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zp_ipc::proto::{
    Domain, Done, Error, ErrorCode, GetItem, Item, Login, Role, Shutdown, Status, StatusReply,
    item, request, response,
};
use zp_ipc::{
    Client, ClientPolicy, DaemonPolicy, Endpoint, Handler, IpcError, Peer, PeerProcess, Server,
    ShutdownHandle,
};

/// Whether this platform tells which executable is at the other end
/// (`docs/spec/ipc.md` §3.3).
const IDENTIFIES_PEERS: bool = cfg!(any(windows, target_os = "linux"));

#[derive(Default)]
struct TestHandler {
    rejected: AtomicUsize,
}

/// A login whose notes are far longer than the transport's buffer.
fn big_login() -> Login {
    let mut login = Login::default();
    login.title = "big".into();
    login.notes = "n".repeat(1_000_000);
    login
}

impl Handler for TestHandler {
    fn handle(&self, peer: &Peer, request: request::Body) -> response::Body {
        match request {
            request::Body::Status(_) => response::Body::Status(StatusReply {
                vault_exists: true,
                vault_id: vec![7; 16],
                ..StatusReply::default()
            }),
            // Echoes the identifier back inside a large item, to push a frame
            // well past the size of the pipe buffer.
            request::Body::GetItem(get) => response::Body::Item(Item {
                item_id: get.item_id,
                content: Some(item::Content::Login(big_login())),
            }),
            request::Body::Shutdown(_) if peer.role == Role::Ui => response::Body::Done(Done {}),
            _ => response::Body::Error(Error::about(
                ErrorCode::Locked,
                Domain::Totp,
                "the totp domain is locked",
            )),
        }
    }

    fn rejected(&self, _process: &PeerProcess) {
        self.rejected.fetch_add(1, Ordering::SeqCst);
    }
}

struct Daemon {
    endpoint: Endpoint,
    handler: Arc<TestHandler>,
    shutdown: ShutdownHandle,
    thread: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

fn this_executable() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn start(policy: ClientPolicy) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::for_vault(&dir.path().join("test.zpvault")).unwrap();
    let server = Server::bind(&endpoint, policy, "0.0.0-test").unwrap();
    let shutdown = server.shutdown_handle();
    let handler = Arc::new(TestHandler::default());
    let thread = {
        let handler = Arc::clone(&handler);
        thread::spawn(move || server.serve(handler))
    };
    Daemon {
        endpoint,
        handler,
        shutdown,
        thread,
        _dir: dir,
    }
}

fn trusting_this_test() -> DaemonPolicy {
    DaemonPolicy::default().allow(this_executable())
}

fn connect_to(endpoint: &Endpoint) -> Result<Client, IpcError> {
    Client::connect(endpoint, &trusting_this_test(), "test")
}

fn connect(daemon: &Daemon) -> Result<Client, IpcError> {
    connect_to(&daemon.endpoint)
}

/// Stops the daemon from its own side and waits for it.
fn stop(daemon: Daemon) {
    daemon.shutdown.shutdown();
    daemon.thread.join().unwrap();
}

#[test]
fn an_admitted_client_talks_to_the_daemon() {
    let daemon = start(ClientPolicy::deny_all().allow(this_executable(), Role::Ui));
    let mut client = connect(&daemon).unwrap();
    assert_eq!(client.role(), Role::Ui);
    assert_eq!(client.daemon_version(), "0.0.0-test");

    for _ in 0..3 {
        match client.call(request::Body::Status(Status {})).unwrap() {
            response::Body::Status(status) => {
                assert!(status.vault_exists);
                assert_eq!(status.vault_id, vec![7; 16]);
            }
            other => panic!("unexpected reply: {other:?}"),
        }
    }

    // A reply far larger than the transport's buffer arrives whole.
    let get = request::Body::GetItem(GetItem {
        item_id: vec![1; 16],
    });
    match client.call(get).unwrap() {
        response::Body::Item(item) => {
            assert_eq!(item.item_id, vec![1; 16]);
            match item.content {
                Some(item::Content::Login(login)) => assert_eq!(login.notes.len(), 1_000_000),
                _ => panic!("unexpected content"),
            }
        }
        other => panic!("unexpected reply: {other:?}"),
    }

    // An error answer carries its code and domain.
    let error = client
        .call(request::Body::ListDevices(Default::default()))
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Locked));
    match &error {
        IpcError::Remote(remote) => assert_eq!(remote.domain, Some(Domain::Totp as i32)),
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(error.to_string(), "the totp domain is locked");

    // Shutdown is answered, and then the daemon stops.
    match client.call(request::Body::Shutdown(Shutdown {})).unwrap() {
        response::Body::Done(_) => {}
        other => panic!("unexpected reply: {other:?}"),
    }
    daemon.thread.join().unwrap();
    drop(daemon.shutdown);
    assert!(matches!(
        connect_to(&daemon.endpoint),
        Err(IpcError::NotRunning)
    ));
}

#[test]
fn several_clients_are_served_at_once() {
    let daemon = start(ClientPolicy::deny_all().allow(this_executable(), Role::Ui));
    let mut first = connect(&daemon).unwrap();
    let mut second = connect(&daemon).unwrap();
    // Interleaved requests on two open connections.
    for _ in 0..2 {
        first.call(request::Body::Status(Status {})).unwrap();
        second.call(request::Body::Status(Status {})).unwrap();
    }
    let endpoint = daemon.endpoint.clone();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let endpoint = endpoint.clone();
            thread::spawn(move || {
                let mut client =
                    Client::connect(&endpoint, &trusting_this_test(), "worker").expect("connect");
                client
                    .call(request::Body::Status(Status {}))
                    .expect("status");
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    drop((first, second));
    stop(daemon);
}

#[test]
fn the_role_comes_from_the_policy_and_limits_shutdown() {
    let daemon = start(ClientPolicy::deny_all().allow(this_executable(), Role::Sync));
    let mut client = connect(&daemon).unwrap();
    let expected = if IDENTIFIES_PEERS {
        Role::Sync
    } else {
        Role::Ui
    };
    assert_eq!(client.role(), expected);
    if IDENTIFIES_PEERS {
        // The handler refuses Shutdown to this role, and the daemon keeps running.
        assert!(client.call(request::Body::Shutdown(Shutdown {})).is_err());
        client.call(request::Body::Status(Status {})).unwrap();
        assert!(!daemon.thread.is_finished());
    }
    drop(client);
    stop(daemon);
}

#[test]
fn the_daemon_can_be_stopped_from_its_own_side() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::for_vault(&dir.path().join("test.zpvault")).unwrap();
    let server = Server::bind(&endpoint, ClientPolicy::deny_all(), "test").unwrap();
    let handle = server.shutdown_handle();
    let thread = thread::spawn(move || server.serve(Arc::new(TestHandler::default())));
    handle.shutdown();
    thread.join().unwrap();
    drop(handle);
    // The endpoint is free again.
    assert!(matches!(
        Client::connect(&endpoint, &trusting_this_test(), "test"),
        Err(IpcError::NotRunning)
    ));
    Server::bind(&endpoint, ClientPolicy::deny_all(), "test").unwrap();
}

#[test]
fn a_process_that_is_not_on_the_list_is_refused() {
    if !IDENTIFIES_PEERS {
        return;
    }
    // The default policy admits the ZeroPass executables beside the daemon; the
    // test binary is none of them.
    let daemon = start(ClientPolicy::beside_current_exe().unwrap());
    for _ in 0..2 {
        assert!(matches!(connect(&daemon), Err(IpcError::Refused)));
    }
    // The server counts a refusal just after closing the connection, so the
    // client can hear of it first.
    let deadline = Instant::now() + Duration::from_secs(5);
    while daemon.handler.rejected.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(daemon.handler.rejected.load(Ordering::SeqCst), 2);
    assert!(!daemon.thread.is_finished());
    stop(daemon);
}

#[test]
fn a_client_does_not_talk_to_an_unexpected_daemon() {
    if !IDENTIFIES_PEERS {
        return;
    }
    let daemon = start(ClientPolicy::deny_all().allow(this_executable(), Role::Ui));
    // The default policy expects `zp-vaultd` beside this executable; the server
    // of this endpoint is the test binary.
    let policy = DaemonPolicy::beside_current_exe().unwrap();
    let error = Client::connect(&daemon.endpoint, &policy, "test").unwrap_err();
    assert!(matches!(error, IpcError::UntrustedPeer(_)), "{error:?}");
    stop(daemon);
}

#[test]
fn only_one_daemon_serves_an_endpoint() {
    let daemon = start(ClientPolicy::deny_all().allow(this_executable(), Role::Ui));
    assert!(matches!(
        Server::bind(&daemon.endpoint, ClientPolicy::deny_all(), "second"),
        Err(IpcError::AlreadyRunning)
    ));
    // Still true while a client is connected.
    let client = connect(&daemon).unwrap();
    assert!(matches!(
        Server::bind(&daemon.endpoint, ClientPolicy::deny_all(), "second"),
        Err(IpcError::AlreadyRunning)
    ));
    drop(client);
    stop(daemon);
}

#[test]
fn connecting_without_a_daemon_reports_that_it_is_not_running() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::for_vault(&dir.path().join("nobody.zpvault")).unwrap();
    assert!(matches!(
        Client::connect(&endpoint, &trusting_this_test(), "test"),
        Err(IpcError::NotRunning)
    ));
}
