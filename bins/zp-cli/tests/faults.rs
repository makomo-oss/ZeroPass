//! Fault injection with the real binaries (plan task P2-18): the process that
//! writes the vault file during a sync is killed, and the vault file must still
//! be usable and catch up afterwards. Since the vault daemon holds the file
//! (P3-05), that process is the daemon, not the `sync` command. Also measures how fast a large sync runs on the local
//! network.
//!
//! Needs a network interface with a private address and working multicast:
//!
//! ```text
//! cargo test --release -p zp-cli --test faults -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;

use zp_vault::model::Login;
use zp_vault::{Store, Vault};

const PC_PASSWORD: &str = "correct horse battery staple";
const PHONE_PASSWORD: &str = "an entirely different passphrase";
/// Enough to keep a sync busy for a moment: about 8 MiB of ciphertext.
const ITEMS: usize = 20_000;

fn command(vault: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zp-cli"));
    command
        .arg("--vault")
        .arg(vault)
        .arg("--insecure-software-keystore")
        .args(args)
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Stops the daemons that the commands started, also when the test fails.
struct Daemons<'a>(&'a [&'a Path]);

impl Drop for Daemons<'_> {
    fn drop(&mut self) {
        for vault in self.0 {
            common::stop_daemon(vault);
        }
    }
}

/// Runs a command to its end, answering its prompts with `input`.
fn run(vault: &Path, args: &[&str], input: &[&str]) -> String {
    let mut child = command(vault, args).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for line in input {
        writeln!(stdin, "{line}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Pairs a new vault file with `pc` through `pair` and `join`.
fn pair(pc: &Path, phone: &Path) {
    let mut pairing = command(pc, &["pair"]).spawn().unwrap();
    let mut stdin = pairing.stdin.take().unwrap();
    writeln!(stdin, "{PC_PASSWORD}").unwrap();
    writeln!(stdin, "y").unwrap();
    let mut stdout = BufReader::new(pairing.stdout.take().unwrap());
    let code = loop {
        let mut line = String::new();
        assert!(stdout.read_line(&mut line).unwrap() > 0, "no pairing code");
        if line.starts_with("ZP1:") {
            break line.trim().to_owned();
        }
    };
    let out = run(
        phone,
        &["join", "--name", "Test phone"],
        &[PHONE_PASSWORD, PHONE_PASSWORD, &code],
    );
    assert!(out.contains("joined vault"), "{out}");
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert!(pairing.wait().unwrap().success());
}

/// How many of the PC's changes the phone's vault file holds.
fn held(phone: &Path, pc: &Path) -> usize {
    let author = Store::open(pc).unwrap().device_id();
    let store = Store::open(phone).unwrap();
    store.version_vector().unwrap().get(&author) as usize
}

fn start_sync(vault: &Path) -> Child {
    command(vault, &["sync", "--seconds", "120"])
        .spawn()
        .unwrap()
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
#[ignore = "needs a local network interface with multicast"]
fn a_sync_killed_while_writing_leaves_a_usable_vault_that_catches_up() {
    let dir = tempfile::tempdir().unwrap();
    let pc: PathBuf = dir.path().join("pc.zpvault");
    let phone: PathBuf = dir.path().join("phone.zpvault");
    common::daemon_is_built();
    // Dropped before `dir`, so the vault files are closed when it is removed.
    let _daemons = Daemons(&[&pc, &phone]);

    run(&pc, &["init"], &[PC_PASSWORD, PC_PASSWORD]);
    pair(&pc, &phone);

    // The PC gets a lot to send.
    {
        let mut vault = Vault::open(&pc).unwrap();
        vault.unlock_password(PC_PASSWORD).unwrap();
        vault
            .insert_many((0..ITEMS).map(|n| {
                let mut login = Login::new(format!("Login {n}"), "alice", "secret");
                login.notes = "n".repeat(200);
                login
            }))
            .unwrap();
    }
    let before = std::fs::metadata(&phone).unwrap().len();
    assert_eq!(held(&phone, &pc), 0);

    // Both sides sync; the process that writes the phone's file, its vault
    // daemon, is killed as soon as the first changes have landed in it.
    let mut pc_sync = start_sync(&pc);
    let mut phone_sync = start_sync(&phone);
    assert!(
        wait_until(Duration::from_secs(60), || held(&phone, &pc) > 0),
        "the sync never started"
    );
    common::kill_daemon(&phone);
    phone_sync.kill().unwrap();
    phone_sync.wait().unwrap();
    pc_sync.kill().unwrap();
    pc_sync.wait().unwrap();

    // The file is intact: it opens, the changes it holds are all readable, and
    // their number is what the version vector says.
    let partial = held(&phone, &pc);
    assert!(partial > 0 && partial <= ITEMS);
    let listed = run(&phone, &["list"], &[PHONE_PASSWORD]);
    assert!(
        listed.contains(&format!("{partial} item(s)")),
        "{partial} held, but: {}",
        listed.lines().last().unwrap_or("")
    );
    eprintln!("killed with {partial} of {ITEMS} changes written");

    // The next sync fetches the rest.
    let started = Instant::now();
    let mut pc_sync = start_sync(&pc);
    let mut phone_sync = start_sync(&phone);
    assert!(
        wait_until(Duration::from_secs(120), || held(&phone, &pc) == ITEMS),
        "the sync did not catch up: {} of {ITEMS}",
        held(&phone, &pc)
    );
    let elapsed = started.elapsed();
    for child in [&mut pc_sync, &mut phone_sync] {
        let _ = child.kill();
        let _ = child.wait();
    }
    let listed = run(&phone, &["list"], &[PHONE_PASSWORD]);
    assert!(listed.contains(&format!("{ITEMS} item(s)")));

    let bytes = std::fs::metadata(&phone).unwrap().len() - before;
    eprintln!(
        "caught up with {} changes in {:.1} s including discovery; the vault file grew by {:.1} MiB in total",
        ITEMS - partial,
        elapsed.as_secs_f64(),
        bytes as f64 / (1024.0 * 1024.0)
    );
}
