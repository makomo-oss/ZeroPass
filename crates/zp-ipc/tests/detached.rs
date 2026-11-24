//! A process started with `spawn_detached` keeps none of the handles of the
//! process that started it: whoever reads the output of a process up the line
//! sees it end when that process ends, not when the detached process does.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TEST: &str = "a_detached_process_keeps_no_handle_of_its_starter";
/// Which copy of this test binary this is: unset for the test itself.
const ROLE: &str = "ZP_IPC_TEST_DETACHED_ROLE";

/// How long the detached process lives: much longer than the bound below.
const DETACHED_SECS: u32 = 10;

/// A program that lives for about `DETACHED_SECS` seconds and needs no console.
fn long_lived() -> Command {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot is set");
        let mut ping = Command::new(std::path::Path::new(&root).join(r"System32\PING.EXE"));
        ping.args(["-n", &(DETACHED_SECS + 1).to_string(), "127.0.0.1"]);
        ping
    } else {
        let mut sleep = Command::new("/bin/sleep");
        sleep.arg(DETACHED_SECS.to_string());
        sleep
    }
}

/// This test binary again, running only this test, as `role`.
fn this_test_as(role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture"])
        .env(ROLE, role)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// The process line is the one of a script, or of a test runner, that reads
/// what a program prints while that program starts a daemon:
///
/// test (reads the output of) → middle → starter → detached process
///
/// The middle process hands its output on to the starter, as a handle the
/// starter does not use, alongside the pipe it gives it as standard output.
#[test]
fn a_detached_process_keeps_no_handle_of_its_starter() {
    match std::env::var(ROLE).as_deref() {
        Ok("starter") => {
            zp_ipc::spawn_detached(&mut long_lived()).unwrap();
            return;
        }
        Ok("middle") => {
            let output = this_test_as("starter").output().unwrap();
            assert!(output.status.success());
            println!("started");
            return;
        }
        _ => {}
    }
    let mut middle = this_test_as("middle")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = middle.stdout.take().unwrap();
    assert!(middle.wait().unwrap().success());

    // The middle process has ended: its output ends now, unless the detached
    // process holds on to it.
    let reading = Instant::now();
    let mut text = String::new();
    output.read_to_string(&mut text).unwrap();
    let waited = reading.elapsed();
    assert!(text.contains("started"), "{text}");
    assert!(
        waited < Duration::from_secs(3),
        "the output of the middle process stayed open for {waited:?}, as long as the detached process"
    );
}
