//! Checks a packet capture for ZeroPass traffic that leaves the local link
//! (`docs/spec/lan.md` §6). Used by `scripts/check-lan-capture.ps1`:
//!
//! ```text
//! cargo run -p zp-transport --example capture_check -- <capture.pcapng> <this machine's IPv4 address>...
//! ```
//!
//! Exits with status 1 if a packet breaks a rule, 2 if the input is unusable or
//! holds no sync connection (no TCP packet from this machine).

use std::net::Ipv4Addr;
use std::process::ExitCode;

use zp_transport::capture::analyse;

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool"
)]
fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(path) = arguments.next() else {
        eprintln!("usage: capture_check <capture.pcapng> <local IPv4 address>...");
        return ExitCode::from(2);
    };
    let local: Vec<Ipv4Addr> = arguments.filter_map(|text| text.parse().ok()).collect();
    if local.is_empty() {
        eprintln!("give at least one IPv4 address of this machine");
        return ExitCode::from(2);
    }
    let report = match std::fs::read(&path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| analyse(&bytes, &local).map_err(|error| error.to_string()))
    {
        Ok(report) => report,
        Err(error) => {
            eprintln!("{path}: {error}");
            return ExitCode::from(2);
        }
    };

    println!("packets in the capture:        {}", report.packets);
    println!(
        "sent from this machine (IPv4): {} ({} TCP, {} UDP)",
        report.sent, report.sent_tcp, report.sent_udp
    );
    println!("destinations:");
    for destination in &report.destinations {
        println!("  {destination}");
    }
    if report.violations.is_empty() {
        if report.sent_tcp == 0 {
            // mDNS alone does not show how a sync connection behaves.
            println!(
                "RESULT: no sync was captured (no TCP packet from this machine); \
                 sync from the other device while the capture runs and try again"
            );
            return ExitCode::from(2);
        }
        println!(
            "RESULT: ok, every packet stays on the local link and every TCP packet has hop limit 1"
        );
        return ExitCode::SUCCESS;
    }
    println!(
        "RESULT: {} packet(s) break the rules:",
        report.violations.len()
    );
    for violation in report.violations.iter().take(20) {
        println!(
            "  {} -> {} protocol {} ports {:?} ttl {}: {}",
            violation.source,
            violation.destination,
            violation.protocol,
            violation.ports,
            violation.ttl,
            violation.reason
        );
    }
    ExitCode::from(1)
}
