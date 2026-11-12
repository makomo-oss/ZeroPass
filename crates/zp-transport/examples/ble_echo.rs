//! A manual check of the Bluetooth LE peripheral (`docs/spec/ble.md` §9).
//!
//! Advertises the ZeroPass service with fixed test tags and echoes whatever a
//! central writes to `Rx` back on `Tx`. Use a generic BLE scanner app on a phone:
//! connect, read `Tag`, subscribe to `Tx`, write to `Rx`.
//!
//! ```text
//! cargo run -p zp-transport --example ble_echo
//! ```
//!
//! No vault is involved and nothing secret is sent.

#[cfg(windows)]
#[allow(
    clippy::print_stdout,
    reason = "an interactive tool that reports on the console"
)]
fn main() -> std::io::Result<()> {
    use std::time::Duration;

    use zp_transport::ble_windows::BlePeripheral;
    use zp_transport::{Connection, DriveError, Transport};

    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };

    let mut peripheral = BlePeripheral::new()?;
    peripheral.advertise([0x11; 8])?;
    peripheral.set_pairing_tag(Some([0x22; 8]))?;
    println!("Advertising service 5a50c0de-0001-4b1d-9c5e-7a65726f7061");
    println!("  Tag (…0002…, read)   = 1111111111111111 2222222222222222");
    println!("  Rx  (…0003…, write)  : bytes written here are printed and echoed");
    println!("  Tx  (…0004…, notify) : subscribe to open a link");
    println!("Press Ctrl+C to stop.");

    loop {
        let Some(link) = peripheral.accept(Duration::from_secs(1))? else {
            continue;
        };
        println!("link opened by {}", link.peer());
        let mut connection = match Connection::open(link, Duration::from_secs(60)) {
            Ok(connection) => connection,
            Err(error) => {
                println!("link failed: {error}");
                continue;
            }
        };
        loop {
            match connection.receive() {
                Ok(bytes) => {
                    println!("received {} bytes: {}", bytes.len(), hex(&bytes));
                    if let Err(error) = connection.send(&bytes) {
                        println!("echo failed: {error}");
                        break;
                    }
                }
                Err(DriveError::Timeout) => {
                    println!("link idle for 60 s, closing");
                    break;
                }
                Err(error) => {
                    println!("link closed: {error}");
                    break;
                }
            }
        }
    }
}

#[cfg(not(windows))]
#[allow(
    clippy::print_stderr,
    reason = "an interactive tool that reports on the console"
)]
fn main() {
    eprintln!("the BLE peripheral is only implemented for Windows so far");
}
