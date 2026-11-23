//! ZeroPass Vault Core Daemon (layer 1). The daemon is in the library, which
//! the Android app also embeds (`zp_vaultd::embedded`).

fn main() -> std::process::ExitCode {
    zp_vaultd::daemon_main()
}
