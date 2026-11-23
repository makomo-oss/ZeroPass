//! Where the daemons of a vault listen (`docs/spec/ipc.md` §2.1, §12).

use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};

/// The IPC endpoint of one of the daemons that serve a vault file: the vault
/// daemon or the sync daemon.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    id: String,
    service: &'static str,
    sandbox: Option<String>,
}

/// The name of the sandbox the vault daemon runs in (on Windows, its
/// AppContainer). Clients look for the daemon's endpoint there first.
pub const DAEMON_SANDBOX: &str = "ZeroPass.Vault";

impl Endpoint {
    /// The endpoint of the vault daemon for the vault file at `vault`. The
    /// file does not need to exist.
    pub fn for_vault(vault: &Path) -> io::Result<Self> {
        Self::new(vault, "vaultd", Some(DAEMON_SANDBOX))
    }

    /// The endpoint of the sync daemon for the vault file at `vault`. The sync
    /// daemon is not sandboxed: it is the process that talks to other devices.
    pub fn for_sync_daemon(vault: &Path) -> io::Result<Self> {
        Self::new(vault, "syncd", None)
    }

    fn new(vault: &Path, service: &'static str, sandbox: Option<&str>) -> io::Result<Self> {
        let absolute = std::path::absolute(vault)?;
        let mut text = absolute.to_string_lossy().into_owned();
        if cfg!(windows) {
            text = text.to_lowercase();
        }
        let mut hasher = Sha256::new();
        hasher.update(b"zeropass/v1/ipc");
        hasher.update([0u8]);
        hasher.update(text.as_bytes());
        let digest = hasher.finalize();
        let id = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            id,
            service,
            sandbox: sandbox.map(str::to_owned),
        })
    }

    /// Looks for the daemon in the sandbox `name` instead of
    /// [`DAEMON_SANDBOX`]. Only clients use this; a daemon listens wherever
    /// the sandbox it was started in lets it.
    #[must_use]
    pub fn with_sandbox(mut self, name: &str) -> Self {
        self.sandbox = Some(name.to_owned());
        self
    }

    /// The name of the sandbox clients look for the daemon in, if it runs in one.
    pub fn sandbox(&self) -> Option<&str> {
        self.sandbox.as_deref()
    }

    /// Which daemon this is: `vaultd` or `syncd`. Part of the endpoint's name.
    pub fn service(&self) -> &str {
        self.service
    }

    /// The identifier derived from the vault path: 16 hexadecimal digits.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The directory the endpoint's socket is made in (Unix), which a
    /// sandboxed daemon must be allowed to make sockets in; `None` on Windows,
    /// where endpoints are not files.
    pub fn directory(&self) -> io::Result<Option<std::path::PathBuf>> {
        crate::sys::endpoint_directory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_file_gives_the_same_endpoint() {
        let dir = std::env::temp_dir();
        let a = Endpoint::for_vault(&dir.join("a.zpvault")).unwrap();
        let again = Endpoint::for_vault(&dir.join("a.zpvault")).unwrap();
        let b = Endpoint::for_vault(&dir.join("b.zpvault")).unwrap();
        assert_eq!(a, again);
        assert_ne!(a, b);
        assert_eq!(a.id().len(), 16);
        assert!(a.id().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn the_two_daemons_of_a_vault_have_their_own_endpoints() {
        let path = std::env::temp_dir().join("a.zpvault");
        let vault = Endpoint::for_vault(&path).unwrap();
        let sync = Endpoint::for_sync_daemon(&path).unwrap();
        assert_eq!(vault.id(), sync.id());
        assert_ne!(vault, sync);
        assert_eq!((vault.service(), sync.service()), ("vaultd", "syncd"));
        assert_eq!(vault.sandbox(), Some(DAEMON_SANDBOX));
        assert_eq!(sync.sandbox(), None);
    }

    #[test]
    fn a_relative_path_is_resolved_against_the_current_directory() {
        let relative = Endpoint::for_vault(Path::new("some.zpvault")).unwrap();
        let absolute =
            Endpoint::for_vault(&std::env::current_dir().unwrap().join("some.zpvault")).unwrap();
        assert_eq!(relative, absolute);
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_are_compared_without_case() {
        let lower = Endpoint::for_vault(Path::new(r"C:\Vaults\Mine.zpvault")).unwrap();
        let upper = Endpoint::for_vault(Path::new(r"c:\vaults\MINE.ZPVAULT")).unwrap();
        assert_eq!(lower, upper);
    }
}
