//! Where the daemon of a vault listens (`docs/spec/ipc.md` §2.1).

use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};

/// The IPC endpoint of the daemon that serves one vault file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    id: String,
}

impl Endpoint {
    /// The endpoint of the daemon for the vault file at `vault`. The file does
    /// not need to exist.
    pub fn for_vault(vault: &Path) -> io::Result<Self> {
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
        Ok(Self { id })
    }

    /// The identifier derived from the vault path: 16 hexadecimal digits.
    pub fn id(&self) -> &str {
        &self.id
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
