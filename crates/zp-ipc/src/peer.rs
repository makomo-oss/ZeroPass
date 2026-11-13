//! Who is at the other end of a connection (`docs/spec/ipc.md` §3).

use std::io;
use std::path::{Path, PathBuf};

use crate::proto::Role;

/// The file name of the daemon executable, without the platform's suffix.
pub const DAEMON_NAME: &str = "zp-vaultd";

/// The executables that may connect when installed beside the daemon, and the
/// role each one gets.
const CLIENTS: [(&str, Role); 5] = [
    ("zp-cli", Role::Ui),
    ("zeropass", Role::Ui),
    ("zp-nmh", Role::Bridge),
    ("zp-broker", Role::Broker),
    ("zp-syncd", Role::Sync),
];

/// What the operating system reports about the process at the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProcess {
    /// The process identifier, where the platform reports one.
    pub pid: Option<u32>,
    /// The full path of the executable, where the platform reports one.
    pub executable: Option<PathBuf>,
}

/// An accepted client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The process at the other end.
    pub process: PeerProcess,
    /// What the client may do.
    pub role: Role,
}

/// Brings a path into the form paths are compared in: without the verbatim
/// prefix and, on Windows, in lower case.
fn normalize(path: &Path) -> PathBuf {
    if cfg!(windows) {
        let text = path.to_string_lossy().replace('/', "\\").to_lowercase();
        let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
        PathBuf::from(text)
    } else {
        path.to_path_buf()
    }
}

fn executable_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn current_exe_dir() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("the current executable has no directory"))
}

/// The daemon's list of executables that may connect.
#[derive(Debug, Clone, Default)]
pub struct ClientPolicy {
    entries: Vec<(PathBuf, Role)>,
}

impl ClientPolicy {
    /// A policy that admits nothing.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// The default policy: the ZeroPass executables in `dir`.
    pub fn installed_in(dir: &Path) -> Self {
        CLIENTS
            .iter()
            .fold(Self::default(), |policy, (name, role)| {
                policy.allow(dir.join(executable_name(name)), *role)
            })
    }

    /// The default policy for the directory of the running executable.
    pub fn beside_current_exe() -> io::Result<Self> {
        Ok(Self::installed_in(&current_exe_dir()?))
    }

    /// Also admits the executable at `path` with `role`.
    #[must_use]
    pub fn allow(mut self, path: impl AsRef<Path>, role: Role) -> Self {
        self.entries.push((normalize(path.as_ref()), role));
        self
    }

    /// The role of a connecting process, or `None` if it is not admitted.
    pub fn admit(&self, process: &PeerProcess) -> Option<Role> {
        if !crate::sys::IDENTIFIES_PEERS {
            // docs/spec/ipc.md §3.3: the platform only guarantees the same user.
            return Some(Role::Ui);
        }
        let executable = normalize(process.executable.as_deref()?);
        self.entries
            .iter()
            .find(|(path, _)| *path == executable)
            .map(|(_, role)| *role)
    }
}

/// A client's list of executables it accepts as the daemon.
#[derive(Debug, Clone, Default)]
pub struct DaemonPolicy {
    executables: Vec<PathBuf>,
}

impl DaemonPolicy {
    /// The default policy: the daemon executable in `dir`.
    pub fn installed_in(dir: &Path) -> Self {
        Self::default().allow(dir.join(executable_name(DAEMON_NAME)))
    }

    /// The default policy for the directory of the running executable.
    pub fn beside_current_exe() -> io::Result<Self> {
        Ok(Self::installed_in(&current_exe_dir()?))
    }

    /// Also accepts the executable at `path` as the daemon.
    #[must_use]
    pub fn allow(mut self, path: impl AsRef<Path>) -> Self {
        self.executables.push(normalize(path.as_ref()));
        self
    }

    /// Whether the process serving the endpoint is an accepted daemon.
    pub fn accepts(&self, process: &PeerProcess) -> bool {
        if !crate::sys::IDENTIFIES_PEERS {
            return true;
        }
        process
            .executable
            .as_deref()
            .map(normalize)
            .is_some_and(|executable| self.executables.contains(&executable))
    }
}

// Where the platform does not identify peers, the policies admit everything
// (docs/spec/ipc.md §3.3) and there is nothing to test here.
#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;

    fn process(path: &Path) -> PeerProcess {
        PeerProcess {
            pid: Some(1),
            executable: Some(path.to_path_buf()),
        }
    }

    #[test]
    fn only_listed_executables_are_admitted() {
        let dir = std::env::temp_dir().join("zeropass-install");
        let policy = ClientPolicy::installed_in(&dir);
        let exe = |name: &str| dir.join(executable_name(name));
        assert_eq!(policy.admit(&process(&exe("zp-cli"))), Some(Role::Ui));
        assert_eq!(policy.admit(&process(&exe("zp-nmh"))), Some(Role::Bridge));
        assert_eq!(
            policy.admit(&process(&exe("zp-broker"))),
            Some(Role::Broker)
        );
        assert_eq!(policy.admit(&process(&exe("zp-syncd"))), Some(Role::Sync));
        // The daemon itself, another name, the right name in another directory,
        // and a process whose executable is unknown.
        assert_eq!(policy.admit(&process(&exe(DAEMON_NAME))), None);
        assert_eq!(policy.admit(&process(&exe("malware"))), None);
        let elsewhere = dir.join("sub").join(executable_name("zp-cli"));
        assert_eq!(policy.admit(&process(&elsewhere)), None);
        let unknown = PeerProcess {
            pid: Some(1),
            executable: None,
        };
        assert_eq!(policy.admit(&unknown), None);
        assert_eq!(
            ClientPolicy::deny_all().admit(&process(&exe("zp-cli"))),
            None
        );
    }

    #[test]
    fn only_the_daemon_executable_is_accepted_as_the_daemon() {
        let dir = std::env::temp_dir().join("zeropass-install");
        let policy = DaemonPolicy::installed_in(&dir);
        assert!(policy.accepts(&process(&dir.join(executable_name(DAEMON_NAME)))));
        assert!(!policy.accepts(&process(&dir.join(executable_name("zp-cli")))));
        assert!(!policy.accepts(&PeerProcess {
            pid: None,
            executable: None
        }));
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_match_without_case_or_verbatim_prefix() {
        let policy =
            ClientPolicy::deny_all().allow(r"C:\Program Files\ZeroPass\zp-cli.exe", Role::Ui);
        for spelling in [
            r"c:\program files\zeropass\ZP-CLI.EXE",
            r"\\?\C:\Program Files\ZeroPass\zp-cli.exe",
            "C:/Program Files/ZeroPass/zp-cli.exe",
        ] {
            assert_eq!(
                policy.admit(&process(Path::new(spelling))),
                Some(Role::Ui),
                "{spelling}"
            );
        }
    }
}
