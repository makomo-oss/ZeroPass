//! Starts ZeroPass processes without network access.
//!
//! The vault daemon must not be able to reach the network even if it is
//! compromised (ADR-0004). The build keeps networking crates out of it; this
//! crate adds the runtime guard, by starting it in a sandbox of the operating
//! system:
//!
//! | Platform | Sandbox | Status |
//! |---|---|---|
//! | Windows | AppContainer without capabilities ([`spawn`]) | available |
//! | macOS | App Sandbox | planned (P6-09) |
//! | Linux | seccomp / Landlock | planned (P6-10) |

mod harden;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_harden;

pub use harden::{Hardening, Measure, can_read_memory_of, harden_process};

use std::ffi::OsString;
use std::io;
use std::path::Path;

/// Whether this platform has a sandbox implementation.
pub const SUPPORTED: bool = cfg!(windows);

/// A running sandboxed process.
pub struct Child {
    #[cfg(windows)]
    inner: windows::Child,
}

impl core::fmt::Debug for Child {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Child").field("id", &self.id()).finish()
    }
}

impl Child {
    /// The process identifier.
    pub fn id(&self) -> u32 {
        #[cfg(windows)]
        {
            self.inner.id()
        }
        #[cfg(not(windows))]
        {
            0
        }
    }

    /// Waits for the process to end and returns its exit code.
    pub fn wait(&self) -> io::Result<u32> {
        #[cfg(windows)]
        {
            self.inner.wait()
        }
        #[cfg(not(windows))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// The exit code if the process has ended.
    pub fn try_wait(&self) -> io::Result<Option<u32>> {
        #[cfg(windows)]
        {
            self.inner.try_wait()
        }
        #[cfg(not(windows))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// Ends the process.
    pub fn kill(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            self.inner.kill()
        }
        #[cfg(not(windows))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

/// Starts `program` in the sandbox named `container`: without network access
/// and with access only to the files granted to that sandbox. The process
/// outlives this one, has no console and inherits no handles.
pub fn spawn(container: &str, program: &Path, args: &[OsString]) -> io::Result<Child> {
    #[cfg(windows)]
    {
        windows::spawn(container, program, args).map(|inner| Child { inner })
    }
    #[cfg(not(windows))]
    {
        let _ = (container, program, args);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// What a sandbox may do with a file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read and execute a file: for the program itself.
    ReadExecute,
    /// Read, write and delete a file.
    Modify,
    /// Create files in a directory and do anything with the files created
    /// from now on. The sandbox can neither list the directory nor open the
    /// files that are already in it.
    CreateFiles,
}

/// Gives the sandbox `container` access to the file or directory at `path`.
/// A sandboxed process can open nothing that was not granted this way. Grants
/// stay until they are removed from the file; granting twice is harmless.
pub fn allow(container: &str, path: &Path, access: Access) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::allow(container, path, access)
    }
    #[cfg(not(windows))]
    {
        let _ = (container, path, access);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The identifier under which files are granted to the sandbox `container`:
/// on Windows, the SID of the AppContainer.
pub fn container_id(container: &str) -> io::Result<String> {
    #[cfg(windows)]
    {
        windows::container_sid(container)
    }
    #[cfg(not(windows))]
    {
        let _ = container;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Whether the current process runs inside a sandbox of this crate's kind.
pub fn is_sandboxed() -> bool {
    #[cfg(windows)]
    {
        windows::is_sandboxed()
    }
    #[cfg(not(windows))]
    {
        false
    }
}
