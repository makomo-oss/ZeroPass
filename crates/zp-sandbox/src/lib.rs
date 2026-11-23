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
//! | macOS | App Sandbox | on hold (P6-09) |
//! | Linux | seccomp and Landlock, applied by the program itself ([`spawn`], [`enter_requested`]) | available |

mod harden;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_harden;
#[cfg(all(windows, feature = "probe"))]
mod windows_probe;

/// Whether `needle` occurs in the memory of the process `pid`. `None` where
/// this is not implemented.
///
/// For tests that check where key material is and is not. It does what any
/// program of the same user can do, including to a process that hardened
/// itself (`docs/spec/hardening.md` §3).
#[cfg(feature = "probe")]
pub fn memory_contains(pid: u32, needle: &[u8]) -> Option<std::io::Result<bool>> {
    #[cfg(windows)]
    {
        Some(windows_probe::memory_contains(pid, needle))
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, needle);
        None
    }
}

pub use harden::{
    Hardening, Measure, can_duplicate_handles_of, can_read_memory_of, harden_network_process,
    harden_process, harden_worker_process, runs_as_administrator,
};

use std::ffi::OsString;
use std::io;
use std::path::Path;

/// Whether this platform has a sandbox implementation.
pub const SUPPORTED: bool = cfg!(any(windows, target_os = "linux"));

/// A running sandboxed process.
pub struct Child {
    #[cfg(windows)]
    inner: windows::Child,
    #[cfg(target_os = "linux")]
    inner: linux::Child,
}

impl core::fmt::Debug for Child {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Child").field("id", &self.id()).finish()
    }
}

impl Child {
    /// The process identifier.
    pub fn id(&self) -> u32 {
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.id()
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            0
        }
    }

    /// Waits for the process to end and returns its exit code.
    pub fn wait(&self) -> io::Result<u32> {
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.wait()
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// The exit code if the process has ended.
    pub fn try_wait(&self) -> io::Result<Option<u32>> {
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.try_wait()
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// Ends the process.
    pub fn kill(&self) -> io::Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        {
            self.inner.kill()
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

/// Starts `program` in the sandbox named `container`: without network access
/// and with access only to the files granted to that sandbox. The process
/// outlives this one, has no console and inherits no handles.
///
/// On Linux the program restricts itself: it must call [`enter_requested`]
/// before it reads anything from outside.
pub fn spawn(container: &str, program: &Path, args: &[OsString]) -> io::Result<Child> {
    #[cfg(windows)]
    {
        windows::spawn(container, program, args).map(|inner| Child { inner })
    }
    #[cfg(target_os = "linux")]
    {
        linux::spawn(container, program, args).map(|inner| Child { inner })
    }
    #[cfg(not(any(windows, target_os = "linux")))]
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
/// A sandboxed process can open nothing that was not granted this way, apart
/// from the system's libraries. On Windows grants stay until they are removed
/// from the file; on Linux they hold for the programs this process starts.
/// Granting twice is harmless.
///
/// On Linux a directory granted with [`Access::CreateFiles`] is open in full:
/// Landlock cannot tell the files a process makes from the others there.
pub fn allow(container: &str, path: &Path, access: Access) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::allow(container, path, access)
    }
    #[cfg(target_os = "linux")]
    {
        linux::allow(container, path, access)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
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
    #[cfg(target_os = "linux")]
    {
        Ok(container.to_owned())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
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
    #[cfg(target_os = "linux")]
    {
        linux::is_sandboxed()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

/// Whether this process was started by [`spawn`] to restrict itself (Linux):
/// [`enter_requested`] will restrict it.
pub fn is_requested() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::is_requested()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// On Linux, if this process was started by [`spawn`]: restricts it to what
/// it was granted, and to `extra` (what only the program knows, such as the
/// directory of its IPC endpoint), and denies it the network. Call it first
/// thing, before any thread is started and anything is read from outside.
///
/// Returns `None` if nothing was asked (not started by [`spawn`], or not
/// Linux), and otherwise whether the files are limited too (the kernel has
/// Landlock). The network is always denied once this returns `Some`.
pub fn enter_requested(extra: &[(&Path, Access)]) -> io::Result<Option<bool>> {
    #[cfg(target_os = "linux")]
    {
        linux::enter_requested(extra)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = extra;
        Ok(None)
    }
}
