//! Time sources. The hybrid logical clock that stamps item versions lives in
//! `zp_sync::hlc`.

use core::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock time in milliseconds since the Unix epoch.
///
/// Injectable so that tests can control time; production code uses
/// [`Clock::system`].
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl Clock {
    /// The operating system clock.
    pub fn system() -> Self {
        Self::from_fn(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
                })
        })
    }

    /// A clock backed by an arbitrary function.
    pub fn from_fn(now_ms: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(now_ms))
    }

    /// The current time in milliseconds since the Unix epoch.
    pub fn now_ms(&self) -> u64 {
        (self.0)()
    }
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Clock")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[test]
    fn clocks_can_be_injected() {
        let now = Arc::new(AtomicU64::new(42));
        let source = Arc::clone(&now);
        let clock = Clock::from_fn(move || source.load(Ordering::SeqCst));
        assert_eq!(clock.now_ms(), 42);
        now.store(43, Ordering::SeqCst);
        assert_eq!(clock.clone().now_ms(), 43);
        assert!(Clock::system().now_ms() > 1_700_000_000_000);
    }
}
