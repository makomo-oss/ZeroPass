//! Storage for 32-byte secrets: wiped on drop and, for long-lived keys, kept on a
//! dedicated page that is locked into physical memory so it cannot be swapped out.
//!
//! This is the only module in the crate that may use `unsafe`.
#![allow(unsafe_code)]

use zeroize::Zeroize;

use crate::secret::KEY_LEN;

/// A private, page-aligned allocation holding one key.
///
/// Each key gets its own page: page locks are not reference counted by the OS, so
/// sharing a page between keys would let one key's drop unlock the others.
struct Page {
    // Field order matters: the lock must be released before the memory is freed.
    lock: Option<region::LockGuard>,
    alloc: region::Allocation,
}

// SAFETY: `Page` exclusively owns its allocation; the raw pointer inside
// `region::Allocation` is never handed out, shared access only reads, and mutation
// requires `&mut self`.
unsafe impl Send for Page {}
// SAFETY: see above; `&Page` only permits reads of plain bytes.
unsafe impl Sync for Page {}

impl Page {
    fn new() -> Option<Self> {
        let alloc = region::alloc(KEY_LEN, region::Protection::READ_WRITE).ok()?;
        if alloc.len() < KEY_LEN {
            return None;
        }
        // Locking can fail (e.g. RLIMIT_MEMLOCK); the key is then merely not pinned.
        let lock = region::lock(alloc.as_ptr::<u8>(), alloc.len()).ok();
        Some(Self { lock, alloc })
    }

    fn bytes(&self) -> &[u8; KEY_LEN] {
        // SAFETY: the allocation is at least `KEY_LEN` bytes (checked in `new`),
        // readable, zero-initialised by the OS, and lives as long as `self`. A byte
        // array has alignment 1. No `&mut` to it exists while `&self` is borrowed.
        unsafe { &*self.alloc.as_ptr::<[u8; KEY_LEN]>() }
    }

    fn bytes_mut(&mut self) -> &mut [u8; KEY_LEN] {
        // SAFETY: as in `bytes`, plus the allocation is writable and `&mut self`
        // guarantees exclusive access.
        unsafe { &mut *self.alloc.as_mut_ptr::<[u8; KEY_LEN]>() }
    }
}

enum Storage {
    Page(Page),
    Heap(Box<[u8; KEY_LEN]>),
}

/// Exactly [`KEY_LEN`] secret bytes that are zeroed when dropped.
pub(crate) struct SecretBytes(Storage);

impl SecretBytes {
    /// Allocates zeroed storage. With `pinned`, a dedicated locked page is used when
    /// the OS allows it, falling back to the heap otherwise.
    pub(crate) fn zeroed(pinned: bool) -> Self {
        let page = if pinned { Page::new() } else { None };
        match page {
            Some(page) => Self(Storage::Page(page)),
            None => Self(Storage::Heap(Box::new([0u8; KEY_LEN]))),
        }
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        match &self.0 {
            Storage::Page(page) => page.bytes(),
            Storage::Heap(bytes) => bytes,
        }
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [u8; KEY_LEN] {
        match &mut self.0 {
            Storage::Page(page) => page.bytes_mut(),
            Storage::Heap(bytes) => bytes,
        }
    }

    /// Whether the bytes live on a page locked into physical memory.
    pub(crate) fn is_page_locked(&self) -> bool {
        matches!(&self.0, Storage::Page(page) if page.lock.is_some())
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.expose_mut().zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_zeroed_and_round_trips() {
        for pinned in [false, true] {
            let mut s = SecretBytes::zeroed(pinned);
            assert_eq!(s.expose(), &[0u8; KEY_LEN]);
            s.expose_mut().copy_from_slice(&[0xA5; KEY_LEN]);
            assert_eq!(s.expose(), &[0xA5; KEY_LEN]);
        }
    }

    #[test]
    fn zeroize_wipes_contents() {
        for pinned in [false, true] {
            let mut s = SecretBytes::zeroed(pinned);
            s.expose_mut().copy_from_slice(&[0x5A; KEY_LEN]);
            s.zeroize();
            assert_eq!(s.expose(), &[0u8; KEY_LEN]);
        }
    }

    #[test]
    fn pinned_storage_uses_a_dedicated_page_per_key() {
        let a = SecretBytes::zeroed(true);
        let b = SecretBytes::zeroed(true);
        if let (Storage::Page(pa), Storage::Page(pb)) = (&a.0, &b.0) {
            let (pa, pb) = (
                pa.alloc.as_ptr::<u8>() as usize,
                pb.alloc.as_ptr::<u8>() as usize,
            );
            assert_ne!(pa, pb);
            assert_eq!(pa % region::page::size(), 0);
            assert_eq!(pb % region::page::size(), 0);
        }
    }

    #[test]
    fn unpinned_storage_is_not_reported_as_locked() {
        assert!(!SecretBytes::zeroed(false).is_page_locked());
    }
}
