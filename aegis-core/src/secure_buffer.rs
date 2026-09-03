//! aegis-core/src/secure_buffer.rs
//! Allocation RAM SÃ©curisÃ©e avec mlock/VirtualLock, registre atomique de purge d'urgence,
//! madvise DONTDUMP / WIPEONFORK et SlidingWindowBuffer (CdCM v2.2-RC1).

#[cfg(unix)]
use libc::{madvise, mlock, munlock, sysconf, MADV_DONTDUMP, _SC_PAGESIZE};

#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroize;

use crate::ffi_security;

const MAX_TRACKED_BUFFERS: usize = 256;

static TRACKED_PTRS: [AtomicUsize; MAX_TRACKED_BUFFERS] =
    [const { AtomicUsize::new(0) }; MAX_TRACKED_BUFFERS];
static TRACKED_LENS: [AtomicUsize; MAX_TRACKED_BUFFERS] =
    [const { AtomicUsize::new(0) }; MAX_TRACKED_BUFFERS];

fn atomic_register(ptr: *mut u8, len: usize) -> Option<usize> {
    let addr = ptr as usize;
    if addr == 0 {
        return None;
    }
    for i in 0..MAX_TRACKED_BUFFERS {
        if TRACKED_PTRS[i]
            .compare_exchange(0, addr, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            TRACKED_LENS[i].store(len, Ordering::SeqCst);
            return Some(i);
        }
    }
    None
}

fn atomic_unregister(ptr: *mut u8) {
    let addr = ptr as usize;
    for i in 0..MAX_TRACKED_BUFFERS {
        if TRACKED_PTRS[i].load(Ordering::Relaxed) == addr {
            TRACKED_LENS[i].store(0, Ordering::SeqCst);
            TRACKED_PTRS[i].store(0, Ordering::SeqCst);
            return;
        }
    }
}

/// # Safety
///
/// Cette fonction parcourt l'ensemble des tampons actifs enregistrÃ©s dans le registre atomique
/// et exÃ©cute un nettoyage volatil immÃ©diat (`zeroize`) en mÃ©moire vive.
/// L'appelant doit s'assurer que les pointeurs stockÃ©s restent valides au moment du balayage.
pub unsafe fn global_wipe_all_buffers() {
    for i in 0..MAX_TRACKED_BUFFERS {
        let addr = TRACKED_PTRS[i].load(Ordering::SeqCst);
        let len = TRACKED_LENS[i].load(Ordering::SeqCst);
        if addr != 0 && len > 0 {
            let ptr = addr as *mut u8;
            slice::from_raw_parts_mut(ptr, len).zeroize();
        }
    }
}

pub fn init_secure_buffer_system() {
    ffi_security::register_zeroize_callback(global_wipe_all_buffers);
}

pub struct SecureBuffer {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
    #[allow(dead_code)]
    tracked_index: Option<usize>,
    locked: bool,
}

unsafe impl Send for SecureBuffer {}
unsafe impl Sync for SecureBuffer {}

impl SecureBuffer {
    pub fn new(len: usize) -> Self {
        assert!(len > 0, "Buffer size must be greater than zero");

        let align = 64; // Alignement fixe 64 octets (compatible SIMD/AVX/NEON)

        let layout = Layout::from_size_align(len, align)
            .or_else(|_| Layout::array::<u8>(len))
            .expect("Layout overflow");

        let ptr = unsafe {
            let raw = alloc_zeroed(layout);
            NonNull::new(raw).unwrap_or_else(|| handle_alloc_error(layout))
        };

        let mut locked = false;

        #[cfg(unix)]
        {
            let lock_res = if cfg!(miri) { 0 } else { unsafe { mlock(ptr.as_ptr() as *const libc::c_void, len) } };
            if lock_res == 0 {
                locked = true;
            }

            unsafe {
                madvise(ptr.as_ptr() as *mut libc::c_void, len, MADV_DONTDUMP);
                #[cfg(target_os = "android")]
                {
                    const MADV_WIPEONFORK: libc::c_int = 18;
                    madvise(ptr.as_ptr() as *mut libc::c_void, len, MADV_WIPEONFORK);
                }
            }
        }

        #[cfg(windows)]
        {
            let lock_res = unsafe { VirtualLock(ptr.as_ptr() as *const core::ffi::c_void, len) };
            if lock_res != 0 {
                locked = true;
            }
        }

        let tracked_index = atomic_register(ptr.as_ptr(), len);

        Self {
            ptr,
            len,
            layout,
            tracked_index,
            locked,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.len
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn clear(&mut self) {
        self.as_slice_mut().zeroize();
    }

    pub fn clone_zeroized(&self) -> Self {
        let mut new_buf = Self::new(self.len);
        new_buf.as_slice_mut().copy_from_slice(self.as_slice());
        new_buf
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_slice_mut()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        atomic_unregister(self.ptr.as_ptr());
        unsafe {
            let data = slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
            data.zeroize();

            if self.locked {
                #[cfg(unix)]
                if !cfg!(miri) { unsafe { munlock(self.ptr.as_ptr() as *const libc::c_void, self.len); } }
                #[cfg(windows)]
                VirtualUnlock(self.ptr.as_ptr() as *const core::ffi::c_void, self.len);
            }

            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

pub const RING_BUFFER_SIZE: usize = 32 * 1024 * 1024;
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

pub struct SlidingWindowBuffer {
    buffer: SecureBuffer,
    capacity: usize,
}

impl SlidingWindowBuffer {
    pub fn new() -> Self {
        Self::with_capacity(RING_BUFFER_SIZE)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: SecureBuffer::new(capacity),
            capacity,
        }
    }

    pub fn write_chunk(&mut self, offset: usize, src_chunk: &[u8]) -> Result<(), &'static str> {
        if src_chunk.len() > CHUNK_SIZE || offset.checked_add(src_chunk.len()).is_none_or(|end| end > self.capacity) {
            return Err("DÃ©passement de la capacitÃ© de fenÃªtre du buffer");
        }
        let dst = &mut self.buffer.as_slice_mut()[offset..offset + src_chunk.len()];
        dst.copy_from_slice(src_chunk);
        Ok(())
    }

    pub fn get_chunk(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end <= self.capacity {
            Some(&self.buffer.as_slice()[offset..end])
        } else {
            None
        }
    }

    pub fn clear_chunk(&mut self, offset: usize, len: usize) {
        if let Some(end) = offset.checked_add(len) {
            if end <= self.capacity {
                self.buffer.as_slice_mut()[offset..end].zeroize();
            }
        }
    }
}

impl Default for SlidingWindowBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_allocation_and_zeroize() {
        let mut buf = SecureBuffer::new(1024);
        assert_eq!(buf.len(), 1024);
        buf.as_slice_mut().fill(0xAA);
        assert_eq!(buf[0], 0xAA);
        buf.clear();
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn test_sliding_window_buffer() {
        let mut window = SlidingWindowBuffer::with_capacity(1024 * 1024);
        let chunk = vec![0x55u8; 1024];
        assert!(window.write_chunk(0, &chunk).is_ok());

        let read_chunk = window.get_chunk(0, 1024).unwrap();
        assert_eq!(read_chunk, chunk.as_slice());

        window.clear_chunk(0, 1024);
        let read_cleared = window.get_chunk(0, 1024).unwrap();
        assert_eq!(read_cleared[0], 0x00);
    }
}


#[cfg(test)]
mod cov_secbuf { use super::*; #[test] fn t() { let mut b = SecureBuffer::new(64); b.as_slice_mut().fill(0xAA); unsafe { global_wipe_all_buffers(); } let _w = SlidingWindowBuffer::new(); } }
