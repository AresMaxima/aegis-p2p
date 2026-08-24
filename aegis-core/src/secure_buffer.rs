//! aegis-core/src/secure_buffer.rs
//! Allocation de mémoire verrouillée et isolée (Anti-Swap & Anti-Dump)

#[cfg(unix)]
use libc::{mlock, munlock, sysconf, _SC_PAGESIZE};

#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::slice;
use zeroize::Zeroize;

pub struct SecureBuffer {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
}

// Safety: SecureBuffer possède exclusivement son pointeur sous-jacent.
unsafe impl Send for SecureBuffer {}
unsafe impl Sync for SecureBuffer {}

impl SecureBuffer {
    pub fn new(len: usize) -> Self {
        assert!(len > 0, "Buffer size must be greater than zero");

        // Récupération de la taille de la page OS
        #[cfg(unix)]
        let page_size = unsafe { sysconf(_SC_PAGESIZE) };
        #[cfg(windows)]
        let page_size = 4096; // Fallback sécurisé par défaut sur Windows

        let align = if page_size > 0 && (page_size as usize).is_power_of_two() {
            page_size as usize
        } else {
            4096 // Fallback sécurisé standard (4 KiB)
        };

        let layout = Layout::from_size_align(len, align)
            .or_else(|_| Layout::array::<u8>(len))
            .expect("Layout overflow");

        let ptr = unsafe {
            let raw = alloc_zeroed(layout);
            NonNull::new(raw).unwrap_or_else(|| handle_alloc_error(layout))
        };

        // OPSEC CRITIQUE : Verrouillage mémoire strict (Anti-Swap) avec Zeroize pré-crash
        #[cfg(unix)]
        {
            let lock_res = unsafe { mlock(ptr.as_ptr() as *const libc::c_void, len) };
            if lock_res != 0 {
                unsafe {
                    slice::from_raw_parts_mut(ptr.as_ptr(), len).zeroize();
                    dealloc(ptr.as_ptr(), layout);
                }
                panic!("CRITICAL OPSEC FAILURE: mlock() failed. Memory could be swapped to disk.");
            }
        }

        #[cfg(windows)]
        {
            let lock_res = unsafe { VirtualLock(ptr.as_ptr() as *const core::ffi::c_void, len) };
            if lock_res == 0 {
                unsafe {
                    slice::from_raw_parts_mut(ptr.as_ptr(), len).zeroize();
                    dealloc(ptr.as_ptr(), layout);
                }
                panic!("CRITICAL OPSEC FAILURE: VirtualLock() failed.");
            }
        }

        Self { ptr, len, layout }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        unsafe {
            // 1. Zéroisation immédiate et déterministe
            let data = slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
            data.zeroize();

            // 2. Déverrouillage de la RAM OS
            #[cfg(unix)]
            munlock(self.ptr.as_ptr() as *const libc::c_void, self.len);
            
            #[cfg(windows)]
            VirtualUnlock(self.ptr.as_ptr() as *const core::ffi::c_void, self.len);

            // 3. Libération de l'allocation
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}