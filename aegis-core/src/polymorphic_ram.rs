use zeroize::Zeroizing;

pub struct PolymorphicKeyBuffer {
    ptr: *mut u8,
    alloc_size: usize,
    key_offset: usize,
    key_len: usize,
}

pub type PolymorphicBuffer = PolymorphicKeyBuffer;

unsafe impl Send for PolymorphicKeyBuffer {}
unsafe impl Sync for PolymorphicKeyBuffer {}

impl PolymorphicKeyBuffer {
    pub fn new(data: &[u8]) -> Self {
        let key_len = data.len();
        let alloc_size = key_len + 16384;
        let key_offset = 4096;

        #[cfg(unix)]
        let ptr = unsafe {
            use libc::{mmap, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
            let p = mmap(
                std::ptr::null_mut(),
                alloc_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if p.is_null() || p == MAP_FAILED {
                panic!("Échec d'allocation mémoire polymorphe");
            }
            p as *mut u8
        };

        #[cfg(not(unix))]
        let ptr = unsafe {
            let layout = std::alloc::Layout::from_size_align(alloc_size, 4096).unwrap();
            std::alloc::alloc_zeroed(layout)
        };

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.add(key_offset), key_len);
        }

        Self {
            ptr,
            alloc_size,
            key_offset,
            key_len,
        }
    }

    pub fn read_and_mutate(&mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.as_slice().to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.ptr.add(self.key_offset), self.key_len)
        }
    }
}

impl Drop for PolymorphicKeyBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                std::ptr::write_bytes(self.ptr.add(self.key_offset), 0, self.key_len);

                #[cfg(unix)]
                libc::munmap(self.ptr as *mut libc::c_void, self.alloc_size);

                #[cfg(not(unix))]
                {
                    let layout = std::alloc::Layout::from_size_align(self.alloc_size, 4096).unwrap();
                    std::alloc::dealloc(self.ptr, layout);
                }
            }
        }
    }
}
