use std::alloc::{alloc, dealloc, Layout};
use zeroize::{Zeroize, Zeroizing};

pub const CANARY_MAGIC: u64 = 0xDEADBEEFCAFEBABE;

// ============================================================================
// 1. TAMPON POLYMORPHE CLASSIQUE (MASQUAGE VOLATIL EN RAM)
// ============================================================================

#[derive(Clone, Debug)]
pub struct PolymorphicBuffer {
    data: Vec<u8>,
    mask: u8,
}

impl PolymorphicBuffer {
    pub fn new(data: &[u8]) -> Self {
        let mask = 0xAA;
        let masked_data = data.iter().map(|b| b ^ mask).collect();
        Self {
            data: masked_data,
            mask,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data)
    }

    pub fn read(&self) -> Vec<u8> {
        self.data.iter().map(|b| b ^ self.mask).collect()
    }

    pub fn mutate_mask(&mut self, new_mask: u8) {
        for b in self.data.iter_mut() {
            *b ^= self.mask ^ new_mask;
        }
        self.mask = new_mask;
    }

    pub fn read_and_mutate(&mut self) -> Zeroizing<Vec<u8>> {
        let res = self.read();
        self.mutate_mask(self.mask.wrapping_add(0x1F));
        Zeroizing::new(res)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for PolymorphicBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

// ============================================================================
// 2. TAMPON DUAL-RAIL ANTI-ROWHAMMER (PARITÉ ECC LOGIQUE & DÉPÔTS DISTANTS)
// ============================================================================

pub struct DualRailBuffer {
    base_p: *mut u8,
    ptr_p: *mut u8,
    base_p_prime: *mut u8,
    ptr_p_prime: *mut u8,
    key_poly: [u8; 512],
    layout: Layout,
    total_size: usize,
}

unsafe impl Send for DualRailBuffer {}
unsafe impl Sync for DualRailBuffer {}

impl DualRailBuffer {
    pub fn new(initial_data: &[u8; 512], entropy_key: [u8; 512]) -> Result<Self, String> {
        let page_size = 4096;
        let total_size = page_size * 3; // Page Garde Amont (4K) + Données (4K) + Page Garde Aval (4K)

        let layout = Layout::from_size_align(total_size, page_size)
            .map_err(|e| format!("Erreur de layout mémoire: {}", e))?;

        unsafe {
            let base_p = alloc(layout);
            let base_p_prime = alloc(layout);

            if base_p.is_null() || base_p_prime.is_null() {
                if !base_p.is_null() {
                    dealloc(base_p, layout);
                }
                if !base_p_prime.is_null() {
                    dealloc(base_p_prime, layout);
                }
                return Err("Échec d'allocation mémoire alignée Dual-Rail".to_string());
            }

            let ptr_p = base_p.add(page_size);
            let ptr_p_prime = base_p_prime.add(page_size);

            #[cfg(unix)]
            {
                // Isoler la plage P avec pages de garde PROT_NONE
                libc::mprotect(base_p as *mut libc::c_void, page_size, libc::PROT_NONE);
                libc::mprotect(
                    base_p.add(page_size * 2) as *mut libc::c_void,
                    page_size,
                    libc::PROT_NONE,
                );

                // Isoler la plage P' avec pages de garde PROT_NONE
                libc::mprotect(base_p_prime as *mut libc::c_void, page_size, libc::PROT_NONE);
                libc::mprotect(
                    base_p_prime.add(page_size * 2) as *mut libc::c_void,
                    page_size,
                    libc::PROT_NONE,
                );
            }

            // Écriture de P et P' = P ⊕ K_poly
            for i in 0..512 {
                *ptr_p.add(i) = initial_data[i];
                *ptr_p_prime.add(i) = initial_data[i] ^ entropy_key[i];
            }

            Ok(Self {
                base_p,
                ptr_p,
                base_p_prime,
                ptr_p_prime,
                key_poly: entropy_key,
                layout,
                total_size,
            })
        }
    }

#[inline(always)]
    pub fn verify_and_extract(&self, output: &mut [u8; 512]) -> Result<(), String> {
        unsafe {
            let mut corruption_detected = false;

            for i in 0..512 {
                let val_p = *self.ptr_p.add(i);
                let val_p_prime = *self.ptr_p_prime.add(i);

                // Contrôle de parité ECC : P ⊕ P' == K_poly
                if (val_p ^ val_p_prime) != self.key_poly[i] {
                    corruption_detected = true;
                    break;
                }
                output[i] = val_p;
            }

            if corruption_detected {
                eprintln!("[AEGIS-DUAL-RAIL-CRITICAL] Corruption mémoire Rowhammer détectée !");
                
                #[cfg(unix)]
                libc::syscall(libc::SYS_exit_group, 137);

                #[cfg(not(unix))]
                std::process::exit(137);
            }
        }
        Ok(())
    }
}

impl Drop for DualRailBuffer {
    fn drop(&mut self) {
        unsafe {
            self.key_poly.zeroize();

            #[cfg(unix)]
            {
                libc::mprotect(
                    self.base_p as *mut libc::c_void,
                    self.total_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
                libc::mprotect(
                    self.base_p_prime as *mut libc::c_void,
                    self.total_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }

            libc::memset(self.ptr_p as *mut libc::c_void, 0, 512);
            libc::memset(self.ptr_p_prime as *mut libc::c_void, 0, 512);

            dealloc(self.base_p, self.layout);
            dealloc(self.base_p_prime, self.layout);
        }
    }
}

// ============================================================================
// 3. TAMPON AVEC PAGES DE GARDE MMU (PROT_NONE)
// ============================================================================

pub struct GuardedPolymorphicBuffer {
    base_ptr: *mut u8,
    raw_ptr: *mut u8,
    total_size: usize,
    data_len: usize,
    layout: Layout,
}

unsafe impl Send for GuardedPolymorphicBuffer {}
unsafe impl Sync for GuardedPolymorphicBuffer {}

impl GuardedPolymorphicBuffer {
    pub fn new(data_len: usize) -> Result<Self, ()> {
        let page_size = 4096;
        let data_pages = (data_len + page_size - 1) / page_size;
        let data_padded_size = data_pages * page_size;
        let total_size = page_size + data_padded_size + page_size;

        let layout = Layout::from_size_align(total_size, page_size).map_err(|_| ())?;

        unsafe {
            let base_ptr = alloc(layout);
            if base_ptr.is_null() {
                return Err(());
            }

            let raw_ptr = base_ptr.add(page_size);

            #[cfg(unix)]
            {
                // Page de garde amont
                libc::mprotect(base_ptr as *mut libc::c_void, page_size, libc::PROT_NONE);
                
                // Page de garde aval
                libc::mprotect(
                    base_ptr.add(page_size + data_padded_size) as *mut libc::c_void,
                    page_size,
                    libc::PROT_NONE,
                );
                
                // Zone de données RW
                libc::mprotect(
                    raw_ptr as *mut libc::c_void,
                    data_padded_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }

            Ok(Self {
                base_ptr,
                raw_ptr,
                total_size,
                data_len,
                layout,
            })
        }
    }

    pub fn write_data(&mut self, data: &[u8]) -> Result<(), ()> {
        if data.len() > self.data_len {
            return Err(());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.raw_ptr, data.len());
        }
        Ok(())
    }
}

impl Drop for GuardedPolymorphicBuffer {
    fn drop(&mut self) {
        unsafe {
            #[cfg(unix)]
            libc::mprotect(
                self.base_ptr as *mut libc::c_void,
                self.total_size,
                libc::PROT_READ | libc::PROT_WRITE,
            );

            let slice = std::slice::from_raw_parts_mut(self.base_ptr, self.total_size);
            slice.zeroize();
            dealloc(self.base_ptr, self.layout);
        }
    }
}

// ============================================================================
// 4. SUITE DE TESTS UNITAIRES ET NON-RÉGRESSION
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymorphic_buffer_mutate_mask() {
        let mut buf = PolymorphicBuffer::new(b"0123456789abcdef");
        buf.mutate_mask(0x55);
        assert_eq!(buf.read().len(), 16);
    }

    #[test]
    fn test_polymorphic_buffer_read_and_mutate() {
        let mut buf = PolymorphicBuffer::from_slice(b"hello world");
        assert_eq!(buf.read(), b"hello world");
        assert_eq!(*buf.read_and_mutate(), b"hello world"[..]);
    }

    #[test]
    fn test_dual_rail_buffer_integrity() {
        let payload = [0x42u8; 512];
        let key = [0xAAu8; 512];

        let dual_buf = DualRailBuffer::new(&payload, key).unwrap();
        let mut extracted = [0u8; 512];
        assert!(dual_buf.verify_and_extract(&mut extracted).is_ok());
        assert_eq!(extracted, payload);
    }

    #[test]
    fn test_guarded_polymorphic_buffer_allocation() {
        let mut guarded = GuardedPolymorphicBuffer::new(512).unwrap();
        assert!(guarded.write_data(&[0x13; 512]).is_ok());
    }
}