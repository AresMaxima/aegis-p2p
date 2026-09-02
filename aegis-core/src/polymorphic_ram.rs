use rand::{rngs::OsRng, RngCore};
use libc::{mmap, mprotect, munmap, MAP_PRIVATE, MAP_ANONYMOUS, PROT_READ, PROT_WRITE, PROT_NONE};
use std::ptr;

const PAGE_SIZE: usize = 4096;
const BUFFER_SIZE: usize = PAGE_SIZE * 4; // Tampon surdimensionné de 16 Ko

pub struct PolymorphicKeyBuffer {
    base_ptr: *mut u8,
    key_offset: usize,
}

impl PolymorphicKeyBuffer {
    /// Alloue un tampon anonyme de 16 Ko, le remplit de canaris cryptographiques,
    /// insère la clé à un offset aléatoire et active des pages de garde (PROT_NONE).
    pub fn new(key: &[u8; 32]) -> Self {
        unsafe {
            // 1. Allocation mémoire anonyme isolée
            let ptr = mmap(
                ptr::null_mut(),
                BUFFER_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut u8;

            if ptr.is_null() || ptr == libc::MAP_FAILED as *mut u8 {
                panic!("Échec d'allocation mmap pour le tampon polymorphe");
            }

            // 2. Remplissage intégral avec du bruit aléatoire (Canaris anti-bit-flip)
            let mut rng = OsRng;
            let slice = std::slice::from_raw_parts_mut(ptr, BUFFER_SIZE);
            rng.fill_bytes(slice);

            // 3. Calcul de l'offset aléatoire (entre la page de garde initiale et finale)
            let min_offset = PAGE_SIZE;
            let max_offset = BUFFER_SIZE - PAGE_SIZE - 64;
            let key_offset = min_offset + (rng.next_u32() as usize % (max_offset - min_offset));

            // 4. Copie de la clé dans l'emplacement polymorphe imprévisible
            ptr::copy_nonoverlapping(key.as_ptr(), ptr.add(key_offset), 32);

            // 5. Positionnement des pages de garde aux extrémités (Provoque un SIGSEGV sur accès OOB)
            mprotect(ptr as *mut libc::c_void, PAGE_SIZE, PROT_NONE);
            mprotect(ptr.add(BUFFER_SIZE - PAGE_SIZE) as *mut libc::c_void, PAGE_SIZE, PROT_NONE);

            PolymorphicKeyBuffer {
                base_ptr: ptr,
                key_offset,
            }
        }
    }

    /// Extrait la clé temporairement pour une opération cryptographique
    pub fn read_key(&self, dest: &mut [u8; 32]) {
        unsafe {
            ptr::copy_nonoverlapping(self.base_ptr.add(self.key_offset), dest.as_mut_ptr(), 32);
        }
    }
}

impl Drop for PolymorphicKeyBuffer {
    fn drop(&mut self) {
        unsafe {
            // Rétablissement des droits en écriture pour zéroïsation intégrale avant libération
            mprotect(self.base_ptr as *mut libc::c_void, BUFFER_SIZE, PROT_READ | PROT_WRITE);
            ptr::write_bytes(self.base_ptr, 0, BUFFER_SIZE);
            munmap(self.base_ptr as *mut libc::c_void, BUFFER_SIZE);
        }
    }
}
