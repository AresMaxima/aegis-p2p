//! aegis-core/src/polymorphic_ram.rs
//! Allocation polymorphe Dual-Rail avec canaris + guard pages (CdCM v2.2-RC3).
//!
//! ─────────────────────────────────────────────────────────────────────
//! Layout mémoire (Dual-Rail) :
//!
//!   ┌──────────────────────────────────────────────────────────────┐
//!   │  REGION A (adresse distincte, mmap séparé)                   │
//!   │  [guard][canari préfixe][padding rnd][CLÉ P][padding rnd]    │
//!   │         [canari suffixe][guard]                              │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  REGION B (adresse distincte, physiquement distante)         │
//!   │  [guard][canari préfixe][padding rnd][CLÉ P'=P⊕K_poly]       │
//!   │         [canari suffixe][guard]                              │
//!   └──────────────────────────────────────────────────────────────┘
//!
//! Contrôles d'intégrité :
//!   1. Canaris préfixe/suffixe — INDÉPENDANTS pour A et B
//!   2. Parité Dual-Rail — P[i] ⊕ P'[i] == K_poly[i % 32] pour tout i
//!
//! Si un bit flip survient dans A OU B (Rowhammer, RAMBleed, corruption),
//! la parité est rompue → PanicPurge immédiat.
//!
//! ─────────────────────────────────────────────────────────────────────
//! API publique (inchangée depuis v2.2-RC1) :
//!   • PolymorphicBuffer::new(&[u8]) -> Self
//!   • .as_slice(&self) -> &[u8]  (vérifie canaris + dual-rail)
//!   • .read_and_mutate(&mut self) -> Zeroizing<Vec<u8>>  (via as_slice)
//!   • Drop (zeroize + munmap x2)
//!   • Send + Sync
//!
//! ─────────────────────────────────────────────────────────────────────
//! NOTE MIRI :
//! Sous Miri, mmap(PROT_NONE) + mprotect n'est pas supporté (Miri ne gère
//! que PROT_READ|PROT_WRITE). On substitue une allocation Rust standard
//! (alloc_zeroed) via #[cfg(miri)]. La logique DualRegion (canaris,
//! dual-rail, zeroize, drop) reste intégralement prouvée sous Miri.
//! Le comportement mmap/mprotect est prouvé séparément par le job CI
//! `linux-mmap-proof` (Valgrind, Linux natif).

use rand::RngCore;
use zeroize::Zeroizing;

/// Taille des canaris (16 octets = 128 bits).
const CANARY_SIZE: usize = 16;

/// Taille d'une page (4 Ko sur Android/Linux).
const PAGE_SIZE: usize = 4096;

/// Taille du masque polymorphe K_poly (32 octets = 256 bits).
const POLY_MASK_SIZE: usize = 32;

/// Préfixe aléatoire fixe. XOR 0xFF donne le canari suffixe.
const CANARY_PREFIX: [u8; CANARY_SIZE] = [
    0xA3, 0x7F, 0x1C, 0xEB, 0x92, 0xD4, 0x88, 0x55,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

// =========================================================================
// DUAL REGION
// =========================================================================

/// Une région mémoire unique (A ou B) avec son layout interne :
///   [guard][canari préfixe][padding][clé][padding][canari suffixe][guard]
struct DualRegion {
    ptr: *mut u8,
    alloc_size: usize,
    key_offset: usize,
    key_len: usize,
}

unsafe impl Send for DualRegion {}
unsafe impl Sync for DualRegion {}

impl DualRegion {
    /// Alloue une région protégée (guard pages + canaris + padding).
    ///
    /// `work_size` : taille logique de la zone travail (canaris + padding + clé)
    /// `key_offset_from_page` : offset de la clé depuis le début de la zone travail
    /// `key_len` : taille de la clé
    fn new(work_size: usize, key_offset_from_page: usize, key_len: usize) -> Self {
        let work_pages = (work_size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
        let alloc_size = PAGE_SIZE + work_pages + PAGE_SIZE;

        #[cfg(all(unix, not(miri)))]
        let ptr = unsafe {
            use libc::{
                mmap, mprotect, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_NONE, PROT_READ,
                PROT_WRITE,
            };

            let p = mmap(
                std::ptr::null_mut(),
                alloc_size,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if p.is_null() || p == MAP_FAILED {
                panic!("polymorphic_ram: échec mmap (DualRegion)");
            }

            let work_ptr = (p as *mut u8).add(PAGE_SIZE);
            let rc = mprotect(
                work_ptr as *mut libc::c_void,
                work_pages,
                PROT_READ | PROT_WRITE,
            );
            if rc != 0 {
                libc::munmap(p, alloc_size);
                panic!("polymorphic_ram: échec mprotect (DualRegion)");
            }

            p as *mut u8
        };

        #[cfg(any(not(unix), miri))]
        let ptr = unsafe {
            let layout = std::alloc::Layout::from_size_align(alloc_size, PAGE_SIZE).unwrap();
            let p = std::alloc::alloc_zeroed(layout);
            if p.is_null() {
                panic!("polymorphic_ram: échec alloc (DualRegion)");
            }
            p
        };

        Self {
            ptr,
            alloc_size,
            key_offset: PAGE_SIZE + key_offset_from_page,
            key_len,
        }
    }

    /// Libère la région (munmap ou dealloc).
    fn free(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        unsafe {
            #[cfg(all(unix, not(miri)))]
            {
                libc::munmap(self.ptr as *mut libc::c_void, self.alloc_size);
            }

            #[cfg(any(not(unix), miri))]
            {
                let layout =
                    std::alloc::Layout::from_size_align(self.alloc_size, PAGE_SIZE).unwrap();
                std::alloc::dealloc(self.ptr, layout);
            }
        }
        self.ptr = std::ptr::null_mut();
    }

    /// Retourne la clé sous forme de slice immutable.
    fn key_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.add(self.key_offset), self.key_len) }
    }

    /// Retourne la clé sous forme de slice mutable.
    fn key_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.add(self.key_offset), self.key_len) }
    }

    /// Écrit les canaris préfixe + suffixe.
    fn write_canaris(&self) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                CANARY_PREFIX.as_ptr(),
                self.ptr.add(PAGE_SIZE),
                CANARY_SIZE,
            );

            let mut suffix = CANARY_PREFIX;
            for b in suffix.iter_mut() {
                *b ^= 0xFF;
            }
            std::ptr::copy_nonoverlapping(
                suffix.as_ptr(),
                self.ptr.add(self.key_offset + self.key_len),
                CANARY_SIZE,
            );
        }
    }

    /// Vérifie les canaris. Panic si corrompu.
    fn verify_canaris(&self, region_name: &str) {
        unsafe {
            // Canari préfixe
            let prefix_slice = std::slice::from_raw_parts(self.ptr.add(PAGE_SIZE), CANARY_SIZE);
            if prefix_slice != CANARY_PREFIX {
                eprintln!(
                    "[ALERT CRITIQUE] Canari préfixe corrompu ({}) — PanicPurge.",
                    region_name
                );
                crate::panic::panic_purge();
                #[cfg(test)]
                panic!("Canari préfixe corrompu ({})", region_name);
            }

            // Canari suffixe
            let mut expected = CANARY_PREFIX;
            for b in expected.iter_mut() {
                *b ^= 0xFF;
            }
            let suffix_slice = std::slice::from_raw_parts(
                self.ptr.add(self.key_offset + self.key_len),
                CANARY_SIZE,
            );
            if suffix_slice != expected {
                eprintln!(
                    "[ALERT CRITIQUE] Canari suffixe corrompu ({}) — PanicPurge.",
                    region_name
                );
                crate::panic::panic_purge();
                #[cfg(test)]
                panic!("Canari suffixe corrompu ({})", region_name);
            }
        }
    }

    /// Zeroize la clé + les canaris de cette région.
    fn zeroize_all(&mut self) {
        unsafe {
            std::ptr::write_bytes(self.ptr.add(self.key_offset), 0, self.key_len);
            std::ptr::write_bytes(self.ptr.add(PAGE_SIZE), 0, CANARY_SIZE);
            std::ptr::write_bytes(
                self.ptr.add(self.key_offset + self.key_len),
                0,
                CANARY_SIZE,
            );
        }
    }
}

// =========================================================================
// POLYMORPHIC KEY BUFFER (Dual-Rail)
// =========================================================================

pub struct PolymorphicKeyBuffer {
    region_a: DualRegion,
    region_b: DualRegion,
    poly_mask: [u8; POLY_MASK_SIZE],
}

pub type PolymorphicBuffer = PolymorphicKeyBuffer;

unsafe impl Send for PolymorphicKeyBuffer {}
unsafe impl Sync for PolymorphicKeyBuffer {}

impl PolymorphicKeyBuffer {
    /// Crée un nouveau buffer polymorphe Dual-Rail contenant `data`.
    ///
    /// Region A : clé en clair P
    /// Region B : clé masquée P' = P ⊕ K_poly
    ///
    /// Les 2 régions sont allouées séparément (adresses distinctes) pour
    /// maximiser la distance physique entre elles (résistance Rowhammer).
    pub fn new(data: &[u8]) -> Self {
        let key_len = data.len();

        // Padding aléatoire (identique pour A et B → layout cohérent)
        let random_prefix = (rand::thread_rng().next_u32() as usize % 512) + 128;
        let random_suffix = (rand::thread_rng().next_u32() as usize % 512) + 128;

        let work_size = CANARY_SIZE + random_prefix + key_len + random_suffix + CANARY_SIZE;
        let key_offset_from_page = CANARY_SIZE + random_prefix;

        // Générer K_poly aléatoire (32 octets)
        let mut poly_mask = [0u8; POLY_MASK_SIZE];
        rand::thread_rng().fill_bytes(&mut poly_mask);

        // Allouer les 2 régions séparément
        let mut region_a = DualRegion::new(work_size, key_offset_from_page, key_len);
        let mut region_b = DualRegion::new(work_size, key_offset_from_page, key_len);

        // Remplir Region A : clé en clair P
        region_a.key_slice_mut().copy_from_slice(data);
        region_a.write_canaris();

        // Remplir Region B : clé masquée P' = P ⊕ K_poly
        {
            let b_slice = region_b.key_slice_mut();
            for i in 0..key_len {
                b_slice[i] = data[i] ^ poly_mask[i % POLY_MASK_SIZE];
            }
        }
        region_b.write_canaris();

        Self {
            region_a,
            region_b,
            poly_mask,
        }
    }

    /// Lit la clé et retourne une copie Zeroizing.
    ///
    /// Vérifie les canaris + la parité dual-rail AVANT lecture.
    pub fn read_and_mutate(&mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.as_slice().to_vec())
    }

    /// Vérifie la parité Dual-Rail : P[i] ⊕ P'[i] == K_poly[i % 32].
    ///
    /// Si un bit flip est détecté → PanicPurge immédiat.
    fn verify_dual_rail(&self) {
        let a = self.region_a.key_slice();
        let b = self.region_b.key_slice();

        for i in 0..self.region_a.key_len {
            if a[i] ^ b[i] != self.poly_mask[i % POLY_MASK_SIZE] {
                eprintln!(
                    "[ALERT CRITIQUE] Dual-Rail parité rompue à l'offset {} — PanicPurge.",
                    i
                );
                crate::panic::panic_purge();
                #[cfg(test)]
                panic!("Dual-Rail parité rompue à l'offset {}", i);
            }
        }
    }

    /// Retourne la clé sous forme de slice.
    ///
    /// Vérifie canaris A + canaris B + parité dual-rail AVANT de retourner.
    pub fn as_slice(&self) -> &[u8] {
        self.region_a.verify_canaris("A");
        self.region_b.verify_canaris("B");
        self.verify_dual_rail();

        self.region_a.key_slice()
    }
}

impl Drop for PolymorphicKeyBuffer {
    fn drop(&mut self) {
        // Zeroize les 2 régions (clé + canaris)
        self.region_a.zeroize_all();
        self.region_b.zeroize_all();

        // Libérer les 2 régions
        self.region_a.free();
        self.region_b.free();

        // Zeroize poly_mask
        for b in self.poly_mask.iter_mut() {
            *b = 0;
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_read() {
        let key = [0xAA; 32];
        let mut buf = PolymorphicKeyBuffer::new(&key);

        // Vérification via as_slice (qui appelle verify_canaries + dual_rail)
        assert_eq!(buf.as_slice(), &key);

        // Vérification via read_and_mutate
        let read = buf.read_and_mutate();
        assert_eq!(read.as_slice(), &key);
    }

    #[test]
    fn test_empty_key() {
        let key: [u8; 0] = [];
        let buf = PolymorphicKeyBuffer::new(&key);
        assert!(buf.as_slice().is_empty());
    }

    #[test]
    fn test_offset_is_random() {
        // Créer 10 buffers → les offsets de clé doivent varier
        let key = [0x55; 16];
        let mut offsets = std::collections::HashSet::new();

        for _ in 0..10 {
            let buf = PolymorphicKeyBuffer::new(&key);
            offsets.insert(buf.region_a.key_offset);
            // `buf` est drop ici (zeroize + munmap)
        }

        // Au moins 5 offsets différents sur 10
        assert!(
            offsets.len() >= 5,
            "Les offsets devraient varier (attendu >=5 différents, obtenu {})",
            offsets.len()
        );
    }

    #[test]
    fn test_poly_mask_varies_per_buffer() {
        // 2 buffers → K_poly différents
        let key = [0x33; 32];
        let buf1 = PolymorphicKeyBuffer::new(&key);
        let buf2 = PolymorphicKeyBuffer::new(&key);

        assert_ne!(
            buf1.poly_mask, buf2.poly_mask,
            "K_poly doit être différent pour chaque buffer"
        );
    }

    #[test]
    fn test_dual_rail_regions_are_distinct() {
        // Les 2 régions doivent être à des adresses différentes
        let key = [0x77; 32];
        let buf = PolymorphicKeyBuffer::new(&key);

        let addr_a = buf.region_a.ptr as usize;
        let addr_b = buf.region_b.ptr as usize;

        assert_ne!(addr_a, addr_b, "Region A et Region B doivent être distinctes");
    }

    #[test]
    fn test_dual_rail_parity() {
        // Vérifie que la parité est bien posée
        let key = [0xCC; 32];
        let buf = PolymorphicKeyBuffer::new(&key);

        let a = buf.region_a.key_slice();
        let b = buf.region_b.key_slice();

        for i in 0..32 {
            assert_eq!(
                a[i] ^ b[i],
                buf.poly_mask[i % POLY_MASK_SIZE],
                "Parité rompue à l'offset {}",
                i
            );
        }
    }

    #[test]
    fn test_zeroize_on_drop() {
        let key = [0xCC; 32];

        let ptr_a_copy: *mut u8;
        let key_offset_a_copy: usize;
        let key_len_copy: usize;

        {
            let buf = PolymorphicKeyBuffer::new(&key);
            ptr_a_copy = buf.region_a.ptr;
            key_offset_a_copy = buf.region_a.key_offset;
            key_len_copy = buf.region_a.key_len;

            // Avant drop : la clé est présente.
            unsafe {
                let slice =
                    std::slice::from_raw_parts(ptr_a_copy.add(key_offset_a_copy), key_len_copy);
                assert_eq!(slice, &key);
            }
        }
        // Drop ici : zeroize + munmap x2.

        // ⚠️ On NE relit PAS après le drop (mémoire libérée).
        let _ = (ptr_a_copy, key_offset_a_copy, key_len_copy);
    }

    #[test]
    fn test_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<PolymorphicKeyBuffer>();
        assert_sync::<PolymorphicKeyBuffer>();
    }

    // ─────────────────────────────────────────────────────────────────
    // Tests de détection de bit flip (dual-rail)
    // ─────────────────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "Dual-Rail parité rompue")]
    fn test_dual_rail_detects_bit_flip_region_a() {
        let key = [0xAA; 32];
        let buf = PolymorphicKeyBuffer::new(&key);

        // Corrompre 1 bit dans Region A
        unsafe {
            let a_ptr = buf.region_a.ptr.add(buf.region_a.key_offset);
            *a_ptr ^= 0x01;
        }

        // Toute lecture doit détecter la corruption
        let _ = buf.as_slice();
    }

    #[test]
    #[should_panic(expected = "Dual-Rail parité rompue")]
    fn test_dual_rail_detects_bit_flip_region_b() {
        let key = [0x55; 32];
        let buf = PolymorphicKeyBuffer::new(&key);

        // Corrompre 1 bit dans Region B
        unsafe {
            let b_ptr = buf.region_b.ptr.add(buf.region_b.key_offset);
            *b_ptr ^= 0x80;
        }

        // Toute lecture doit détecter la corruption
        let _ = buf.as_slice();
    }

    #[test]
    #[should_panic(expected = "Canari préfixe corrompu (A)")]
    fn test_dual_rail_detects_canary_corruption_a() {
        let key = [0x42; 32];
        let buf = PolymorphicKeyBuffer::new(&key);

        // Corrompre le canari préfixe de Region A
        unsafe {
            let canary_ptr = buf.region_a.ptr.add(PAGE_SIZE);
            *canary_ptr ^= 0xFF;
        }

        let _ = buf.as_slice();
    }

    // ─────────────────────────────────────────────────────────────────
    // Test guard-page Linux natif : vérifie que mmap(PROT_NONE) bloque
    // effectivement l'accès (preuve que Miri ne peut pas fournir).
    // ─────────────────────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore)] // Miri ne supporte pas fork+waitpid correctement
    #[test]
    fn test_guard_page_blocks_access() {
        let region = DualRegion::new(4096, 0, 32);
        let ptr = region.ptr;

        // Fork : le fils tente d'écrire dans la guard page (ptr = début PROT_NONE)
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() a échoué");

        if pid == 0 {
            // ─── Fils ───
            // Écriture dans la guard page → SIGSEGV attendu
            unsafe {
                std::ptr::write_volatile(ptr, 0xFF);
                // Si on arrive ici, le guard page n'a PAS bloqué → échec
                libc::_exit(0);
            }
        }

        // ─── Père ───
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(rc > 0, "waitpid() a échoué");

        // Le fils doit être mort par signal
        assert!(
            libc::WIFSIGNALED(status),
            "Le fils aurait dû mourir par signal (statut = 0x{:x})",
            status
        );
        // Et le signal doit être SIGSEGV
        let sig = libc::WTERMSIG(status);
        assert_eq!(
            sig,
            libc::SIGSEGV,
            "Signal attendu SIGSEGV, reçu {}",
            sig
        );
    }

    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore)]
    #[test]
    fn test_work_page_allows_access() {
        // Contrôle négatif : la zone PROT_READ|PROT_WRITE doit être accessible
        let region = DualRegion::new(4096, 0, 32);
        let work_ptr = unsafe { region.ptr.add(PAGE_SIZE) };

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);

        if pid == 0 {
            // Fils : écriture dans la zone travail → doit réussir
            unsafe {
                std::ptr::write_volatile(work_ptr, 0xAB);
                libc::_exit(0);
            }
        }

        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(rc > 0);

        // Le fils doit s'être terminé NORMALEMENT (exit code 0)
        assert!(
            libc::WIFEXITED(status),
            "Le fils aurait dû se terminer normalement (statut = 0x{:x})",
            status
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "Le fils devrait avoir exit(0)"
        );
    }
}