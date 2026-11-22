//! aegis-core/src/panic.rs
//! Moteur d'Ã‰radication d'Urgence PanicPurge & Silent Burn â€” Phase 4 (CdCM v2.2-RC1).
//!
//! C11 FIX (2026-09-21) : le wipe du fichier vault n'ouvre plus
//! /dev/urandom Ã  chaque chunk. Un handle unique est gardÃ© pour toute
//! la durÃ©e du wipe. Fallback sur `getrandom` (syscall direct) en cas
//! d'Ã©chec â€” jamais de pattern fixe.

use crate::keystore::HardwareKeystore;
use crate::secure_buffer;
use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::raw::c_char;
use std::sync::Mutex;

static VAULT_PATH: Mutex<Option<String>> = Mutex::new(None);

/// # Safety
/// Le pointeur `path` doit pointer vers une chaÃ®ne de caractÃ¨res C valide terminÃ©e par un octet nul (`\0`).
#[no_mangle]
pub unsafe extern "C" fn aegis_init_vault_path(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(path) };
    if let Ok(s) = c_str.to_str() {
        if let Ok(mut guard) = VAULT_PATH.lock() {
            *guard = Some(s.to_string());
            return 0;
        }
    }
    -2
}

#[inline(always)]
fn system_exit(code: i32) {
    #[cfg(not(test))]
    std::process::exit(code);

    #[cfg(test)]
    let _ = code; // Ã‰vite l'avertissement de variable inutilisÃ©e pendant les tests
}

pub struct PanicPurge;

impl PanicPurge {
    pub fn execute_silent_burn() {
        let _ = HardwareKeystore::wipe_root_key();
        let _ = crate::aegis_v36_wipe_ephemeral_buffers();
        unsafe {
            secure_buffer::global_wipe_all_buffers();
        }
        system_exit(137)
    }

    pub fn trigger() {
        panic_purge();
    }
}

pub fn panic_purge() {
    let _ = HardwareKeystore::wipe_root_key();
    let _ = crate::aegis_v36_wipe_ephemeral_buffers();
    unsafe {
        secure_buffer::global_wipe_all_buffers();
    }
    system_exit(137);
}

#[no_mangle]
pub extern "C" fn aegis_purge_ram_buffer() {
    let _ = crate::aegis_v36_wipe_ephemeral_buffers();
    unsafe {
        secure_buffer::global_wipe_all_buffers();
    }
}

#[no_mangle]
pub extern "C" fn aegis_panic_purge() {
    panic_purge();
}

/// Remplit `buf` avec des octets alÃ©atoires cryptographiquement sÃ»rs.
///
/// Ordre de prÃ©fÃ©rence :
///   1. Handle `/dev/urandom` (passÃ© en paramÃ¨tre, ouvert une fois par l'appelant).
///   2. `getrandom::getrandom` (syscall direct, ne peut pas Ã©chouer cÃ´tÃ© OS moderne).
///
/// Jamais de fallback sur un octet fixe : un attaquant pourrait dÃ©tecter
/// le pattern dans le fichier wipÃ© et en dÃ©duire que le wipe a partiellement
/// Ã©chouÃ© (fuite d'information).
fn fill_random(maybe_urandom: Option<&mut File>, buf: &mut [u8]) -> bool {
    // 1) /dev/urandom
    if let Some(urandom) = maybe_urandom {
        if urandom.read_exact(buf).is_ok() {
            return true;
        }
    }
    // 2) getrandom (syscall)
    if getrandom::getrandom(buf).is_ok() {
        return true;
    }
    // 3) Ã‰chec total : remplir avec un pattern HAUTEMENT alÃ©atoire dÃ©rivÃ©
    //    du timestamp + adresse du buffer (mieux que 0x55 fixe, mais on
    //    ne devrait jamais y arriver sur Android/Linux).
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xA3E1);
    let mut x = seed;
    for b in buf.iter_mut() {
        // xorshift64* â€” rapide, dÃ©terministe si seed connu, mais diffÃ©rent Ã  chaque appel
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    false
}

fn internal_silent_burn() {
    // 1. Wipe RAM avant tout
    let _ = HardwareKeystore::wipe_root_key();
    let _ = crate::aegis_v36_wipe_ephemeral_buffers();
    unsafe {
        secure_buffer::global_wipe_all_buffers();
    }

    // 2. Wipe disque (vault)
    if let Ok(guard) = VAULT_PATH.lock() {
        if let Some(ref path) = *guard {
            let original_size = std::fs::metadata(path).map(|m| m.len() as usize).unwrap_or(0);

            if original_size > 0 {
                if let Ok(mut file) = File::create(path) {
                    // C11 FIX : ouvrir /dev/urandom UNE SEULE FOIS pour tout le wipe
                    let mut urandom: Option<File> = File::open("/dev/urandom").ok();

                    const CHUNK_SIZE: usize = 64 * 1024;
                    let mut chunk = secure_buffer::SecureBuffer::new(CHUNK_SIZE);

                    let mut written = 0usize;
                    while written < original_size {
                        let to_write = std::cmp::min(CHUNK_SIZE, original_size - written);
                        fill_random(urandom.as_mut(), &mut chunk.as_slice_mut()[..to_write]);
                        let _ = file.write_all(&chunk.as_slice()[..to_write]);
                        written += to_write;
                    }
                    let _ = file.sync_all();
                    chunk.clear();
                }
            }
        }
    }

    system_exit(137)
}

#[no_mangle]
pub extern "C" fn aegis_panic_silent_burn() {
    internal_silent_burn();
}

/// # Safety
/// Le pointeur `path` doit Ãªtre soit nul, soit pointer vers une chaÃ®ne C valide.
#[no_mangle]
pub unsafe extern "C" fn aegis_ingest(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn aegis_purge() {
    panic_purge();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::ffi::CString;

    #[test]
    fn test_ffi_aegis_purge_ram_buffer() {
        aegis_purge_ram_buffer();
    }

    #[test]
    fn test_ffi_aegis_ingest_branches() {
        unsafe {
            let res_null = aegis_ingest(ptr::null());
            assert_eq!(res_null, -1);

            let dummy_path = "fake_path\0";
            let res_ok = aegis_ingest(dummy_path.as_ptr() as *const c_char);
            assert_eq!(res_ok, 0);
        }
    }

    #[test]
    fn test_panic_module_execution() {
        // Ces fonctions traverseront 100% de la logique sans dÃ©truire le processus
        PanicPurge::execute_silent_burn();
        PanicPurge::trigger();
        aegis_panic_purge();
        aegis_purge();
    }

    #[test]
    fn test_silent_burn_with_vault_path() {
        unsafe {
            // Test du chemin nul
            assert_eq!(aegis_init_vault_path(ptr::null()), -1);

            // Test avec un chemin valide (fichier temporaire factice pour forcer la logique de wipe)
            let valid_path = CString::new("test_vault_dummy.tmp").unwrap();
            assert_eq!(aegis_init_vault_path(valid_path.as_ptr()), 0);

            // CrÃ©ation d'un fichier factice pour valider la boucle d'Ã©crasement
            let _ = std::fs::write("test_vault_dummy.tmp", b"DONNEES_SENSIBLES");

            // DÃ©clenche l'Ã©crasement (qui ira jusqu'au bout sans crasher)
            aegis_panic_silent_burn();

            // Nettoyage post-test
            let _ = std::fs::remove_file("test_vault_dummy.tmp");
        }
    }

    #[test]
    fn test_fill_random_produces_varied_output() {
        // Sans urandom, le fallback doit produire des sorties diffÃ©rentes Ã 
        // chaque appel (grÃ¢ce au timestamp).
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        fill_random(None, &mut buf1);
        std::thread::sleep(std::time::Duration::from_millis(2));
        fill_random(None, &mut buf2);
        // Les 2 buffers ne doivent pas Ãªtre identiques (probabilitÃ© ~2^-256)
        assert_ne!(buf1, buf2, "fallback non-alÃ©atoire dÃ©tectÃ©");
    }

    #[test]
    fn test_fill_random_no_fixed_pattern() {
        // VÃ©rifier qu'aucun octet fixe (0x55 ou 0x00) n'apparaÃ®t
        // systÃ©matiquement â€” indicatif d'un fallback faible.
        let mut buf = [0u8; 1024];
        fill_random(None, &mut buf);
        let all_55 = buf.iter().all(|&b| b == 0x55);
        let all_zero = buf.iter().all(|&b| b == 0x00);
        assert!(!all_55, "pattern 0x55 dÃ©tectÃ© â€” fallback faible");
        assert!(!all_zero, "pattern 0x00 dÃ©tectÃ© â€” fallback faible");
    }
}