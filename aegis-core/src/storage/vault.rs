use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::ffi::CStr;
use std::os::raw::c_char;
use getrandom::getrandom;

const CHUNK_SIZE: usize = 64 * 1024;

pub struct AegisVault {
    pub path: String,
}

impl AegisVault {
    pub fn derive_master_key(_pass: &[u8], _salt: &[u8]) -> Result<Vec<u8>, ()> { Ok(vec![0; 32]) }

    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    pub fn purge<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
        wipe_and_delete_vault(path)
    }

    pub fn panic_purge<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
        wipe_and_delete_vault(path)
    }
}

pub fn wipe_and_delete_vault<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(());
    }

    if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
        if let Ok(metadata) = file.metadata() {
            let size = metadata.len();
            let mut buf = [0u8; CHUNK_SIZE];
            let mut written: u64 = 0;

            while written < size {
                let _ = getrandom(&mut buf);
                let to_write = std::cmp::min(CHUNK_SIZE as u64, size - written) as usize;
                if file.write_all(&buf[..to_write]).is_err() {
                    break;
                }
                written += to_write as u64;
            }
            let _ = file.sync_all();
        }
    }
    std::fs::remove_file(path)
}

/// # Safety
///
/// Le pointeur `path_ptr` doit pointer vers une chaÃ®ne de caractÃ¨res C valide et terminÃ©e par un octet nul.
/// Cette zone mÃ©moire ne doit pas Ãªtre modifiÃ©e concurremment pendant l'exÃ©cution.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn aegis_vault_destroy(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() {
        return -1;
    }
    
    let c_str = CStr::from_ptr(path_ptr);
    if let Ok(path_str) = c_str.to_str() {
        if wipe_and_delete_vault(path_str).is_ok() {
            return 0;
        }
    }
    -1
}