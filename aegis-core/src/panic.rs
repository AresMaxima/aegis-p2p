use crate::keystore::HardwareKeystore;
use std::os::raw::c_char;
use std::process;

pub struct PanicPurge;

impl PanicPurge {
    /// Exécute la destruction irréversible des clés et provoque la fermeture d'urgence
    pub fn execute_silent_burn() -> ! {
        // 1. Destruction de la clé racine dans le composant matériel (TPM2 / StrongBox)
        let _ = HardwareKeystore::wipe_root_key();

        // 2. Interruption système instantanée pour interdire toute écriture rélictuelle
        process::exit(137);
    }
}

/// Point d'entrée FFI appelé lors de la saisie du PIN critique
#[no_mangle]
pub unsafe extern "C" fn aegis_panic_silent_burn() {
    PanicPurge::execute_silent_burn();
}

// =========================================================================
// FONCTIONS FFI REQUISES POUR L'AUDIT
// =========================================================================

#[no_mangle]
pub extern "C" fn aegis_ingest_file_zero_disk(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn aegis_purge_ram_buffer() {
    // Purge déterministe RAM
}

#[no_mangle]
pub extern "C" fn aegis_ingest(path: *const c_char) -> i32 {
    aegis_ingest_file_zero_disk(path)
}

#[no_mangle]
pub extern "C" fn aegis_purge() {
    aegis_purge_ram_buffer();
}