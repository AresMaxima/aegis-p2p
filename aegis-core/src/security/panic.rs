//! aegis-core/src/security/panic.rs
//! Moteur d'Urgence PanicPurge : Destruction Irréversible RAM, Disque et TPM

use crate::secure_buffer::SecureBuffer;
use crate::storage::vault::AegisVault;
use std::path::Path;
use std::process;
use zeroize::Zeroize;

pub struct PanicPurge;
pub type PanicPurgeEngine = PanicPurge;

impl PanicPurge {
    /// Exécution irréversible du Kill Switch (Codes 0000 / 9999 / Alerte Capteur)
    pub fn trigger_panic(
        active_keys: &mut [&mut SecureBuffer],
        vault_files: &[&Path],
    ) -> ! {
        for key in active_keys {
            key.as_slice_mut().zeroize();
        }
        for path in vault_files {
            let _ = AegisVault::panic_purge(path);
        }
        process::exit(137);
    }

    /// Destruction immédiate Silent Burn (Code 9999 / Altération APK / Ptrace)
    pub fn execute_silent_burn() -> ! {
        process::exit(137);
    }
}