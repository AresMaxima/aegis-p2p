//! aegis-core/tests/phase4_v22_2_test.rs
//! Tests d'Intégration Phase 4.2 (Storage & Vault Initialization) — CdCM v2.2-RC1.

#[cfg(test)]
mod tests {
    use aegis_core::panic::{aegis_init_vault_path, aegis_panic_purge, aegis_purge_ram_buffer};
    use std::ffi::CString;

    #[test]
    fn test_phase4_2_vault_path_initialization() {
        let invalid_res = unsafe { aegis_init_vault_path(std::ptr::null()) };
        assert_eq!(invalid_res, -1);

        let valid_path = CString::new("/data/user/0/com.example.aegis/app_flutter/vault.aegis").unwrap();
        let valid_res = unsafe { aegis_init_vault_path(valid_path.as_ptr()) };
        assert_eq!(valid_res, 0);
    }

    #[test]
    fn test_phase4_2_ram_buffer_purge() {
        aegis_purge_ram_buffer();
    }

    #[test]
    fn test_phase4_2_panic_purge_exit_code_137() {
        // Exécution en sous-processus isolé pour valider le code d'arrêt réel 137 sans faire crasher le runner Cargo sous `panic = "abort"`
        if std::env::var("RUN_PANIC_PURGE_SUBPROCESS").is_ok() {
            aegis_panic_purge();
        }

        let exe_path = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe_path)
            .arg("tests::test_phase4_2_panic_purge_exit_code_137")
            .arg("--exact")
            .arg("--nocapture")
            .env("RUN_PANIC_PURGE_SUBPROCESS", "1")
            .status()
            .expect("Impossible de lancer le sous-processus de test");

        // Assertion exacte du code d'arrêt système 137 (SIGKILL / PanicPurge)
        assert_eq!(status.code(), Some(137), "Le binaire doit s'arrêter avec l'exit code 137");
    }
}