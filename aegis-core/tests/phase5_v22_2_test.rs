#[cfg(test)]
mod tests {
    use aegis_core::storage::vault::AegisVault;

    #[test]
    fn test_phase5_honeytoken_vault_purge() {
        let temp_dir = std::env::temp_dir();
        let vault_file_path = temp_dir.join("honeytoken_test.aegis");

        // Création d'un conteneur factice
        std::fs::write(&vault_file_path, b"FAKE_AEGIS_HONEYTOKEN_DATA_CONTENT").unwrap();
        assert!(vault_file_path.exists());

        // Purge d'urgence (Honeytoken Trigger)
        assert!(AegisVault::panic_purge(&vault_file_path).is_ok());
        assert!(!vault_file_path.exists());
    }
}