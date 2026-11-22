//! aegis-core/src/storage/mod.rs
//! Architecture Zero-Disk : uniquement utilitaires d'effacement forensique de fichiers externes.
pub mod vault;

#[cfg(test)]
mod cov_stg {
    use super::*;
    #[test]
    fn t() {
        let p = std::env::temp_dir().join("stg.tmp");
        let _ = vault::wipe_and_delete_vault(&p);
    }
}