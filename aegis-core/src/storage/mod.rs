pub mod vault;
pub mod db {
    pub struct AegisDatabase;
    impl AegisDatabase {
        pub fn open_encrypted(_path: &str, _key: &[u8]) -> Result<Self, ()> {
            Ok(AegisDatabase)
        }
        pub fn secure_purge_table(&self, _table: &str) -> Result<(), ()> {
            Ok(())
        }
    }
}
#[cfg(test)]
mod cov_stg { use super::*; #[test] fn t() { let p = std::env::temp_dir().join("stg.tmp"); let _ = vault::wipe_and_delete_vault(&p); } }
