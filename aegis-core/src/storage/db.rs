//! aegis-core/src/storage/db.rs
//! Gestionnaire de Base de Données Chiffrée SQLCipher & Destruction Forensique

use crate::secure_buffer::SecureBuffer;
use rusqlite::{Connection, OpenFlags};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Échec de connexion ou d'opération SQLCipher: {0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("Clé de chiffrement invalide ou manquante")]
    InvalidKey,
    #[error("Tentative d'injection SQL ou nom de table non sécurisé")]
    InvalidIdentifier,
}

pub struct AegisDatabase {
    conn: Connection,
}

impl AegisDatabase {
    /// Ouvre ou crée une base de données chiffrée avec durcissement PRAGMA strict
    pub fn open_encrypted(db_path: &str, master_key: &SecureBuffer) -> Result<Self, DbError> {
        if master_key.is_empty() {
            return Err(DbError::InvalidKey);
        }

        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Clé brute 256-bit SQLCipher (format x'HEX') emballée dans Zeroizing
        let hex_key = Zeroizing::new(hex::encode(master_key.as_slice()));
        let key_pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", *hex_key));

        // Injection directe du PRAGMA pour éviter l'échappement texte de pragma_update
        conn.execute_batch(&key_pragma)?;

        // Configuration du moteur cryptographique SQLCipher
        conn.pragma_update(None, "cipher_memory_security", "ON")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;

        let db = Self { conn };
        db.init_schema()?;

        Ok(db)
    }

    /// Initialise la structure minimale des tables isolées
    fn init_schema(&self) -> Result<(), DbError> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS secure_kv (
                key TEXT PRIMARY KEY,
                val BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            );",
            [],
        )?;
        Ok(())
    }

    /// Purge sécurisée d'une table avec écrasement physique (VACUUM)
    pub fn secure_purge_table(&self, table_name: &str) -> Result<(), DbError> {
        // Validation stricte contre les injections SQL sur les identifiants
        if !table_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DbError::InvalidIdentifier);
        }

        let query = format!("DELETE FROM {};", table_name);
        self.conn.execute(&query, [])?;
        self.conn.execute("VACUUM;", [])?;

        Ok(())
    }
}