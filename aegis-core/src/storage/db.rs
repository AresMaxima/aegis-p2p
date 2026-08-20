use rusqlite::{params, Connection, Result};

/// Structure gérant la base de données temporaire en mémoire RAM.
pub struct TemporaryStorage {
    conn: Connection,
}

#[derive(Debug, PartialEq)]
pub struct PendingMessage {
    pub id: i64,
    pub recipient_hash: String,
    pub payload: Vec<u8>,
    pub timestamp: i64,
}

impl TemporaryStorage {
    /// Initialise une base de données SQLite volatile 100% en RAM (`:memory:`).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        
        // CORRECTION OPSEC : Verrouillage strict de SQLite en RAM
        // temp_store = MEMORY : Interdit l'usage du disque pour les tris et tables temporaires.
        // secure_delete = ON  : Écrase avec des zéros la mémoire vive libérée.
        // journal_mode = OFF  : Désactive la journalisation inutile en mémoire volatile.
        conn.execute_batch(
            "PRAGMA temp_store = MEMORY;
             PRAGMA secure_delete = ON;
             PRAGMA journal_mode = OFF;"
        )?;
        
        // CORRECTION SYNTAXE : Utilisation de () au lieu de []
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_hash TEXT NOT NULL,
                payload BLOB NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            (),
        )?;

        Ok(Self { conn })
    }

    /// Insère un message chiffré en attente dans la file éphémère.
    pub fn store_message(&self, recipient_hash: &str, payload: &[u8]) -> Result<i64> {
        let timestamp = chrono_like_timestamp();
        self.conn.execute(
            "INSERT INTO pending_messages (recipient_hash, payload, timestamp) VALUES (?1, ?2, ?3)",
            params![recipient_hash, payload, timestamp],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Récupère tous les messages en attente pour un destinataire donné.
    pub fn get_messages_for(&self, recipient_hash: &str) -> Result<Vec<PendingMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, recipient_hash, payload, timestamp FROM pending_messages WHERE recipient_hash = ?1",
        )?;

        let message_iter = stmt.query_map(params![recipient_hash], |row| {
            Ok(PendingMessage {
                id: row.get(0)?,
                recipient_hash: row.get(1)?,
                payload: row.get(2)?,
                timestamp: row.get(3)?,
            })
        })?;

        let mut messages = Vec::new();
        for msg in message_iter {
            messages.push(msg?);
        }

        Ok(messages)
    }

    /// Supprime un message de la BDD après confirmation de réception/lecture.
    pub fn delete_message(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM pending_messages WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Purge intégrale de la table (Emergency Clean).
    pub fn wipe_all(&self) -> Result<()> {
        // CORRECTION SYNTAXE : Utilisation de ()
        self.conn.execute("DELETE FROM pending_messages", ())?;
        self.conn.execute("VACUUM", ())?;
        Ok(())
    }
}

/// Générateur simple de timestamp UNIX en secondes sans dépendances lourdes
fn chrono_like_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temporary_storage_lifecycle() {
        let storage = TemporaryStorage::open_in_memory().unwrap();
        let recipient = "a1b2c3d4e5f67890a1b2c3d4e5f67890";
        let payload = b"Message chiffre de test";

        // Insertion
        let msg_id = storage.store_message(recipient, payload).unwrap();
        assert!(msg_id > 0);

        // Lecture
        let messages = storage.get_messages_for(recipient).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, payload);

        // Suppression
        storage.delete_message(msg_id).unwrap();
        let empty_messages = storage.get_messages_for(recipient).unwrap();
        assert_eq!(empty_messages.len(), 0);
    }
}