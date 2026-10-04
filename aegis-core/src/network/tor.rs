//! aegis-core/src/network/tor.rs
//!
//! Client Tor embarqué (Arti) + transport isolé par contact.
//!
//! ─────────────────────────────────────────────────────────────────────
//! Contenu :
//!
//!   1. `AegisTorClient` (legacy) — envoi d'un fichier unique via bootstrap.
//!
//!   2. `TorTransport` (P0-A.1d.1) — transport Tor persistant avec :
//!        • Un client de base (bootstrap unique)
//!        • Un `HashMap<contact_id, TorClient>` isolé par contact
//!        • Un `HashMap<contact_id, Arc<Mutex<DataStream>>>` stream persistant
//!
//!   3. `TorTransportPerContact` (P0-A.1d.2) — wrapper qui implémente
//!      `EncryptedTransport` :
//!        • Pipeline send : strip → Ratchet::encrypt → prefix_len → pack → write
//!        • Pipeline recv : read → concat → strip_prefix → Ratchet::decrypt
//!
//!   4. `secure_wipe_dir` — utilitaire partagé (wipe fichiers avant Drop).
//!
//! ─────────────────────────────────────────────────────────────────────
//! Décisions actées (02-04/10/2026) :
//!
//!   • D40   : Chiffrement applicatif obligatoire (fail-closed)
//!   • D42   : un TorClient par contact (isolation par circuit)
//!   • D49   : rester sur Arti 0.18
//!   • D50   : isolation via `base.isolated_client()` + HashMap
//!   • D51   : `TorIsolationToken` (P0-A.1b) = identifiant sémantique
//!   • D52   : struct `TorTransport` wraps client de base + map
//!   • D53   : `send_encrypted` sépare connect et send
//!   • D55   : Metadata stripping via SecureBuffer intermédiaire
//!   • D56   : `P2PFramePacker::pack_payload` APRÈS `Ratchet::encrypt`
//!   • D58   : FRAME_SIZE = 512 B indépendant du transport physique
//!   • D59   : Stream persistant via `Arc<tokio::sync::Mutex<DataStream>>`
//!   • Opt.2  : préfixe `ciphertext_len: u32 BE` avant packing
//! ─────────────────────────────────────────────────────────────────────

use arti_client::{config::CfgPath, DataStream, TorClient, TorClientConfig};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tor_rtcompat::tokio::TokioRustlsRuntime;
use zeroize::Zeroize;

use crate::crypto::ratchet::RatchetSession;
use crate::network::encrypted_transport::{EncryptedTransport, TransportError};
use crate::network::p2p_transfer::{MetadataStripper, P2PFramePacker, FRAME_SIZE, HEADER_SIZE};
use crate::secure_buffer::SecureBuffer;

// =========================================================================
// Client Tor legacy — envoi d'un fichier unique
// =========================================================================

/// Client Tor minimaliste (legacy).
pub struct AegisTorClient {
    client: Option<TorClient<TokioRustlsRuntime>>,
    ram_fs: Option<TempDir>,
}

impl AegisTorClient {
    pub async fn bootstrap(target_onion: &str, file_path: &str) -> Result<Self, Box<dyn Error>> {
        let ram_fs = tempfile::tempdir()?;
        let state_dir = ram_fs.path().join("state");
        let cache_dir = ram_fs.path().join("cache");

        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&cache_dir)?;

        let mut config_builder = TorClientConfig::builder();
        config_builder
            .storage()
            .state_dir(CfgPath::new(state_dir.display().to_string()))
            .cache_dir(CfgPath::new(cache_dir.display().to_string()));

        let config = config_builder.build()?;
        let runtime = TokioRustlsRuntime::current()?;

        let client = TorClient::with_runtime(runtime)
            .config(config)
            .create_bootstrapped()
            .await?;

        let mut stream = client.connect((target_onion, 80)).await?;
        let mut file = File::open(file_path).await?;
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            stream.write_all(&buffer[..bytes_read]).await?;
        }

        stream.flush().await?;
        stream.shutdown().await?;   // D59 : shutdown() tokio au lieu de close() futures

        Ok(Self {
            client: Some(client),
            ram_fs: Some(ram_fs),
        })
    }

    pub fn inner(&self) -> &TorClient<TokioRustlsRuntime> {
        self.client.as_ref().expect("Le client Tor a été détruit")
    }
}

impl Drop for AegisTorClient {
    fn drop(&mut self) {
        self.client.take();
        if let Some(temp_dir) = self.ram_fs.take() {
            let path = temp_dir.path().to_path_buf();
            secure_wipe_dir(&path);
            let _ = temp_dir.close();
        }
    }
}

// =========================================================================
// TorTransport — isolation par contact (P0-A.1d.1)
// =========================================================================

/// Type de stream partagé : Arc<Mutex<DataStream>>.
///
/// Permet :
///   • Un stream par contact (isolation réseau)
///   • Un partage entre `send_encrypted` et `recv_decrypted` (persistance)
///   • Un accès `&mut` via `lock().await` (contrat `&self` du trait)
pub type SharedStream = Arc<Mutex<DataStream>>;

/// Transport Tor avec isolation par contact.
pub struct TorTransport {
    base_client: TorClient<TokioRustlsRuntime>,
    isolated_clients: Arc<RwLock<HashMap<String, TorClient<TokioRustlsRuntime>>>>,
    streams: Arc<RwLock<HashMap<String, SharedStream>>>,
    ram_fs: Option<TempDir>,
}

impl TorTransport {
    /// Bootstrap un nouveau `TorTransport`.
    pub async fn bootstrap() -> Result<Self, Box<dyn Error>> {
        let ram_fs = tempfile::tempdir()?;
        let state_dir = ram_fs.path().join("state");
        let cache_dir = ram_fs.path().join("cache");

        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&cache_dir)?;

        let mut config_builder = TorClientConfig::builder();
        config_builder
            .storage()
            .state_dir(CfgPath::new(state_dir.display().to_string()))
            .cache_dir(CfgPath::new(cache_dir.display().to_string()));

        let config = config_builder.build()?;
        let runtime = TokioRustlsRuntime::current()?;

        let base_client = TorClient::with_runtime(runtime)
            .config(config)
            .create_bootstrapped()
            .await?;

        Ok(Self {
            base_client,
            isolated_clients: Arc::new(RwLock::new(HashMap::new())),
            streams: Arc::new(RwLock::new(HashMap::new())),
            ram_fs: Some(ram_fs),
        })
    }

    /// Récupère (ou crée) le client isolé pour un contact.
    pub async fn get_or_create_isolated_client(
        &self,
        contact_id: &str,
    ) -> Result<TorClient<TokioRustlsRuntime>, Box<dyn Error>> {
        {
            let map = self.isolated_clients.read().await;
            if let Some(client) = map.get(contact_id) {
                return Ok(client.clone());
            }
        }

        let new_client = self.base_client.isolated_client();

        {
            let mut map = self.isolated_clients.write().await;
            if let Some(existing) = map.get(contact_id) {
                return Ok(existing.clone());
            }
            map.insert(contact_id.to_string(), new_client.clone());
        }

        Ok(new_client)
    }

    /// Récupère (ou ouvre) le stream Tor persistant pour un contact.
    ///
    /// Premier appel : ouvre un nouveau stream via `client.connect()`.
    /// Appels suivants : retourne le `SharedStream` déjà stocké.
    ///
    /// Le stream est protégé par un `tokio::sync::Mutex` — accès
    /// exclusif pendant chaque lecture/écriture.
    pub async fn get_or_create_stream(
        &self,
        contact_id: &str,
        target_onion: &str,
    ) -> Result<SharedStream, TransportError> {
        // Fast path : stream déjà présent
        {
            let map = self.streams.read().await;
            if let Some(stream) = map.get(contact_id) {
                return Ok(Arc::clone(stream));
            }
        }

        // Slow path : ouvrir un nouveau stream
        let client = self
            .get_or_create_isolated_client(contact_id)
            .await
            .map_err(|e| TransportError::TransportUnavailable(e.to_string()))?;

        let stream = client
            .connect((target_onion, 80))
            .await
            .map_err(|e| TransportError::TransportUnavailable(e.to_string()))?;

        let shared: SharedStream = Arc::new(Mutex::new(stream));

        // Double-check pour éviter la race
        {
            let mut map = self.streams.write().await;
            if let Some(existing) = map.get(contact_id) {
                return Ok(Arc::clone(existing));
            }
            map.insert(contact_id.to_string(), Arc::clone(&shared));
        }

        Ok(shared)
    }

    /// Nombre de contacts ayant un client isolé actif.
    pub async fn isolated_client_count(&self) -> usize {
        self.isolated_clients.read().await.len()
    }

    /// Nombre de streams actifs.
    pub async fn stream_count(&self) -> usize {
        self.streams.read().await.len()
    }

    /// Force le drop du client isolé d'un contact.
    pub async fn drop_isolated_client(&self, contact_id: &str) {
        let mut map = self.isolated_clients.write().await;
        map.remove(contact_id);
    }

    /// Force le drop du stream d'un contact.
    pub async fn drop_stream(&self, contact_id: &str) {
        let mut map = self.streams.write().await;
        map.remove(contact_id);
    }

    /// Accès au client de base.
    pub fn base_client(&self) -> &TorClient<TokioRustlsRuntime> {
        &self.base_client
    }
}

impl Drop for TorTransport {
    fn drop(&mut self) {
        if let Some(temp_dir) = self.ram_fs.take() {
            let path = temp_dir.path().to_path_buf();
            secure_wipe_dir(&path);
            let _ = temp_dir.close();
        }
    }
}

// =========================================================================
// TorTransportPerContact — impl EncryptedTransport (P0-A.1d.2)
// =========================================================================

/// Wrapper par contact qui implémente `EncryptedTransport`.
pub struct TorTransportPerContact {
    transport: Arc<TorTransport>,
    contact_id: String,
    target_onion: String,
}

impl TorTransportPerContact {
    pub fn new(
        transport: Arc<TorTransport>,
        contact_id: String,
        target_onion: String,
    ) -> Self {
        Self {
            transport,
            contact_id,
            target_onion,
        }
    }

    pub fn contact_id(&self) -> &str {
        &self.contact_id
    }

    pub fn target_onion(&self) -> &str {
        &self.target_onion
    }
}

#[allow(async_fn_in_trait)]
impl EncryptedTransport for TorTransportPerContact {
    async fn send_encrypted(
        &self,
        session: &mut RatchetSession,
        plaintext: &[u8],
    ) -> Result<(), TransportError> {
        // 1. Wrap plaintext dans SecureBuffer
        let mut sb = SecureBuffer::new(plaintext.len());
        sb.as_slice_mut().copy_from_slice(plaintext);

        // 2. Strip métadonnées
        let stripped = MetadataStripper::strip_and_normalize(&sb);

        // 3. Chiffrer
        let ciphertext = session
            .encrypt(stripped.as_slice())
            .map_err(|e| TransportError::EncryptionFailed(e))?;

        // 4. Préfixe length (u32 BE)
        let mut prefixed = Vec::with_capacity(4 + ciphertext.len());
        prefixed.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        prefixed.extend_from_slice(&ciphertext);

        // 5. Pack en trames de 512 B
        let frames = P2PFramePacker::pack_payload(&prefixed);

        // 6. Récupérer le stream persistant (Arc<Mutex<DataStream>>)
        let shared = self
            .transport
            .get_or_create_stream(&self.contact_id, &self.target_onion)
            .await?;

        // 7. Lock + envoi trame par trame + flush
        let mut stream = shared.lock().await;
        for frame in frames.iter() {
            stream
                .write_all(frame)
                .await
                .map_err(|e| TransportError::IoError(e.to_string()))?;
            stream
                .flush()
                .await
                .map_err(|e| TransportError::IoError(e.to_string()))?;
        }

        Ok(())
    }

    async fn recv_decrypted(
        &self,
        session: &mut RatchetSession,
    ) -> Result<Vec<u8>, TransportError> {
        let shared = self
            .transport
            .get_or_create_stream(&self.contact_id, &self.target_onion)
            .await?;

        let mut stream = shared.lock().await;

        // 1. Lire la première trame (header)
        let mut first_frame = [0u8; FRAME_SIZE];
        stream
            .read_exact(&mut first_frame)
            .await
            .map_err(|e| TransportError::IoError(e.to_string()))?;

        // 2. Parser total_chunks (bytes 4-7)
        let total_chunks = u32::from_be_bytes([
            first_frame[4],
            first_frame[5],
            first_frame[6],
            first_frame[7],
        ]) as usize;

        if total_chunks == 0 {
            return Err(TransportError::DecryptionFailed(
                "total_chunks = 0 (invalid frame)".to_string(),
            ));
        }

        // 3. Concaténer les payloads (bytes 8.. de chaque trame)
        let mut prefixed: Vec<u8> = Vec::with_capacity(total_chunks * (FRAME_SIZE - HEADER_SIZE));
        prefixed.extend_from_slice(&first_frame[HEADER_SIZE..]);

        for _ in 1..total_chunks {
            let mut frame = [0u8; FRAME_SIZE];
            stream
                .read_exact(&mut frame)
                .await
                .map_err(|e| TransportError::IoError(e.to_string()))?;
            prefixed.extend_from_slice(&frame[HEADER_SIZE..]);
        }

        // 4. Parser ciphertext_len (bytes 0-3)
        if prefixed.len() < 4 {
            return Err(TransportError::DecryptionFailed(
                "prefixed payload too short".to_string(),
            ));
        }

        let ciphertext_len =
            u32::from_be_bytes([prefixed[0], prefixed[1], prefixed[2], prefixed[3]]) as usize;

        if prefixed.len() < 4 + ciphertext_len {
            return Err(TransportError::DecryptionFailed(format!(
                "ciphertext_len {} > available {}",
                ciphertext_len,
                prefixed.len() - 4
            )));
        }

        // 5. Extraire ciphertext exact
        let ciphertext = &prefixed[4..4 + ciphertext_len];

        // 6. Déchiffrer
        let plaintext = session
            .decrypt(ciphertext)
            .map_err(|e| TransportError::DecryptionFailed(e))?;

        Ok(plaintext)
    }
}

// =========================================================================
// Utilitaires partagés
// =========================================================================

pub fn secure_wipe_dir(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if let Ok(metadata) = fs::metadata(&entry_path) {
                    let size = metadata.len();
                    if let Ok(mut file) = OpenOptions::new().write(true).open(&entry_path) {
                        let zeros = [0u8; 8192];
                        let mut written: u64 = 0;
                        while written < size {
                            let to_write = std::cmp::min(8192, size - written) as usize;
                            if file.write_all(&zeros[..to_write]).is_err() {
                                break;
                            }
                            written += to_write as u64;
                        }
                        let _ = file.sync_all();
                    }
                }
                let _ = fs::remove_file(&entry_path);
            } else if entry_path.is_dir() {
                secure_wipe_dir(&entry_path);
            }
        }
    }
    let _ = fs::remove_dir(path);
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test hérité de l'ancien tor.rs — vérifie Zeroize sur un buffer 32 B.
    #[test]
    fn test_tor_client_instantiation_and_wipe() {
        let mut dummy_key = [0x42u8; 32];
        assert_eq!(dummy_key.len(), 32);
        dummy_key.zeroize();
        assert_eq!(dummy_key, [0u8; 32]);
    }

    /// Vérifie que le préfixe length u32 BE est bien parsé.
    #[test]
    fn test_length_prefix_parsing_roundtrip() {
        let ciphertext = b"ciphertext_data_example";
        let mut prefixed = Vec::with_capacity(4 + ciphertext.len());
        prefixed.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        prefixed.extend_from_slice(ciphertext);

        let parsed_len = u32::from_be_bytes([prefixed[0], prefixed[1], prefixed[2], prefixed[3]])
            as usize;
        assert_eq!(parsed_len, ciphertext.len());
        assert_eq!(&prefixed[4..4 + parsed_len], ciphertext);
    }

    /// Vérifie qu'un ciphertext < 504 B produit 1 seule trame.
    #[test]
    fn test_single_frame_for_small_ciphertext() {
        let small_ciphertext = vec![0x42u8; 100];
        let mut prefixed = Vec::with_capacity(4 + small_ciphertext.len());
        prefixed.extend_from_slice(&(small_ciphertext.len() as u32).to_be_bytes());
        prefixed.extend_from_slice(&small_ciphertext);

        let frames = P2PFramePacker::pack_payload(&prefixed);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), FRAME_SIZE);

        let total_chunks =
            u32::from_be_bytes([frames[0][4], frames[0][5], frames[0][6], frames[0][7]]);
        assert_eq!(total_chunks, 1);
    }

    /// Bootstrap Tor réel — lent, ignoré par défaut.
    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_bootstrap() {
        let result = TorTransport::bootstrap().await;
        assert!(result.is_ok(), "bootstrap Tor échoué: {:?}", result.err());
        let transport = result.unwrap();
        assert_eq!(transport.isolated_client_count().await, 0);
    }

    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_reuses_existing_isolated_client() {
        let transport = TorTransport::bootstrap().await.expect("bootstrap");
        let _c1 = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("create alice");
        let _c2 = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("reuse alice");
        assert_eq!(transport.isolated_client_count().await, 1);
    }

    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_creates_isolated_client_per_contact() {
        let transport = TorTransport::bootstrap().await.expect("bootstrap");
        let _a = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("create alice");
        let _b = transport
            .get_or_create_isolated_client("contact_bob")
            .await
            .expect("create bob");
        assert_eq!(transport.isolated_client_count().await, 2);
    }

    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_drops_isolated_client() {
        let transport = TorTransport::bootstrap().await.expect("bootstrap");
        let _a = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("create alice");
        assert_eq!(transport.isolated_client_count().await, 1);
        transport.drop_isolated_client("contact_alice").await;
        assert_eq!(transport.isolated_client_count().await, 0);
    }
}