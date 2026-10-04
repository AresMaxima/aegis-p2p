//! aegis-core/src/network/tor.rs
//!
//! Client Tor embarqué (Arti) + transport isolé par contact.
//!
//! ─────────────────────────────────────────────────────────────────────
//! Contenu :
//!
//!   1. `AegisTorClient` (legacy)
//!      Client Tor minimal — utilisé pour l'envoi de fichier unique
//!      via `bootstrap()`. Sera progressivement remplacé par
//!      `TorTransport`.
//!
//!   2. `TorTransport` (P0-A.1d.1)
//!      Transport Tor persistant avec :
//!        • Un client de base (bootstrap unique, coûteux)
//!        • Un `HashMap<contact_id, TorClient>` isolé par contact
//!          (circuits dédiés, jamais partagés entre contacts)
//!        • Méthode `get_or_create_isolated_client(contact_id)`
//!
//!   3. `secure_wipe_dir` (utilitaire partagé)
//!      Écrase récursivement les fichiers d'un dossier avant suppression.
//!      Utilisé par le Drop des deux types Tor.
//!
//! ─────────────────────────────────────────────────────────────────────
//! Décisions actées (02-04/10/2026) :
//!
//!   • D42   : un TorClient par contact (isolation par circuit)
//!   • D49   : rester sur Arti 0.18 (pas de migration)
//!   • D50   : isolation via `base.isolated_client()` + HashMap
//!   • D51   : `TorIsolationToken` (P0-A.1b) = identifiant sémantique,
//!             pas passé à Arti
//!   • D52   : struct `TorTransport` wraps client de base + map
//! ─────────────────────────────────────────────────────────────────────

use arti_client::{config::CfgPath, TorClient, TorClientConfig};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use futures::io::AsyncWriteExt;
use tor_rtcompat::tokio::TokioRustlsRuntime;
use zeroize::Zeroize;

// =========================================================================
// Client Tor legacy — envoi d'un fichier unique
// =========================================================================

/// Client Tor minimaliste (legacy).
///
/// Bootstrap un client Tor, envoie un fichier via un stream `.onion`,
/// et wipe le répertoire RAM au Drop.
///
/// **Ce type sera remplacé par `TorTransport` dans les sous-blocs
/// suivants de P0-A.1.** Il est conservé pour ne pas casser les usages
/// existants et les tests.
pub struct AegisTorClient {
    client: Option<TorClient<TokioRustlsRuntime>>,
    ram_fs: Option<TempDir>,
}

impl AegisTorClient {
    /// Bootstrap + envoi d'un fichier vers `target_onion:80`.
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
        stream.close().await?;

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

/// Transport Tor avec isolation par contact.
///
/// ─────────────────────────────────────────────────────────────────────
/// Architecture :
///
///   `base_client`     : TorClient initial (bootstrap une fois, coûteux)
///   `isolated_clients`: un TorClient isolé par contact_id
///                       (créé via `base_client.isolated_client()`)
///   `ram_fs`          : répertoire RAM temporaire (state + cache Tor)
///                       wipe au Drop
///
/// Chaque appel à `get_or_create_isolated_client(contact_id)` :
///   • Retourne le TorClient isolé déjà créé si présent
///   • Sinon, crée un nouveau client isolé, le stocke, et le retourne
///
/// Les circuits Tor sont isolés entre contacts : le réseau ne peut
/// pas corréler les flux de deux contacts différents.
/// ─────────────────────────────────────────────────────────────────────
pub struct TorTransport {
    /// Client Tor de base (partagé, cloneable).
    base_client: TorClient<TokioRustlsRuntime>,

    /// Clients isolés par contact.
    /// Clé = contact_id (typiquement hex d'une pubkey ed25519).
    isolated_clients: Arc<RwLock<HashMap<String, TorClient<TokioRustlsRuntime>>>>,

    /// Répertoire RAM (state + cache Tor), wipe au Drop.
    ram_fs: Option<TempDir>,
}

impl TorTransport {
    /// Bootstrap un nouveau `TorTransport`.
    ///
    /// **Coûteux** (~30-60 s la première fois, Tor doit établir son
    /// premier circuit). À n'appeler qu'une fois par session.
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
            ram_fs: Some(ram_fs),
        })
    }

    /// Récupère (ou crée) le client isolé pour un contact donné.
    ///
    /// Premier appel : crée un nouveau client isolé (`base.isolated_client()`)
    /// et le stocke.
    ///
    /// Appels suivants : retourne le client déjà stocké.
    ///
    /// Chaque client isolé utilise des circuits Tor distincts — aucune
    /// corrélation possible entre les flux de deux contacts.
    pub async fn get_or_create_isolated_client(
        &self,
        contact_id: &str,
    ) -> Result<TorClient<TokioRustlsRuntime>, Box<dyn Error>> {
        // 1. Tentative de lecture (chemin rapide)
        {
            let map = self.isolated_clients.read().await;
            if let Some(client) = map.get(contact_id) {
                return Ok(client.clone());
            }
        }

        // 2. Création (chemin lent)
        let new_client = self.base_client.isolated_client();

        // 3. Insertion (double check pour éviter la race)
        {
            let mut map = self.isolated_clients.write().await;
            // Si un autre thread a inséré entre-temps, on réutilise son client.
            if let Some(existing) = map.get(contact_id) {
                return Ok(existing.clone());
            }
            map.insert(contact_id.to_string(), new_client.clone());
        }

        Ok(new_client)
    }

    /// Nombre de contacts ayant un client isolé actif.
    pub async fn isolated_client_count(&self) -> usize {
        self.isolated_clients.read().await.len()
    }

    /// Force le drop du client isolé d'un contact.
    ///
    /// Utilisé par la rotation de circuit (P0-A.1d.3) : fermer le client
    /// isolé ferme tous ses circuits. Le prochain appel à
    /// `get_or_create_isolated_client(contact_id)` créera un nouveau client
    /// (donc de nouveaux circuits).
    pub async fn drop_isolated_client(&self, contact_id: &str) {
        let mut map = self.isolated_clients.write().await;
        map.remove(contact_id);
    }

    /// Accès au client de base (pour tests et usages futurs).
    pub fn base_client(&self) -> &TorClient<TokioRustlsRuntime> {
        &self.base_client
    }
}

impl Drop for TorTransport {
    fn drop(&mut self) {
        // Drop des clients isolés (ferme leurs circuits).
        // Le RwLock est dropé avec le struct, ce qui drop les TorClient.
        // On ne peut pas await ici (Drop est sync), donc on laisse
        // tokio::sync::RwLock gérer.

        if let Some(temp_dir) = self.ram_fs.take() {
            let path = temp_dir.path().to_path_buf();
            secure_wipe_dir(&path);
            let _ = temp_dir.close();
        }
    }
}

// =========================================================================
// Utilitaires partagés
// =========================================================================

/// Écrase récursivement les fichiers d'un dossier (patterns zéros) puis
/// supprime le dossier.
///
/// Utilisé par les `Drop` de `AegisTorClient` et `TorTransport`.
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

    /// Test hérité de l'ancien `tor.rs`.
    /// Vérifie que `Zeroize` fonctionne sur un buffer 32 octets.
    /// (Ce test est faible — il ne teste pas réellement AegisTorClient.
    ///  Il sera renforcé ou remplacé en P0-A.7 doc.)
    #[test]
    fn test_tor_client_instantiation_and_wipe() {
        let mut dummy_key = [0x42u8; 32];
        assert_eq!(dummy_key.len(), 32);
        dummy_key.zeroize();
        assert_eq!(dummy_key, [0u8; 32]);
    }

    /// Vérifie que `TorTransport::bootstrap()` compile et réussit.
    ///
    /// **⚠️ Ce test est lent** (~30-60 s : bootstrap Tor réel).
    /// Il est `#[ignore]` par défaut, à activer manuellement :
    ///   `cargo test --lib tor::tests::test_tor_transport_bootstrap -- --ignored`
    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_bootstrap() {
        let result = TorTransport::bootstrap().await;
        assert!(result.is_ok(), "bootstrap Tor échoué: {:?}", result.err());
        let transport = result.unwrap();
        assert_eq!(transport.isolated_client_count().await, 0);
    }

    /// Vérifie qu'un même `contact_id` retourne toujours le même client isolé.
    ///
    /// **⚠️ Ce test est lent** (bootstrap Tor requis).
    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_reuses_existing_isolated_client() {
        let transport = TorTransport::bootstrap().await.expect("bootstrap");

        // Premier appel : crée le client isolé
        let _client_1 = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("create alice");

        // Deuxième appel : réutilise le même client
        let _client_2 = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("reuse alice");

        assert_eq!(
            transport.isolated_client_count().await,
            1,
            "un seul client isolé pour un seul contact"
        );
    }

    /// Vérifie que deux contacts différents obtiennent deux clients isolés distincts.
    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_creates_isolated_client_per_contact() {
        let transport = TorTransport::bootstrap().await.expect("bootstrap");

        let _alice = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("create alice");

        let _bob = transport
            .get_or_create_isolated_client("contact_bob")
            .await
            .expect("create bob");

        assert_eq!(
            transport.isolated_client_count().await,
            2,
            "deux contacts → deux clients isolés"
        );
    }

    /// Vérifie que `drop_isolated_client` retire bien le contact.
    #[tokio::test]
    #[ignore = "slow: requires real Tor network bootstrap (~30-60s)"]
    #[cfg_attr(miri, ignore)]
    async fn test_tor_transport_drops_isolated_client() {
        let transport = TorTransport::bootstrap().await.expect("bootstrap");

        let _alice = transport
            .get_or_create_isolated_client("contact_alice")
            .await
            .expect("create alice");

        assert_eq!(transport.isolated_client_count().await, 1);

        transport.drop_isolated_client("contact_alice").await;

        assert_eq!(
            transport.isolated_client_count().await,
            0,
            "après drop → 0 client isolé"
        );
    }
}