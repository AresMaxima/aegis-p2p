//! aegis-core/src/network/wifi_direct.rs
//!
//! Transport Wi-Fi Direct — implémentation de `EncryptedTransport`.
//!
//! ─────────────────────────────────────────────────────────────────────
//! P0-A.2b.3b (2026-10-10) :
//!
//! Ce module prend le fd du socket Wi-Fi Direct (transmis par Kotlin via
//! JNI, stocké dans `WIFI_DIRECT_FD`), le transforme en `TcpStream` Tokio,
//! et implémente le pipeline de chiffrement identique à Tor :
//!
//!   read file / payload
//!     → MetadataStripper::strip_and_normalize
//!     → RatchetSession::encrypt
//!     → préfixe u32 BE (ciphertext_len)
//!     → P2PFramePacker::pack_payload (trames 512 B)
//!     → write_all trame par trame (sur le socket Wi-Fi Direct)
//!
//! Réciproquement pour `recv_decrypted`.
//!
//! ─────────────────────────────────────────────────────────────────────
//! Décisions actées :
//!   • D40 : Chiffrement applicatif obligatoire (fail-closed)
//!   • D56 : P2PFramePacker après Ratchet::encrypt
//!   • D58 : FRAME_SIZE 512 B indépendant du transport
//!   • Opt.2 : préfixe u32 BE ciphertext_len
//!   • Q1=A : from_global_fd (take ownership via swap)
//!   • Q3=A : Arc<Mutex<TcpStream>> (cohérent avec Tor)
//! ─────────────────────────────────────────────────────────────────────

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::crypto::ratchet::RatchetSession;
use crate::network::encrypted_transport::{EncryptedTransport, TransportError};
use crate::network::p2p_transfer::{MetadataStripper, P2PFramePacker, FRAME_SIZE, HEADER_SIZE};
use crate::secure_buffer::SecureBuffer;

/// Transport Wi-Fi Direct — wraps un `TcpStream` Tokio sur le fd fourni
/// par Kotlin via JNI.
///
/// Un transport = un peer. Pas de notion de `contact_id` : le socket est
/// déjà connecté à un peer spécifique.
#[derive(Debug)]
pub struct WifiDirectTransport {
    stream: Arc<Mutex<TcpStream>>,
}

impl WifiDirectTransport {
    /// Récupère le fd du socket Wi-Fi Direct depuis le slot global
    /// (`WIFI_DIRECT_FD`), le met à -1 (take ownership), et le transforme
    /// en `TcpStream` Tokio.
    ///
    /// # Erreurs
    /// - `TransportUnavailable` si aucun fd n'est disponible
    /// - `IoError` si la conversion échoue
    pub fn from_global_fd() -> Result<Self, TransportError> {
        let fd = crate::take_wifi_direct_fd();
        if fd < 0 {
            return Err(TransportError::TransportUnavailable(
                "no Wi-Fi Direct fd available (Kotlin has not transmitted one)".to_string(),
            ));
        }
        Self::from_fd(fd)
    }

    /// Transforme un fd brut en `WifiDirectTransport`.
    ///
    /// Prend ownership du fd : il sera fermé au Drop du `TcpStream`.
    ///
    /// # Sécurité
    /// `fd` doit être un socket TCP valide. Vérifié côté Kotlin
    /// (`aegis_wifi_direct_set_fd` fait un `getsockopt(SO_TYPE) == SOCK_STREAM`).
    #[cfg(unix)]
    pub fn from_fd(fd: i32) -> Result<Self, TransportError> {
        use std::net::TcpStream as StdTcpStream;
        use std::os::fd::FromRawFd;

        // SAFETY : fd vient d'un socket TCP vérifié côté Kotlin.
        // On prend ownership — le fd ne sera plus utilisé ailleurs.
        let std_stream = unsafe { StdTcpStream::from_raw_fd(fd) };

        // Tokio exige un stream non-blocking.
        std_stream
            .set_nonblocking(true)
            .map_err(|e| TransportError::IoError(format!("set_nonblocking: {}", e)))?;

        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| TransportError::IoError(format!("from_std: {}", e)))?;

        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
        })
    }

    /// Stub Windows : Wi-Fi Direct n'existe pas côté serveur.
    #[cfg(not(unix))]
    pub fn from_fd(_fd: i32) -> Result<Self, TransportError> {
        Err(TransportError::TransportUnavailable(
            "Wi-Fi Direct transport not supported on this platform".to_string(),
        ))
    }
}

#[allow(async_fn_in_trait)]
impl EncryptedTransport for WifiDirectTransport {
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

        // 6. Envoi trame par trame + flush
        let mut stream = self.stream.lock().await;
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
        let mut stream = self.stream.lock().await;

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

        // 3. Concaténer les payloads
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
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Aucun fd disponible dans le slot global → `from_global_fd` échoue.
    #[test]
    fn test_wifi_direct_from_global_no_fd() {
        // S'assurer que le slot est vide
        let _ = crate::take_wifi_direct_fd();

        let result = WifiDirectTransport::from_global_fd();
        assert!(result.is_err());
        match result {
            Err(TransportError::TransportUnavailable(_)) => {}
            other => panic!("attendu TransportUnavailable, obtenu {:?}", other),
        }
    }

    /// fd négatif → erreur (via `from_fd` directement).
    #[cfg(unix)]
    #[test]
    fn test_wifi_direct_from_invalid_fd() {
        // -1 n'est pas un fd valide → from_raw_fd va créer un TcpStream
        // invalide, mais set_nonblocking va échouer proprement (EBADF).
        let result = WifiDirectTransport::from_fd(-1);
        assert!(result.is_err(), "fd -1 doit échouer");
    }

    /// Socket TCP valide (loopback) → transport créé avec succès.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_wifi_direct_from_valid_socket() {
        use std::net::TcpListener;
        use std::net::TcpStream as StdTcp;
        use std::os::fd::IntoRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        // Connecter un client dans un thread séparé
        let connector = std::thread::spawn(move || {
            StdTcp::connect(addr).expect("connect")
        });

        // Accepter la connexion côté serveur
        let (accepted, _peer) = listener.accept().expect("accept");
        let _client = connector.join().expect("join");

        // Transférer le fd de `accepted` vers le transport
        let fd = accepted.into_raw_fd();
        let transport = WifiDirectTransport::from_fd(fd).expect("from_fd");

        // Vérifier que le stream est utilisable (peer_addr ne bloque pas)
        let stream = transport.stream.lock().await;
        assert!(stream.peer_addr().is_ok(), "peer_addr doit réussir");
    }

    /// Roundtrip complet : send_encrypted + recv_decrypted sur un socket pair.
    ///
    /// ⚠️ Ce test ne peut pas être exécuté sans une `RatchetSession`
    /// fonctionnelle ET un socket pair. Il est `#[ignore]` par défaut.
    /// À activer en test d'intégration (P0-A.2b.5).
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires full RatchetSession handshake (test P0-A.2b.5)"]
    async fn test_wifi_direct_send_recv_roundtrip() {
        // TODO : créer 2 WifiDirectTransport sur un socket pair,
        // établir une RatchetSession des deux côtés (X3DH), puis
        // vérifier que send_encrypted → recv_decrypted restitue
        // le plaintext.
    }
}