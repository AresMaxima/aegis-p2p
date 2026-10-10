//! aegis-core/src/network/wifi_direct.rs
//!
//! Transport Wi-Fi Direct — implémentation de `EncryptedTransport`
//! avec handshake ed25519 symétrique.
//!
//! ─────────────────────────────────────────────────────────────────────
//! P0-A.2b.3b (2026-10-10) : pipeline de chiffrement.
//! P0-A.2b.3c (2026-10-11) : handshake ed25519 post-connexion.
//!
//! ─────────────────────────────────────────────────────────────────────
//! Handshake symétrique (Q1=A, Q2=B, Q3=ajusté, Q4=10s, Q5=A) :
//!
//!   [Initiator]                          [Responder]
//!   nonce_I || pubkey_I          ────→
//!                                ←────  nonce_R || pubkey_R || sig_R(nonce_I)
//!   sig_I(nonce_R)               ────→
//!
//! Chacun vérifie :
//!   1. SHA-256(pubkey_X) == fingerprint_X (du QR code)
//!   2. sig_X(nonce_Y) est valide contre pubkey_X
//!
//! Fail-closed : si une vérification échoue → TransportError, pas de
//! construction du transport, disconnect.
//!
//! Décisions actées :
//!   • D40  : Chiffrement applicatif obligatoire (fail-closed)
//!   • D56  : P2PFramePacker après Ratchet::encrypt
//!   • D58  : FRAME_SIZE 512 B indépendant du transport
//!   • Opt.2 : préfixe u32 BE ciphertext_len
//!   • D3   : manual pairing (deviceName + fingerprint ed25519)
//!   • Q1=A : handshake dans from_global_fd (fail-closed)
//!   • Q2=B : fingerprint = SHA-256(pubkey) (32 octets)
//!   • Q4=10s : timeout handshake
//! ─────────────────────────────────────────────────────────────────────

use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::crypto::ratchet::RatchetSession;
use crate::network::encrypted_transport::{EncryptedTransport, TransportError};
use crate::network::p2p_transfer::{MetadataStripper, P2PFramePacker, FRAME_SIZE, HEADER_SIZE};
use crate::secure_buffer::SecureBuffer;

/// Timeout global du handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Taille d'un nonce (32 octets).
const NONCE_LEN: usize = 32;

/// Taille d'une pubkey ed25519 (32 octets).
const PUBKEY_LEN: usize = 32;

/// Taille d'une signature ed25519 (64 octets).
const SIG_LEN: usize = 64;

/// Taille d'une fingerprint SHA-256 (32 octets).
const FINGERPRINT_LEN: usize = 32;

/// Transport Wi-Fi Direct — wraps un `TcpStream` Tokio sur le fd fourni
/// par Kotlin via JNI, après authentification ed25519 du peer.
#[derive(Debug)]
pub struct WifiDirectTransport {
    stream: Arc<Mutex<TcpStream>>,
    /// Pubkey ed25519 du peer, vérifiée pendant le handshake.
    peer_pubkey: [u8; PUBKEY_LEN],
}

impl WifiDirectTransport {
    /// Récupère le fd du socket Wi-Fi Direct, l'authentifie via un
    /// handshake ed25519 symétrique, et retourne le transport prêt.
    ///
    /// # Arguments
    /// - `expected_peer_fingerprint` : SHA-256(pubkey_peer), obtenu du QR code
    /// - `is_initiator` : true si ce device a initié la connexion Wi-Fi Direct
    ///
    /// # Erreurs
    /// - `TransportUnavailable` : pas de fd, handshake timeout
    /// - `DecryptionFailed` : handshake échoué (fingerprint mismatch, sig invalide)
    /// - `IoError` : erreur réseau
    /// - `EncryptionFailed` : impossible de signer (master_key indisponible)
    pub async fn from_global_fd(
        expected_peer_fingerprint: [u8; FINGERPRINT_LEN],
        is_initiator: bool,
    ) -> Result<Self, TransportError> {
        let fd = crate::take_wifi_direct_fd();
        if fd < 0 {
            return Err(TransportError::TransportUnavailable(
                "no Wi-Fi Direct fd available (Kotlin has not transmitted one)".to_string(),
            ));
        }
        let mut transport = Self::from_fd(fd)?;

        // Handshake avec timeout global
        let hs = timeout(
            HANDSHAKE_TIMEOUT,
            transport.perform_handshake(expected_peer_fingerprint, is_initiator),
        )
        .await;

        match hs {
            Ok(Ok(peer_pubkey)) => {
                transport.peer_pubkey = peer_pubkey;
                Ok(transport)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(TransportError::TransportUnavailable(
                "handshake timeout (10s)".to_string(),
            )),
        }
    }

    /// Transforme un fd brut en `WifiDirectTransport` (sans handshake).
    ///
    /// Le champ `peer_pubkey` est initialisé à zéro — il DOIT être rempli
    /// par `perform_handshake` avant utilisation.
    ///
    /// **Ne pas utiliser directement** en production : préférer `from_global_fd`.
    #[cfg(unix)]
    pub fn from_fd(fd: i32) -> Result<Self, TransportError> {
        use std::net::TcpStream as StdTcpStream;
        use std::os::fd::FromRawFd;

        // SAFETY : fd vient d'un socket TCP vérifié côté Kotlin (>= 0).
        let std_stream = unsafe { StdTcpStream::from_raw_fd(fd) };

        std_stream
            .set_nonblocking(true)
            .map_err(|e| TransportError::IoError(format!("set_nonblocking: {}", e)))?;

        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| TransportError::IoError(format!("from_std: {}", e)))?;

        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            peer_pubkey: [0u8; PUBKEY_LEN],
        })
    }

    /// Stub Windows : Wi-Fi Direct n'existe pas côté serveur.
    #[cfg(not(unix))]
    pub fn from_fd(_fd: i32) -> Result<Self, TransportError> {
        Err(TransportError::TransportUnavailable(
            "Wi-Fi Direct transport not supported on this platform".to_string(),
        ))
    }

    /// Pubkey ed25519 du peer authentifiée pendant le handshake.
    pub fn peer_pubkey(&self) -> &[u8; PUBKEY_LEN] {
        &self.peer_pubkey
    }

    /// Handshake ed25519 symétrique.
    ///
    /// Retourne la pubkey du peer (vérifiée) en cas de succès.
    async fn perform_handshake(
        &mut self,
        expected_peer_fingerprint: [u8; FINGERPRINT_LEN],
        is_initiator: bool,
    ) -> Result<[u8; PUBKEY_LEN], TransportError> {
        // 1. Générer notre nonce (OsRng) et récupérer notre pubkey
        let mut my_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut my_nonce);

        let my_pubkey = my_pubkey_from_identity()?;

        if is_initiator {
            self.handshake_as_initiator(my_nonce, my_pubkey, expected_peer_fingerprint)
                .await
        } else {
            self.handshake_as_responder(my_nonce, my_pubkey, expected_peer_fingerprint)
                .await
        }
    }

    /// Handshake côté initiator (envoie en premier).
    async fn handshake_as_initiator(
        &self,
        my_nonce: [u8; NONCE_LEN],
        my_pubkey: [u8; PUBKEY_LEN],
        expected_peer_fingerprint: [u8; FINGERPRINT_LEN],
    ) -> Result<[u8; PUBKEY_LEN], TransportError> {
        // Msg 1 : envoyer nonce_I || pubkey_I (64 octets)
        let mut msg1 = [0u8; NONCE_LEN + PUBKEY_LEN];
        msg1[..NONCE_LEN].copy_from_slice(&my_nonce);
        msg1[NONCE_LEN..].copy_from_slice(&my_pubkey);
        self.write_all(&msg1).await?;

        // Msg 2 : recevoir nonce_R || pubkey_R || sig_R(nonce_I) (128 octets)
        let mut msg2 = [0u8; NONCE_LEN + PUBKEY_LEN + SIG_LEN];
        self.read_exact(&mut msg2).await?;

        let peer_nonce: [u8; NONCE_LEN] = msg2[..NONCE_LEN].try_into().unwrap();
        let peer_pubkey: [u8; PUBKEY_LEN] =
            msg2[NONCE_LEN..NONCE_LEN + PUBKEY_LEN].try_into().unwrap();
        let peer_sig: [u8; SIG_LEN] =
            msg2[NONCE_LEN + PUBKEY_LEN..].try_into().unwrap();

        // Vérification 1 : SHA-256(pubkey_R) == fingerprint_R (du QR)
        verify_fingerprint(&peer_pubkey, &expected_peer_fingerprint)?;

        // Vérification 2 : sig_R(nonce_I) valide contre pubkey_R
        if !crate::ed25519_verify_safe(&my_nonce, &peer_pubkey, &peer_sig) {
            return Err(TransportError::DecryptionFailed(
                "handshake: sig_R(nonce_I) invalid".to_string(),
            ));
        }

        // Msg 3 : envoyer sig_I(nonce_R) (64 octets)
        let my_sig = crate::ed25519_sign_safe(&peer_nonce)
            .map_err(|e| TransportError::EncryptionFailed(e))?;
        self.write_all(&my_sig).await?;

        Ok(peer_pubkey)
    }

    /// Handshake côté responder (attend en premier).
    async fn handshake_as_responder(
        &self,
        my_nonce: [u8; NONCE_LEN],
        my_pubkey: [u8; PUBKEY_LEN],
        expected_peer_fingerprint: [u8; FINGERPRINT_LEN],
    ) -> Result<[u8; PUBKEY_LEN], TransportError> {
        // Msg 1 : recevoir nonce_I || pubkey_I (64 octets)
        let mut msg1 = [0u8; NONCE_LEN + PUBKEY_LEN];
        self.read_exact(&mut msg1).await?;

        let peer_nonce: [u8; NONCE_LEN] = msg1[..NONCE_LEN].try_into().unwrap();
        let peer_pubkey: [u8; PUBKEY_LEN] = msg1[NONCE_LEN..].try_into().unwrap();

        // Vérification 1 : SHA-256(pubkey_I) == fingerprint_I (du QR)
        verify_fingerprint(&peer_pubkey, &expected_peer_fingerprint)?;

        // Msg 2 : envoyer nonce_R || pubkey_R || sig_R(nonce_I) (128 octets)
        let my_sig = crate::ed25519_sign_safe(&peer_nonce)
            .map_err(|e| TransportError::EncryptionFailed(e))?;
        let mut msg2 = [0u8; NONCE_LEN + PUBKEY_LEN + SIG_LEN];
        msg2[..NONCE_LEN].copy_from_slice(&my_nonce);
        msg2[NONCE_LEN..NONCE_LEN + PUBKEY_LEN].copy_from_slice(&my_pubkey);
        msg2[NONCE_LEN + PUBKEY_LEN..].copy_from_slice(&my_sig);
        self.write_all(&msg2).await?;

        // Msg 3 : recevoir sig_I(nonce_R) (64 octets)
        let mut peer_sig = [0u8; SIG_LEN];
        self.read_exact(&mut peer_sig).await?;

        // Vérification 2 : sig_I(nonce_R) valide contre pubkey_I
        if !crate::ed25519_verify_safe(&my_nonce, &peer_pubkey, &peer_sig) {
            return Err(TransportError::DecryptionFailed(
                "handshake: sig_I(nonce_R) invalid".to_string(),
            ));
        }

        Ok(peer_pubkey)
    }

    // ===== Helpers I/O =====

    async fn write_all(&self, data: &[u8]) -> Result<(), TransportError> {
        let mut stream = self.stream.lock().await;
        stream
            .write_all(data)
            .await
            .map_err(|e| TransportError::IoError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| TransportError::IoError(e.to_string()))?;
        Ok(())
    }

    async fn read_exact(&self, buf: &mut [u8]) -> Result<(), TransportError> {
        let mut stream = self.stream.lock().await;
        stream
            .read_exact(buf)
            .await
            .map_err(|e| TransportError::IoError(e.to_string()))?;
        Ok(())
    }
}

/// Récupère notre pubkey ed25519 via l'identité dérivée.
fn my_pubkey_from_identity() -> Result<[u8; PUBKEY_LEN], TransportError> {
    // On utilise la FFI fingerprint pour récupérer indirectement la pubkey
    // via le helper. En réalité, on veut juste la pubkey ed25519 du device.
    let mut pk = [0u8; PUBKEY_LEN];
    let rc = unsafe { crate::aegis_ed25519_public_key(pk.as_mut_ptr()) };
    if rc != 0 {
        return Err(TransportError::EncryptionFailed(format!(
            "aegis_ed25519_public_key rc={}",
            rc
        )));
    }
    Ok(pk)
}

/// Vérifie que SHA-256(pubkey) == expected_fingerprint.
fn verify_fingerprint(
    pubkey: &[u8; PUBKEY_LEN],
    expected: &[u8; FINGERPRINT_LEN],
) -> Result<(), TransportError> {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let computed = hasher.finalize();

    if computed.as_slice() != expected.as_slice() {
        return Err(TransportError::DecryptionFailed(
            "handshake: fingerprint mismatch".to_string(),
        ));
    }
    Ok(())
}

#[allow(async_fn_in_trait)]
impl EncryptedTransport for WifiDirectTransport {
    async fn send_encrypted(
        &self,
        session: &mut RatchetSession,
        plaintext: &[u8],
    ) -> Result<(), TransportError> {
        let mut sb = SecureBuffer::new(plaintext.len());
        sb.as_slice_mut().copy_from_slice(plaintext);

        let stripped = MetadataStripper::strip_and_normalize(&sb);

        let ciphertext = session
            .encrypt(stripped.as_slice())
            .map_err(|e| TransportError::EncryptionFailed(e))?;

        let mut prefixed = Vec::with_capacity(4 + ciphertext.len());
        prefixed.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        prefixed.extend_from_slice(&ciphertext);

        let frames = P2PFramePacker::pack_payload(&prefixed);

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

        let mut first_frame = [0u8; FRAME_SIZE];
        stream
            .read_exact(&mut first_frame)
            .await
            .map_err(|e| TransportError::IoError(e.to_string()))?;

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

        let ciphertext = &prefixed[4..4 + ciphertext_len];

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

    /// Aucun fd disponible → `from_global_fd` échoue (même après handshake).
    #[tokio::test]
    async fn test_wifi_direct_from_global_no_fd() {
        let _ = crate::take_wifi_direct_fd();

        let fp = [0u8; FINGERPRINT_LEN];
        let result = WifiDirectTransport::from_global_fd(fp, true).await;
        assert!(result.is_err());
        match result {
            Err(TransportError::TransportUnavailable(_)) => {}
            other => panic!("attendu TransportUnavailable, obtenu {:?}", other),
        }
    }

    /// `verify_fingerprint` accepte un match exact.
    #[test]
    fn test_verify_fingerprint_accepts_match() {
        let pubkey = [0x42u8; PUBKEY_LEN];
        let mut hasher = Sha256::new();
        hasher.update(&pubkey);
        let expected: [u8; FINGERPRINT_LEN] = hasher.finalize().into();

        assert!(verify_fingerprint(&pubkey, &expected).is_ok());
    }

    /// `verify_fingerprint` rejette un mismatch.
    #[test]
    fn test_verify_fingerprint_rejects_mismatch() {
        let pubkey = [0x42u8; PUBKEY_LEN];
        let wrong_fp = [0x99u8; FINGERPRINT_LEN];

        let result = verify_fingerprint(&pubkey, &wrong_fp);
        assert!(result.is_err());
        match result {
            Err(TransportError::DecryptionFailed(_)) => {}
            other => panic!("attendu DecryptionFailed, obtenu {:?}", other),
        }
    }

    /// Roundtrip handshake symétrique : initiator ↔ responder.
    ///
    /// ⚠️ Test `#[ignore]` — nécessite une master_key déverrouillée
    /// ET un socket pair.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires unlocked master_key + socket pair (test P0-A.2b.5)"]
    async fn test_handshake_symmetric_roundtrip() {
        // TODO : créer un socket pair (TcpListener + TcpStream loopback),
        // construire 2 WifiDirectTransport::from_fd,
        // lancer handshake_as_initiator sur l'un, handshake_as_responder
        // sur l'autre (via tokio::join!), vérifier que les 2 peer_pubkey
        // correspondent.
    }

    /// Replay du nonce d'un handshake précédent → rejet.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires unlocked master_key + socket pair (test P0-A.2b.5)"]
    async fn test_handshake_rejects_replayed_nonce() {
        // TODO : capturer nonce_I d'un premier handshake, rejouer dans
        // un second → sig_R(nonce_I_old) ne doit pas valider le nouveau
        // nonce_I_new.
    }
}