//! aegis-core/src/network/encrypted_transport.rs
//!
//! Trait `EncryptedTransport` — couche obligatoire pour tout transport réseau AEGIS.
//!
//! ─────────────────────────────────────────────────────────────────────
//! RÈGLE D40 : aucun transport ne peut émettre ou recevoir un payload
//! applicatif sans passer par `RatchetSession::encrypt()` /
//! `RatchetSession::decrypt()`. Fail-closed : si aucune session active,
//! `TransportError::NoSession` est retournée.
//!
//! Implémenté par (roadmap P0-A) :
//!   • `TorTransport`         (P0-A.1d)
//!   • `WifiDirectTransport`  (P0-A.2)
//!   • `BleMeshTransport`     (P0-A.3)
//!
//! Décisions actées :
//!   • D38 : Option A — créer Wi-Fi Direct + BLE Mesh réels
//!   • D39 : Tor = colonne vertébrale, Wi-Fi Direct/BLE = canaux locaux
//!   • D40 : Chiffrement applicatif obligatoire, fail-closed
//! ─────────────────────────────────────────────────────────────────────

use thiserror::Error;

use crate::crypto::ratchet::RatchetSession;

/// Erreurs du transport chiffré.
///
/// `NoSession` est l'erreur de fail-closed : retournée quand aucun
/// `RatchetSession` n'est actif. AUCUN octet ne doit sortir de l'appareil
/// dans ce cas (règle D40).
#[derive(Debug, Error)]
pub enum TransportError {
    /// Aucune session Double Ratchet active — fail-closed.
    #[error("encrypted transport: no ratchet session available")]
    NoSession,

    /// Le chiffrement a échoué (clé invalide, état corrompu, etc.).
    #[error("encrypted transport: encryption failed: {0}")]
    EncryptionFailed(String),

    /// Le déchiffrement a échoué (MAC invalide, replay, format incorrect).
    #[error("encrypted transport: decryption failed: {0}")]
    DecryptionFailed(String),

    /// Erreur d'I/O sur le transport sous-jacent (socket, pipe, stream).
    #[error("encrypted transport: I/O error: {0}")]
    IoError(String),

    /// Le transport n'est pas disponible (réseau coupé, peer injoignable).
    #[error("encrypted transport: transport unavailable: {0}")]
    TransportUnavailable(String),

    /// StrongBox requis mais indisponible (D42-bis, fail-closed).
    #[error("encrypted transport: StrongBox required but unavailable")]
    StrongBoxUnavailable,
}

/// Trait obligatoire pour tout transport réseau AEGIS.
///
/// Tout `impl` doit :
///   1. Chiffrer le `plaintext` avec `session.encrypt()` AVANT toute I/O
///   2. Déchiffrer le ciphertext reçu avec `session.decrypt()` AVANT de
///      le rendre à l'appelant
///   3. Refuser (fail-closed) si aucune session n'est fournie
///
/// Le compilateur Rust ne peut pas imposer ces règles (pas d'effets dans
/// le système de types), mais les tests nommés
/// (`test_encrypted_transport_refuses_no_session`,
///  `test_*_refuses_plaintext_without_session`)
/// les vérifient à l'exécution.
#[allow(async_fn_in_trait)]
pub trait EncryptedTransport {
    /// Envoie un payload APRÈS chiffrement Double Ratchet obligatoire.
    ///
    /// # Erreurs
    /// - `NoSession` si aucune session n'est active (fail-closed)
    /// - `EncryptionFailed` si le chiffrement échoue
    /// - `IoError` si l'écriture sur le transport échoue
    /// - `TransportUnavailable` si le peer est injoignable
    async fn send_encrypted(
        &self,
        session: &mut RatchetSession,
        plaintext: &[u8],
    ) -> Result<(), TransportError>;

    /// Reçoit un payload et le déchiffre.
    ///
    /// # Erreurs
    /// - `NoSession` si aucune session n'est active (fail-closed)
    /// - `DecryptionFailed` si le déchiffrement échoue (MAC, replay, format)
    /// - `IoError` si la lecture sur le transport échoue
    async fn recv_decrypted(
        &self,
        session: &mut RatchetSession,
    ) -> Result<Vec<u8>, TransportError>;
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie que `TransportError::NoSession` est un variant distinct
    /// avec le bon message (fail-closed, règle D40).
    #[test]
    fn test_transport_error_no_session_is_distinct() {
        let err = TransportError::NoSession;
        assert!(matches!(err, TransportError::NoSession));
        assert_eq!(
            err.to_string(),
            "encrypted transport: no ratchet session available"
        );
    }

    /// Vérifie que `StrongBoxUnavailable` est un variant distinct
    /// (D42-bis, fail-closed quand StrongBox est requis mais absent).
    #[test]
    fn test_transport_error_strongbox_unavailable_is_distinct() {
        let err = TransportError::StrongBoxUnavailable;
        assert!(matches!(err, TransportError::StrongBoxUnavailable));
        assert_eq!(
            err.to_string(),
            "encrypted transport: StrongBox required but unavailable"
        );
    }

    /// Vérifie que les erreurs paramétrées formatent correctement
    /// (thiserror) avec le contenu fourni.
    #[test]
    fn test_transport_error_display_formats() {
        let e1 = TransportError::EncryptionFailed("bad key".to_string());
        assert!(e1.to_string().contains("bad key"));
        assert!(e1.to_string().starts_with("encrypted transport: encryption failed"));

        let e2 = TransportError::DecryptionFailed("MAC mismatch".to_string());
        assert!(e2.to_string().contains("MAC mismatch"));
        assert!(e2.to_string().starts_with("encrypted transport: decryption failed"));

        let e3 = TransportError::IoError("connection reset".to_string());
        assert!(e3.to_string().contains("connection reset"));
        assert!(e3.to_string().starts_with("encrypted transport: I/O error"));

        let e4 = TransportError::TransportUnavailable("peer offline".to_string());
        assert!(e4.to_string().contains("peer offline"));
        assert!(e4.to_string().starts_with("encrypted transport: transport unavailable"));
    }

    /// Vérifie que tous les variants sont bien distincts (anti-régression
    /// si quelqu'un ajoute un variant par erreur dans le futur).
    #[test]
    fn test_transport_error_all_variants_distinct() {
        let variants = [
            TransportError::NoSession,
            TransportError::EncryptionFailed("x".to_string()),
            TransportError::DecryptionFailed("x".to_string()),
            TransportError::IoError("x".to_string()),
            TransportError::TransportUnavailable("x".to_string()),
            TransportError::StrongBoxUnavailable,
        ];

        // Chaque variant a un message unique.
        let mut seen = std::collections::HashSet::new();
        for v in &variants {
            assert!(seen.insert(v.to_string()), "duplicate error message: {}", v);
        }
        assert_eq!(seen.len(), 6);
    }
}