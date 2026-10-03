//! aegis-core/src/network/tor_isolation.rs
//!
//! Isolation par contact Tor — dérivation HKDF-SHA384 du token d'isolation.
//!
//! ─────────────────────────────────────────────────────────────────────
//! DÉCISION D42 (02/10/2026) :
//!   Chaque contact AEGIS obtient un circuit Tor DÉDIÉ.
//!   L'isolation est obtenue en fournissant à Arti un `IsolationToken`
//!   distinct par contact.
//!
//!   IsolationToken = HKDF-SHA384(
//!       ikm  = master_key,
//!       salt = "AEGIS-TOR-ISOLATION",
//!       info = contact_id
//!   )
//!
//! Propriétés :
//!   • Déterministe — même contact → même token à chaque session
//!   • Non-déductible sans master_key — le contact_id seul ne suffit pas
//!   • Indépendant par contact — pas de corrélation possible entre deux
//!     contacts observés depuis le réseau Tor
//!   • Compatible Arti — le token est fourni à `client.connect_with_isolation()`
//!
//! La master_key est récupérée via `HardwareKeystore::get_master_key()`
//! (voir `src/keystore.rs`), jamais lue directement depuis un fichier.
//! ─────────────────────────────────────────────────────────────────────

use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroize;

/// Sel HKDF figé — ne JAMAIS changer sans casser la compatibilité avec
/// les sessions Tor en cours. Si une v2 est nécessaire, créer un
/// nouveau sel (`AEGIS-TOR-ISOLATION-v2`) et gérer la migration.
const TOR_ISOLATION_SALT: &[u8] = b"AEGIS-TOR-ISOLATION";

/// Taille du token d'isolation (32 octets = 256 bits, NIST Level 5).
pub const ISOLATION_TOKEN_LEN: usize = 32;

/// Erreurs de dérivation du token d'isolation.
#[derive(Debug, thiserror::Error)]
pub enum IsolationError {
    /// La master_key n'est pas disponible (vault non déverrouillé).
    #[error("tor isolation: master key unavailable (vault locked?)")]
    MasterKeyUnavailable,

    /// Le `contact_id` est vide — pas d'isolation possible sans identifiant.
    #[error("tor isolation: contact_id must not be empty")]
    EmptyContactId,

    /// HKDF a échoué (taille de sortie invalide, etc.).
    #[error("tor isolation: HKDF derivation failed: {0}")]
    HkdfFailed(String),
}

/// Token d'isolation Tor — 32 octets dérivés par HKDF-SHA384.
///
/// Ce type est **opaque** : il n'expose son contenu qu'à Arti via
/// `as_bytes()`. Zeroize au Drop.
#[derive(Clone)]
pub struct IsolationToken {
    bytes: [u8; ISOLATION_TOKEN_LEN],
}

impl IsolationToken {
    /// Dérive un token d'isolation à partir de la master_key courante
    /// et d'un `contact_id` (typiquement l'empreinte ed25519 du contact,
    /// en hex ou bytes).
    ///
    /// # Erreurs
    /// - `MasterKeyUnavailable` si le vault n'est pas déverrouillé
    /// - `EmptyContactId` si `contact_id` est vide
    /// - `HkdfFailed` si HKDF échoue (ne devrait jamais arriver)
    pub fn derive(contact_id: &str) -> Result<Self, IsolationError> {
        if contact_id.is_empty() {
            return Err(IsolationError::EmptyContactId);
        }

        // Récupération de la master_key depuis le keystore.
        let master_key = crate::keystore::HardwareKeystore::get_master_key()
            .map_err(|_| IsolationError::MasterKeyUnavailable)?;

        // HKDF-SHA384 : cohérent avec D24 (NIST Level 5).
        let hk = Hkdf::<Sha384>::new(Some(TOR_ISOLATION_SALT), master_key.as_slice());

        let mut out = [0u8; ISOLATION_TOKEN_LEN];
        hk.expand(contact_id.as_bytes(), &mut out)
            .map_err(|e| IsolationError::HkdfFailed(format!("{e}")))?;

        Ok(Self { bytes: out })
    }

    /// Accès brut au token (pour Arti).
    ///
    /// Le token ne doit **jamais** être loggé, sérialisé, ou transmis
    /// hors du contexte Tor.
    pub fn as_bytes(&self) -> &[u8; ISOLATION_TOKEN_LEN] {
        &self.bytes
    }

    /// Représentation hex pour debug/tests UNIQUEMENT.
    ///
    /// **Ne pas utiliser en production** — exposerait le token.
    #[cfg(test)]
    pub fn to_hex_for_test(&self) -> String {
        hex::encode(self.bytes)
    }
}

impl Drop for IsolationToken {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for IsolationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ne JAMAIS afficher le token en clair.
        f.debug_struct("IsolationToken")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{HardwareKeystore, TEST_LOCK};

    /// Préparation : ROOT_KEY + PIN → master_key dérivée.
    /// Le TEST_LOCK DOIT être pris par chaque test qui appelle ce helper,
    /// car ROOT_KEY et MASTER_KEY sont des statics globaux partagés
    /// avec les tests de `keystore.rs`.
    fn setup_master_key() {
        let root_key = [0x42u8; 32];
        HardwareKeystore::set_root_key(&root_key).expect("set_root_key failed");
        HardwareKeystore::derive_master_key("TestPIN-TorIsolation").expect("derive failed");
    }

    fn teardown_master_key() {
        let _ = HardwareKeystore::wipe_all();
    }

    /// Token déterministe : même contact_id + même master_key → même token.
    #[test]
    fn test_isolation_token_is_deterministic() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let t1 = IsolationToken::derive("contact_abc123").expect("derive 1");
        let t2 = IsolationToken::derive("contact_abc123").expect("derive 2");

        assert_eq!(
            t1.to_hex_for_test(),
            t2.to_hex_for_test(),
            "même contact_id → même token"
        );

        teardown_master_key();
    }

    /// Deux contact_id différents → tokens différents (anti-corrélation).
    #[test]
    fn test_isolation_token_differs_per_contact() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let t_a = IsolationToken::derive("contact_alice").expect("derive alice");
        let t_b = IsolationToken::derive("contact_bob").expect("derive bob");

        assert_ne!(
            t_a.to_hex_for_test(),
            t_b.to_hex_for_test(),
            "contact_id différents → tokens différents"
        );

        teardown_master_key();
    }

    /// contact_id vide → refus immédiat.
    #[test]
    fn test_isolation_token_rejects_empty_contact_id() {
        // Pas besoin de TEST_LOCK ni de master_key : on échoue AVANT.
        let err = IsolationToken::derive("").unwrap_err();
        assert!(matches!(err, IsolationError::EmptyContactId));
        assert_eq!(
            err.to_string(),
            "tor isolation: contact_id must not be empty"
        );
    }

    /// Vault verrouillé (pas de master_key) → refus.
    #[test]
    fn test_isolation_token_requires_master_key() {
        let _g = TEST_LOCK.lock().unwrap();
        // S'assurer qu'aucune master_key n'est présente.
        let _ = HardwareKeystore::wipe_all();

        let err = IsolationToken::derive("contact_abc123").unwrap_err();
        assert!(matches!(err, IsolationError::MasterKeyUnavailable));
        assert_eq!(
            err.to_string(),
            "tor isolation: master key unavailable (vault locked?)"
        );
    }

    /// Drop zeroize le token (anti-forensics RAM).
    #[test]
    fn test_isolation_token_zeroizes_on_drop() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let mut token = IsolationToken::derive("contact_abc123").expect("derive");
        assert_ne!(token.as_bytes(), &[0u8; ISOLATION_TOKEN_LEN]);

        // Simuler le Drop (zeroize manuel).
        token.bytes.zeroize();
        assert_eq!(token.as_bytes(), &[0u8; ISOLATION_TOKEN_LEN]);

        teardown_master_key();
    }

    /// Debug n'expose PAS le token en clair.
    #[test]
    fn test_isolation_token_debug_is_redacted() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let token = IsolationToken::derive("contact_abc123").expect("derive");
        let debug_str = format!("{token:?}");

        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains(&token.to_hex_for_test()));

        teardown_master_key();
    }
}