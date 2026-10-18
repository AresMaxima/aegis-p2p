//! aegis-core/src/updater.rs
//!
//! P0-A.8a (2026-10-18) — Vérification cryptographique des mises à jour.
//! P-6 (Updater in-app) : empêche l'installation d'un APK altéré (MITM).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Structure du manifeste JSON signé (hébergé sur aresmaxima.com).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: String,
    pub apk_url: String,
    pub sha256: String,
    pub force_update: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateError {
    InvalidSignature,
    HashMismatch,
    ParseError,
}

impl UpdateError {
    pub fn to_code(self) -> i32 {
        match self {
            UpdateError::InvalidSignature => -60,
            UpdateError::HashMismatch => -61,
            UpdateError::ParseError => -62,
        }
    }
}

/// Vérifie la signature ed25519 du manifeste.
/// Retourne `Ok(UpdateManifest)` si la signature est valide.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8; 64],
    admin_pubkey: &[u8; 32],
) -> Result<UpdateManifest, UpdateError> {
    // 1. Vérifier la signature ed25519 sur le contenu brut du JSON
    let pubkey = VerifyingKey::from_bytes(admin_pubkey).map_err(|_| UpdateError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature_bytes);

    if pubkey.verify(manifest_bytes, &signature).is_err() {
        return Err(UpdateError::InvalidSignature);
    }

    // 2. Parser le JSON (seulement si la signature est valide)
    let manifest: UpdateManifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| UpdateError::ParseError)?;

    Ok(manifest)
}

/// Vérifie que le hash SHA-256 de l'APK téléchargé correspond à celui du manifeste.
pub fn verify_apk_hash(apk_bytes: &[u8], expected_hash_hex: &str) -> Result<(), UpdateError> {
    let mut hasher = Sha256::new();
    hasher.update(apk_bytes);
    let computed_hash = hex::encode(hasher.finalize());

    if computed_hash != expected_hash_hex {
        return Err(UpdateError::HashMismatch);
    }

    Ok(())
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn generate_test_keypair() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        (signing_key, pubkey)
    }

    #[test]
    fn test_verify_manifest_valid() {
        let (signing_key, pubkey) = generate_test_keypair();
        let manifest_json = br#"{"version":"3.0.9","apk_url":"https://aresmaxima.com/aegis.apk","sha256":"abc123","force_update":false}"#;
        let signature = signing_key.sign(manifest_json);

        let result = verify_manifest(manifest_json, &signature.to_bytes(), &pubkey);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, "3.0.9");
    }

    #[test]
    fn test_verify_manifest_tampered() {
        let (signing_key, pubkey) = generate_test_keypair();
        let manifest_json = br#"{"version":"3.0.9","apk_url":"https://aresmaxima.com/aegis.apk","sha256":"abc123","force_update":false}"#;
        let signature = signing_key.sign(manifest_json);

        // Modification d'un octet (version différente)
        let tampered = br#"{"version":"3.1.0","apk_url":"https://aresmaxima.com/aegis.apk","sha256":"abc123","force_update":false}"#;
        let result = verify_manifest(tampered, &signature.to_bytes(), &pubkey);
        assert_eq!(result, Err(UpdateError::InvalidSignature));
    }

    #[test]
    fn test_verify_apk_hash_valid() {
        let apk_bytes = b"dummy_apk_content";
        let mut hasher = Sha256::new();
        hasher.update(apk_bytes);
        let expected_hash = hex::encode(hasher.finalize());

        assert!(verify_apk_hash(apk_bytes, &expected_hash).is_ok());
    }

    #[test]
    fn test_verify_apk_hash_mismatch() {
        let apk_bytes = b"dummy_apk_content";
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        assert_eq!(
            verify_apk_hash(apk_bytes, wrong_hash),
            Err(UpdateError::HashMismatch)
        );
    }
}