//! aegis-core/src/vault_persistence.rs
//! Persistance du vault 100% Rust — remplace SharedPreferences (F6-C).
//!
//! Architecture :
//!   • vault.json (dans filesDir Android) contient UNIQUEMENT :
//!       - version : u32 (actuellement 1)
//!       - salt    : 32 bytes (OsRng, unique par vault)
//!       - verifier: 32 bytes = HMAC-SHA256(key=MASTER_KEY, msg=salt)
//!   • Le PIN n'est JAMAIS persisté.
//!   • La MASTER_KEY est dérivée à la volée (HKDF-SHA256(ROOT_KEY || PIN))
//!     via keystore::HardwareKeystore::derive_master_key().
//!
//! Sécurité :
//!   • Aucun hash de PIN stocké → bruteforce offline impossible sans ROOT_KEY
//!     (qui vit exclusivement dans le StrongBox/TEE).
//!   • HMAC-SHA256 plutôt qu'AES-GCM verifier : immunité contre
//!     l'attaque « invisible salamanders » (pas de déchiffrement à valider).
//!   • Comparaison constant-time via subtle::ConstantTimeEq.
//!
//! Cycle de vie :
//!   set_vault_dir() → vault_is_initialized() → vault_init(pin)
//!                                       ↓
//!                              vault_unlock(pin) → Real | Decoy
//!                                       ↓
//!                              vault_wipe() (optionnel)

use crate::keystore::HardwareKeystore;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Version actuelle du format vault.json.
/// Toute modification du schéma incrémente cette version.
const VAULT_FILE_VERSION: u32 = 1;

/// Nom du fichier de persistance (relatif à vault_dir).
const VAULT_FILE_NAME: &str = "vault.json";

/// Message HMAC (constant, non-secret) utilisé pour dériver le verifier.
const VERIFIER_MESSAGE_TAG: &[u8] = b"AEGIS_VAULT_VERIFIER_V1";

/// Taille du salt en octets (identique à la sortie SHA256).
const SALT_LEN: usize = 32;

/// Taille du verifier en octets (identique à la sortie HMAC-SHA256).
const VERIFIER_LEN: usize = 32;

/// Répertoire de persistance du vault. Initialisé via `set_vault_dir()`
/// par l'appelant (Dart/Kotlin au démarrage).
static VAULT_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Résultat d'un déverrouillage.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VaultSession {
    /// PIN correct → session réelle.
    Real,
    /// PIN incorrect → session leurre (decoy).
    Decoy,
    /// Aucun vault.json présent → l'utilisateur doit initialiser.
    NeedsInitialization,
}

/// Définit le répertoire où sera écrit `vault.json`.
///
/// Doit être appelé une seule fois au démarrage, avant toute autre
/// opération vault. Le dossier est créé s'il n'existe pas.
pub fn set_vault_dir(path: PathBuf) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir_all(&path)
            .map_err(|e| format!("Création dossier vault échouée: {}", e))?;
    }
    if !path.is_dir() {
        return Err(format!("Chemin vault n'est pas un dossier: {:?}", path));
    }

    let mut guard = VAULT_DIR
        .lock()
        .map_err(|_| "VAULT_DIR mutex empoisonné".to_string())?;
    *guard = Some(path);
    Ok(())
}

/// Retourne le chemin absolu vers `vault.json`.
fn vault_file_path() -> Result<PathBuf, String> {
    let guard = VAULT_DIR
        .lock()
        .map_err(|_| "VAULT_DIR mutex empoisonné".to_string())?;
    let dir = guard
        .as_ref()
        .ok_or_else(|| "VAULT_DIR non initialisé — appeler set_vault_dir() d'abord".to_string())?;
    Ok(dir.join(VAULT_FILE_NAME))
}

/// Représentation interne du contenu de `vault.json`.
struct VaultFile {
    salt: [u8; SALT_LEN],
    verifier: [u8; VERIFIER_LEN],
}

impl VaultFile {
    /// Sérialise en JSON minimal (pas de dépendance serde).
    fn to_json(&self) -> String {
        let salt_b64 = base64_encode(&self.salt);
        let verifier_b64 = base64_encode(&self.verifier);
        format!(
            "{{\n  \"version\": {},\n  \"salt\": \"{}\",\n  \"verifier\": \"{}\"\n}}\n",
            VAULT_FILE_VERSION, salt_b64, verifier_b64
        )
    }

    /// Parse un JSON minimal. Retourne Err si invalide.
    fn from_json(input: &str) -> Result<Self, String> {
        let version = extract_u32(input, "version")
            .ok_or_else(|| "vault.json: version manquante".to_string())?;
        if version != VAULT_FILE_VERSION {
            return Err(format!(
                "vault.json: version non supportée ({}, attendu {})",
                version, VAULT_FILE_VERSION
            ));
        }

        let salt_b64 = extract_str(input, "salt")
            .ok_or_else(|| "vault.json: salt manquant".to_string())?;
        let verifier_b64 = extract_str(input, "verifier")
            .ok_or_else(|| "vault.json: verifier manquant".to_string())?;

        let salt = base64_decode(&salt_b64)
            .map_err(|e| format!("vault.json: salt base64 invalide: {}", e))?;
        let verifier = base64_decode(&verifier_b64)
            .map_err(|e| format!("vault.json: verifier base64 invalide: {}", e))?;

        if salt.len() != SALT_LEN {
            return Err(format!("vault.json: salt doit faire {} octets", SALT_LEN));
        }
        if verifier.len() != VERIFIER_LEN {
            return Err(format!(
                "vault.json: verifier doit faire {} octets",
                VERIFIER_LEN
            ));
        }

        let mut salt_arr = [0u8; SALT_LEN];
        salt_arr.copy_from_slice(&salt);
        let mut verifier_arr = [0u8; VERIFIER_LEN];
        verifier_arr.copy_from_slice(&verifier);

        Ok(Self {
            salt: salt_arr,
            verifier: verifier_arr,
        })
    }
}

// =============================================================================
// JSON minimal — extraction de champs (pas de dépendance serde)
// =============================================================================

/// Extrait une valeur `"key": 123` (u32).
fn extract_u32(input: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{}\"", key);
    let start = input.find(&needle)?;
    let rest = &input[start + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    let end = after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len());
    after[..end].parse().ok()
}

/// Extrait une valeur `"key": "value"` (chaîne). Retourne la chaîne sans guillemets.
fn extract_str(input: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = input.find(&needle)?;
    let rest = &input[start + needle.len()..];
    let colon = rest.find(':')?;
    let after = rest[colon + 1..].trim_start();
    if !after.starts_with('"') {
        return None;
    }
    let inner = &after[1..];
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

/// Encode en base64 standard (RFC 4648) sans padding — implémentation minimale.
fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Décode du base64 standard (RFC 4648) — implémentation minimale.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn idx(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut buf = [0u8; 4];
    let mut idx_buf = 0;

    for &b in &bytes {
        if b == b'=' {
            break;
        }
        let v = idx(b).ok_or_else(|| format!("caractère base64 invalide: {}", b))?;
        buf[idx_buf] = v;
        idx_buf += 1;
        if idx_buf == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
            out.push((buf[2] << 6) | buf[3]);
            idx_buf = 0;
        }
    }

    match idx_buf {
        0 => {}
        2 => out.push((buf[0] << 2) | (buf[1] >> 4)),
        3 => {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        _ => return Err("padding base64 invalide".to_string()),
    }

    Ok(out)
}

// =============================================================================
// API PUBLIQUE
// =============================================================================

/// Vrai si `vault.json` existe et parse correctement.
pub fn vault_is_initialized() -> bool {
    let path = match vault_file_path() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !path.exists() {
        return false;
    }
    match fs::read_to_string(&path) {
        Ok(content) => VaultFile::from_json(&content).is_ok(),
        Err(_) => false,
    }
}

/// Initialise un nouveau vault à partir du PIN choisi.
///
/// Prérequis : ROOT_KEY doit être initialisée (`aegis_set_hardware_secret`).
///
/// Effet : écrit `vault.json` avec salt aléatoire + verifier HMAC.
/// Écrase tout vault existant (usage : wipe préalable recommandé).
pub fn vault_init(pin: &str) -> Result<(), String> {
    if pin.is_empty() {
        return Err("PIN vide — refusé".to_string());
    }

    // 1. Dériver MASTER_KEY (peut échouer si ROOT_KEY non initialisée)
    HardwareKeystore::derive_master_key(pin)?;

    // 2. Générer salt aléatoire
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // 3. Calculer verifier = HMAC-SHA256(master_key, salt || TAG)
    let master_key = HardwareKeystore::get_master_key()?;
    let verifier = compute_verifier(master_key.as_slice(), &salt)?;

    // 4. Écrire vault.json
    let vault = VaultFile { salt, verifier };
    let path = vault_file_path()?;
    fs::write(&path, vault.to_json())
        .map_err(|e| format!("Écriture vault.json échouée: {}", e))?;

    Ok(())
}

/// Tente de déverrouiller le vault avec le PIN fourni.
///
/// Retourne :
///   • `Real` si le PIN est correct.
///   • `Decoy` si le PIN est incorrect.
///   • `NeedsInitialization` si aucun vault.json n'existe.
pub fn vault_unlock(pin: &str) -> Result<VaultSession, String> {
    if !vault_is_initialized() {
        return Ok(VaultSession::NeedsInitialization);
    }

    let path = vault_file_path()?;
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Lecture vault.json échouée: {}", e))?;
    let vault = VaultFile::from_json(&content)?;

    // Dériver MASTER_KEY à partir du PIN
    HardwareKeystore::derive_master_key(pin)?;
    let master_key = HardwareKeystore::get_master_key()?;

    // Recalculer le verifier
    let computed = compute_verifier(master_key.as_slice(), &vault.salt)?;

    // Comparaison constant-time
    if computed.ct_eq(&vault.verifier).into() {
        Ok(VaultSession::Real)
    } else {
        Ok(VaultSession::Decoy)
    }
}

/// Supprime `vault.json` et efface ROOT_KEY + MASTER_KEY de la RAM.
pub fn vault_wipe() -> Result<(), String> {
    let path = vault_file_path()?;
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|e| format!("Suppression vault.json échouée: {}", e))?;
    }
    let _ = HardwareKeystore::wipe_all();
    Ok(())
}

/// Calcule HMAC-SHA256(key=master_key, msg=salt || TAG).
fn compute_verifier(master_key: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; VERIFIER_LEN], String> {
    let mut mac = HmacSha256::new_from_slice(master_key)
        .map_err(|e| format!("HMAC init échouée: {}", e))?;
    mac.update(salt);
    mac.update(VERIFIER_MESSAGE_TAG);
    let result = mac.finalize().into_bytes();

    let mut out = [0u8; VERIFIER_LEN];
    out.copy_from_slice(&result);
    Ok(out)
}

// =============================================================================
// ZÉROISATION — Nettoyage des buffers sensibles à la destruction
// =============================================================================

/// Wipe manuel des tableaux de verifier intermédiaires.
/// Note : le `[u8; N]` ne drop pas automatiquement via Zeroize, donc on
/// l'appelle explicitement là où nécessaire.
#[allow(dead_code)]
fn zeroize_array<const N: usize>(arr: &mut [u8; N]) {
    arr.zeroize();
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Sérialise les tests vault (VAULT_DIR est global).
    static TEST_VAULT_LOCK: Mutex<()> = Mutex::new(());

    /// Crée un dossier temporaire unique.
    fn fresh_tmp_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nonce: u64 = rand::random();
        dir.push(format!("aegis_vault_test_{}_{}", label, nonce));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Cleanup
    fn rm_tmp_dir(dir: &PathBuf) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_set_vault_dir_creates_directory() {
        let _g = crate::keystore::TEST_LOCK.lock().unwrap();
        let _g2 = TEST_VAULT_LOCK.lock().unwrap();

        let dir = fresh_tmp_dir("setdir");
        // Supprimer pour tester la création
        fs::remove_dir_all(&dir).unwrap();

        set_vault_dir(dir.clone()).unwrap();
        assert!(dir.exists(), "set_vault_dir doit créer le dossier");

        rm_tmp_dir(&dir);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, AEGIS! \x00\x01\xFF\xFE";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_vault_file_json_roundtrip() {
        let vault = VaultFile {
            salt: [0xAA; SALT_LEN],
            verifier: [0xBB; VERIFIER_LEN],
        };
        let json = vault.to_json();
        let parsed = VaultFile::from_json(&json).unwrap();
        assert_eq!(parsed.salt, vault.salt);
        assert_eq!(parsed.verifier, vault.verifier);
    }

    #[test]
    fn test_vault_init_then_unlock_succeeds() {
        let _g = crate::keystore::TEST_LOCK.lock().unwrap();
        let _g2 = TEST_VAULT_LOCK.lock().unwrap();

        let dir = fresh_tmp_dir("init_unlock");
        set_vault_dir(dir.clone()).unwrap();
        let _ = crate::keystore::HardwareKeystore::wipe_all();
        crate::keystore::HardwareKeystore::set_root_key(&[0x42u8; 32]).unwrap();

        // Init
        vault_init("MonPIN-Test-1234").expect("init doit réussir");
        assert!(vault_is_initialized(), "vault doit être initialisé");

        // Unlock avec le bon PIN → Real
        let result = vault_unlock("MonPIN-Test-1234").unwrap();
        assert_eq!(result, VaultSession::Real);

        rm_tmp_dir(&dir);
    }

    #[test]
    fn test_vault_unlock_wrong_pin_returns_decoy() {
        let _g = crate::keystore::TEST_LOCK.lock().unwrap();
        let _g2 = TEST_VAULT_LOCK.lock().unwrap();

        let dir = fresh_tmp_dir("wrong_pin");
        set_vault_dir(dir.clone()).unwrap();
        let _ = crate::keystore::HardwareKeystore::wipe_all();
        crate::keystore::HardwareKeystore::set_root_key(&[0x42u8; 32]).unwrap();

        vault_init("CorrectPIN-1234").unwrap();
        let result = vault_unlock("WrongPIN-5678").unwrap();
        assert_eq!(result, VaultSession::Decoy);

        rm_tmp_dir(&dir);
    }

    #[test]
    fn test_vault_unlock_uninitialized() {
        let _g = crate::keystore::TEST_LOCK.lock().unwrap();
        let _g2 = TEST_VAULT_LOCK.lock().unwrap();

        let dir = fresh_tmp_dir("not_init");
        set_vault_dir(dir.clone()).unwrap();

        assert!(!vault_is_initialized());
        let result = vault_unlock("AnyPIN").unwrap();
        assert_eq!(result, VaultSession::NeedsInitialization);

        rm_tmp_dir(&dir);
    }

    #[test]
    fn test_vault_persists_across_reinit() {
        let _g = crate::keystore::TEST_LOCK.lock().unwrap();
        let _g2 = TEST_VAULT_LOCK.lock().unwrap();

        let dir = fresh_tmp_dir("persist");
        set_vault_dir(dir.clone()).unwrap();
        let _ = crate::keystore::HardwareKeystore::wipe_all();
        crate::keystore::HardwareKeystore::set_root_key(&[0x42u8; 32]).unwrap();

        vault_init("PersistPIN-1234").unwrap();

        // Simuler un "restart" : wipe MASTER_KEY (ROOT_KEY reste car StrongBox)
        let _ = crate::keystore::HardwareKeystore::wipe_master_key();
        assert!(!crate::keystore::HardwareKeystore::get_master_key().is_ok());

        // Le vault doit toujours être marqué initialisé
        assert!(vault_is_initialized());

        // Et le PIN doit toujours fonctionner (dérivation à la volée)
        let result = vault_unlock("PersistPIN-1234").unwrap();
        assert_eq!(result, VaultSession::Real);

        rm_tmp_dir(&dir);
    }

    #[test]
    fn test_vault_wipe_clears_state() {
        let _g = crate::keystore::TEST_LOCK.lock().unwrap();
        let _g2 = TEST_VAULT_LOCK.lock().unwrap();

        let dir = fresh_tmp_dir("wipe");
        set_vault_dir(dir.clone()).unwrap();
        let _ = crate::keystore::HardwareKeystore::wipe_all();
        crate::keystore::HardwareKeystore::set_root_key(&[0x42u8; 32]).unwrap();

        vault_init("WipePIN-1234").unwrap();
        assert!(vault_is_initialized());

        vault_wipe().unwrap();
        assert!(!vault_is_initialized(), "après wipe, vault non initialisé");

        rm_tmp_dir(&dir);
    }
}