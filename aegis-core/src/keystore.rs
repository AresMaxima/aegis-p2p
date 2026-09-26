//! aegis-core/src/keystore.rs
//! Ancrage cryptographique matériel — v3.0 (Option 2, audit 2026-09-20).
//!
//! Politique :
//!   • La clé racine provient EXCLUSIVEMENT du StrongBox/TEE via FFI.
//!   • Pas de génération locale — `get_or_create_root_key()` échoue si non initialisée.
//!   • `derive_master_key(pin)` combine StrongBox_key || vault_PIN via HKDF-SHA256.
//!   • `wipe_root_key()` et `wipe_master_key()` zéroïsent effectivement.
//!   • `verify_signature()` n'a plus de bypass de test.
//!
//! Deux facteurs :
//!   1. Matériel : StrongBox_key (scellée dans la puce, jamais extraite).
//!   2. Connaissance : vault_PIN (saisi par l'utilisateur).
//!   → HKDF-SHA256(StrongBox_key || pin, salt, info) = master_key.
//!
//! Sans l'un OU l'autre, la master_key est indérivable.

use crate::secure_buffer::SecureBuffer;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::process;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::Mutex;

const ADMIN_PUBLIC_KEY_HEX: &str =
    "ac2611c408d34cf565189cba8448d776c20d958c288372659067690c5dd2146d";

// =========================================================================
// CONSTANTES HKDF
// =========================================================================

/// Salt applicatif : fixe, non-secret. Sert à séparer les domaines.
const HKDF_SALT: &[u8] = b"AEGIS-P2P-MASTER-v3";

/// Info HKDF : contexte d'usage de la clé dérivée.
const HKDF_INFO: &[u8] = b"aegis-master-key-v3";

// =========================================================================
// ÉTAT GLOBAL
// =========================================================================

/// Clé racine fournie par le matériel via FFI (`aegis_set_hardware_secret`).
/// `None` tant que Kotlin n'a pas appelé cette fonction.
static ROOT_KEY: Mutex<Option<SecureBuffer>> = Mutex::new(None);

/// Clé maître dérivée : HKDF(ROOT_KEY || vault_PIN).
/// `None` tant que `derive_master_key()` n'a pas été appelée.
static MASTER_KEY: Mutex<Option<SecureBuffer>> = Mutex::new(None);

// =========================================================================
// BURN — Utilisé sur les chemins critiques (à conserver)
// =========================================================================

#[cfg(not(test))]
extern "C" {
    fn aegis_panic_silent_burn();
}

#[cfg(test)]
thread_local! {
    pub static MOCK_KEYSTORE_FAIL: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

#[inline(always)]
fn trigger_burn() -> ! {
    #[cfg(not(test))]
    unsafe {
        aegis_panic_silent_burn();
        process::exit(137);
    }
    #[cfg(test)]
    panic!("SYSTEM_EXIT_137");
}

// =========================================================================
// HARDWARE KEYSTORE
// =========================================================================

pub struct HardwareKeystore;

impl HardwareKeystore {
    // -----------------------------------------------------------------
    // ROOT_KEY — fourni par le StrongBox/TEE (FFI)
    // -----------------------------------------------------------------

    /// Retourne une copie de la clé racine fournie par le StrongBox/TEE.
    ///
    /// **Err** si `aegis_set_hardware_secret` n'a pas encore été appelé.
    /// Il n'y a **plus de fallback** vers `rand::thread_rng()`.
    pub fn get_or_create_root_key() -> Result<SecureBuffer, String> {
        let guard = ROOT_KEY
            .lock()
            .map_err(|_| "ROOT_KEY mutex empoisonné".to_string())?;

        let stored = guard.as_ref().ok_or_else(|| {
            "Root key non initialisée — appeler aegis_set_hardware_secret d'abord"
                .to_string()
        })?;

        let mut copy = SecureBuffer::new(32);
        copy.as_slice_mut().copy_from_slice(stored.as_slice());
        Ok(copy)
    }

    /// Enregistre la clé racine transmise par Kotlin (StrongBox/TEE).
    ///
    /// **Err** si la longueur != 32 ou si le buffer est tout-à-zéro.
    pub fn set_root_key(bytes: &[u8]) -> Result<(), String> {
        if bytes.len() != 32 {
            return Err(format!("Longueur invalide : {} (attendu 32)", bytes.len()));
        }
        if bytes.iter().all(|&b| b == 0) {
            return Err("Clé tout-à-zéro rejetée".to_string());
        }

        let mut guard = ROOT_KEY
            .lock()
            .map_err(|_| "ROOT_KEY mutex empoisonné".to_string())?;

        if let Some(mut old) = guard.take() {
            for b in old.as_slice_mut().iter_mut() {
                *b = 0;
            }
            compiler_fence(Ordering::SeqCst);
        }

        let mut new_key = SecureBuffer::new(32);
        new_key.as_slice_mut().copy_from_slice(bytes);
        *guard = Some(new_key);

        // Toute nouvelle ROOT_KEY invalide la MASTER_KEY dérivée.
        drop(guard);
        let _ = HardwareKeystore::wipe_master_key();

        Ok(())
    }

    /// Wipe **effectif** de la clé racine.
    pub fn wipe_root_key() -> Result<(), String> {
        let mut guard = ROOT_KEY
            .lock()
            .map_err(|_| "ROOT_KEY mutex empoisonné".to_string())?;

        if let Some(mut key) = guard.take() {
            for b in key.as_slice_mut().iter_mut() {
                *b = 0;
            }
            compiler_fence(Ordering::SeqCst);
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // MASTER_KEY — dérivée via HKDF(ROOT_KEY || vault_PIN)
    // -----------------------------------------------------------------

    /// Dérive la master_key à partir de :
    ///   • ROOT_KEY (StrongBox, scellée matériellement, 32 octets)
    ///   • vault_PIN (connaissance utilisateur, UTF-8)
    /// → HKDF-SHA256(IKM=ROOT_KEY || PIN, salt=HKDF_SALT, info=HKDF_INFO)
    ///
    /// **Err** si ROOT_KEY n'est pas initialisée, ou si le PIN est vide.
    ///
    /// # Sécurité
    /// Le PIN est zéroïsé en mémoire après usage (buffer local).
    pub fn derive_master_key(pin: &str) -> Result<(), String> {
        if pin.is_empty() {
            return Err("PIN vide — refusé".to_string());
        }

        // 1. Récupérer ROOT_KEY (copie indépendante)
        let root = HardwareKeystore::get_or_create_root_key()?;

        // 2. Construire l'IKM = ROOT_KEY || PIN_bytes
        let pin_bytes = pin.as_bytes();
        let mut ikm = SecureBuffer::new(32 + pin_bytes.len());
        ikm.as_slice_mut()[..32].copy_from_slice(root.as_slice());
        ikm.as_slice_mut()[32..].copy_from_slice(pin_bytes);

        // 3. HKDF-SHA256 → 32 octets
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm.as_slice());
        let mut okm = [0u8; 32];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| "HKDF expand a échoué".to_string())?;

        // 4. Stocker MASTER_KEY
        {
            let mut guard = MASTER_KEY
                .lock()
                .map_err(|_| "MASTER_KEY mutex empoisonné".to_string())?;

            if let Some(mut old) = guard.take() {
                for b in old.as_slice_mut().iter_mut() {
                    *b = 0;
                }
                compiler_fence(Ordering::SeqCst);
            }

            let mut mk = SecureBuffer::new(32);
            mk.as_slice_mut().copy_from_slice(&okm);
            *guard = Some(mk);
        }

        // 5. Zéroïser les intermédiaires
        for b in okm.iter_mut() {
            *b = 0;
        }
        compiler_fence(Ordering::SeqCst);
        drop(ikm);
        drop(root);

        Ok(())
    }

    /// Retourne une copie de la master_key courante.
    ///
    /// **Err** si `derive_master_key()` n'a pas encore été appelée.
    pub fn get_master_key() -> Result<SecureBuffer, String> {
        let guard = MASTER_KEY
            .lock()
            .map_err(|_| "MASTER_KEY mutex empoisonné".to_string())?;

        let stored = guard.as_ref().ok_or_else(|| {
            "Master key non dérivée — appeler derive_master_key(pin) d'abord".to_string()
        })?;

        let mut copy = SecureBuffer::new(32);
        copy.as_slice_mut().copy_from_slice(stored.as_slice());
        Ok(copy)
    }

    /// Wipe **effectif** de la master_key.
    pub fn wipe_master_key() -> Result<(), String> {
        let mut guard = MASTER_KEY
            .lock()
            .map_err(|_| "MASTER_KEY mutex empoisonné".to_string())?;

        if let Some(mut key) = guard.take() {
            for b in key.as_slice_mut().iter_mut() {
                *b = 0;
            }
            compiler_fence(Ordering::SeqCst);
        }
        Ok(())
    }

    /// Wipe combiné : ROOT_KEY + MASTER_KEY (utilisé par PanicPurge).
    pub fn wipe_all() -> Result<(), String> {
        HardwareKeystore::wipe_root_key()?;
        HardwareKeystore::wipe_master_key()?;
        Ok(())
    }
}

// =========================================================================
// VÉRIFICATION SIGNATURE — Sans bypass de test
// =========================================================================

#[inline(always)]
fn verify_signature(pk: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    pk.verify(msg, sig).is_ok()
}

// =========================================================================
// FFI — Vérification et scellement de licence
// =========================================================================

#[no_mangle]
pub extern "C" fn aegis_verify_and_seal_license(license_hex_ptr: *const c_char) -> i32 {
    #[cfg(test)]
    let res = std::panic::catch_unwind(|| internal_verify_and_seal(license_hex_ptr));

    #[cfg(test)]
    match res {
        Ok(val) => val,
        Err(_) => -1,
    }

    #[cfg(not(test))]
    internal_verify_and_seal(license_hex_ptr)
}

#[inline(always)]
fn internal_verify_and_seal(license_hex_ptr: *const c_char) -> i32 {
    if license_hex_ptr.is_null() {
        trigger_burn();
    }

    let raw_c_str = unsafe { CStr::from_ptr(license_hex_ptr) };
    let raw_str = match raw_c_str.to_str() {
        Ok(s) => s.trim(),
        Err(_) => trigger_burn(),
    };

    let decoded_bytes = match hex::decode(raw_str) {
        Ok(b) => b,
        Err(_) => trigger_burn(),
    };

    let license_str = match String::from_utf8(decoded_bytes) {
        Ok(s) => s,
        Err(_) => trigger_burn(),
    };

    let parts: Vec<&str> = license_str.split(':').collect();
    if parts.len() != 2 {
        trigger_burn();
    }

    let order_num = parts[0];
    let sig_hex_str = parts[1];

    let sig_bytes = match hex::decode(sig_hex_str) {
        Ok(b) => b,
        Err(_) => trigger_burn(),
    };

    let pub_key_bytes = match hex::decode(ADMIN_PUBLIC_KEY_HEX) {
        Ok(b) => b,
        Err(_) => trigger_burn(),
    };

    if pub_key_bytes.len() != 32 || sig_bytes.len() != 64 {
        trigger_burn();
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pub_key_bytes);

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let public_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(pk) => pk,
        Err(_) => trigger_burn(),
    };

    let signature = Signature::from_bytes(&sig_arr);

    if !verify_signature(&public_key, order_num.as_bytes(), &signature) {
        trigger_burn();
    }
    if !seal_in_strongbox_nvram(order_num) {
        trigger_burn();
    }

    0
}

/// Scellement NVRAM — STUB v3.0.
///
/// **TODO Phase 3.5+** : implémenter via JNI vers `HardwareKeystore.sealLicenseInNvram()`.
/// En attendant, la fonction retourne `true` sans effet — **ne pas prétendre
/// dans la documentation utilisateur que le scellement NVRAM est actif.**
fn seal_in_strongbox_nvram(_order_identifier: &str) -> bool {
    true
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // FIX 2026-09-20 : le trait `Signer` fournit `.sign()` sur `SigningKey`.
    use ed25519_dalek::{Signer, SigningKey};
    use std::ffi::CString;
    use std::ptr;

    // Sérialise les tests qui touchent aux Mutex globaux
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        let _ = HardwareKeystore::wipe_root_key();
        let _ = HardwareKeystore::wipe_master_key();
    }

    // ---------------- ROOT_KEY ----------------

    #[test]
    fn test_root_key_fails_before_provide() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();
        match HardwareKeystore::get_or_create_root_key() {
            Ok(_) => panic!("Doit échouer sans provide préalable"),
            Err(msg) => assert!(msg.contains("non initialisée")),
        }
    }

    #[test]
    fn test_root_key_succeeds_after_provide() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();

        let key_bytes = [0x42u8; 32];
        HardwareKeystore::set_root_key(&key_bytes).expect("set_root_key doit réussir");

        let got = HardwareKeystore::get_or_create_root_key().expect("doit réussir");
        assert_eq!(got.as_slice(), &key_bytes);
    }

    #[test]
    fn test_wipe_root_key_actually_zeroizes() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();

        HardwareKeystore::set_root_key(&[0xABu8; 32]).unwrap();
        assert!(HardwareKeystore::get_or_create_root_key().is_ok());

        HardwareKeystore::wipe_root_key().unwrap();

        assert!(HardwareKeystore::get_or_create_root_key().is_err());
    }

    #[test]
    fn test_set_root_key_rejects_wrong_length() {
        let _g = TEST_LOCK.lock().unwrap();
        assert!(HardwareKeystore::set_root_key(&[0u8; 16]).is_err());
        assert!(HardwareKeystore::set_root_key(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_set_root_key_rejects_all_zero() {
        let _g = TEST_LOCK.lock().unwrap();
        assert!(HardwareKeystore::set_root_key(&[0u8; 32]).is_err());
    }

    // ---------------- MASTER_KEY (HKDF) ----------------

    #[test]
    fn test_derive_master_key_fails_without_root() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();
        let res = HardwareKeystore::derive_master_key("MonPIN-Test-1234");
        assert!(res.is_err(), "derive sans ROOT_KEY doit échouer");
    }

    #[test]
    fn test_derive_master_key_fails_with_empty_pin() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();
        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();
        let res = HardwareKeystore::derive_master_key("");
        assert!(res.is_err(), "PIN vide doit être refusé");
    }

    #[test]
    fn test_derive_master_key_succeeds_with_root_and_pin() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();
        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();
        HardwareKeystore::derive_master_key("MonPIN-Test-1234").expect("doit réussir");

        let mk = HardwareKeystore::get_master_key().expect("master key doit exister");
        assert_eq!(mk.as_slice().len(), 32);
    }

    #[test]
    fn test_derive_master_key_is_deterministic() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();
        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();

        HardwareKeystore::derive_master_key("MonPIN-Test-1234").unwrap();
        let mk1 = HardwareKeystore::get_master_key().unwrap();

        HardwareKeystore::derive_master_key("MonPIN-Test-1234").unwrap();
        let mk2 = HardwareKeystore::get_master_key().unwrap();

        assert_eq!(mk1.as_slice(), mk2.as_slice(),
            "même ROOT_KEY + même PIN → même master_key");
    }

    #[test]
    fn test_derive_master_key_differs_by_pin() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();
        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();

        HardwareKeystore::derive_master_key("PIN-A").unwrap();
        let mk_a = HardwareKeystore::get_master_key().unwrap();

        HardwareKeystore::derive_master_key("PIN-B").unwrap();
        let mk_b = HardwareKeystore::get_master_key().unwrap();

        assert_ne!(mk_a.as_slice(), mk_b.as_slice(),
            "PIN différents → master_key différents");
    }

    #[test]
    fn test_derive_master_key_differs_by_root() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();

        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();
        HardwareKeystore::derive_master_key("MêmePIN").unwrap();
        let mk1 = HardwareKeystore::get_master_key().unwrap();

        HardwareKeystore::set_root_key(&[0x22u8; 32]).unwrap();
        HardwareKeystore::derive_master_key("MêmePIN").unwrap();
        let mk2 = HardwareKeystore::get_master_key().unwrap();

        assert_ne!(mk1.as_slice(), mk2.as_slice(),
            "ROOT_KEY différents → master_key différents");
    }

    #[test]
    fn test_set_root_key_invalidates_master_key() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();

        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();
        HardwareKeystore::derive_master_key("MonPIN").unwrap();
        assert!(HardwareKeystore::get_master_key().is_ok());

        // Nouvelle ROOT_KEY → MASTER_KEY doit être wipée
        HardwareKeystore::set_root_key(&[0x22u8; 32]).unwrap();
        assert!(HardwareKeystore::get_master_key().is_err(),
            "Nouvelle ROOT_KEY doit invalider MASTER_KEY");
    }

    #[test]
    fn test_wipe_master_key_actually_zeroizes() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();

        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();
        HardwareKeystore::derive_master_key("MonPIN").unwrap();
        assert!(HardwareKeystore::get_master_key().is_ok());

        HardwareKeystore::wipe_master_key().unwrap();
        assert!(HardwareKeystore::get_master_key().is_err());
    }

    #[test]
    fn test_wipe_all_clears_both() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_state();

        HardwareKeystore::set_root_key(&[0x11u8; 32]).unwrap();
        HardwareKeystore::derive_master_key("MonPIN").unwrap();

        HardwareKeystore::wipe_all().unwrap();

        assert!(HardwareKeystore::get_or_create_root_key().is_err());
        assert!(HardwareKeystore::get_master_key().is_err());
    }

    // ---------------- VERIFY SIGNATURE ----------------

    #[test]
    fn test_verify_signature_rejects_invalid() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pub_key = signing_key.verifying_key();
        let bad_sig = Signature::from_bytes(&[0u8; 64]);

        assert!(!verify_signature(&pub_key, b"hello", &bad_sig));
    }

    #[test]
    fn test_verify_signature_accepts_valid() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pub_key = signing_key.verifying_key();
        let msg = b"hello world";
        let sig = signing_key.sign(msg);

        assert!(verify_signature(&pub_key, msg, &sig));
    }

    #[test]
    fn test_verify_signature_rejects_wrong_message() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let pub_key = signing_key.verifying_key();
        let sig = signing_key.sign(b"message_a");

        assert!(!verify_signature(&pub_key, b"message_b", &sig));
    }

    // ---------------- FFI ----------------

    #[test]
    fn test_ffi_null_pointer() {
        assert_eq!(aegis_verify_and_seal_license(ptr::null()), -1);
    }

    #[test]
    fn test_ffi_invalid_hex() {
        let invalid = CString::new("ZZZZZ").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_invalid_utf8() {
        let invalid_utf8_hex = CString::new("fffe").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid_utf8_hex.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_missing_colon() {
        let missing_colon = CString::new("68656c6c6f").unwrap();
        assert_eq!(aegis_verify_and_seal_license(missing_colon.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_invalid_sig_hex() {
        let invalid_sig = CString::new("6f726465726e756d3a5858").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid_sig.as_ptr()), -1);
    }

    #[test]
    fn test_ffi_invalid_sig_size() {
        let invalid_size = CString::new("6f726465726e756d3a30313032").unwrap();
        assert_eq!(aegis_verify_and_seal_license(invalid_size.as_ptr()), -1);
    }
}