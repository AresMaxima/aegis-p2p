pub mod crypto;
pub mod crypto_pq;
pub mod deadman;
pub mod ffi_security;
pub mod hardware_triggers;
pub mod keystore;
pub mod mesh;
pub mod network;
pub mod panic;
pub mod polymorphic_ram;
pub mod seccomp;
pub mod secure_buffer;
pub mod session;
pub mod signals;
pub mod stegano;
pub mod storage;
pub mod transport;

use ffi_support::{define_string_destructor, FfiStr};
use std::os::raw::c_char;
use subtle::ConstantTimeEq;

define_string_destructor!(aegis_free_string);

/// Empreinte SHA-256 officielle de votre clé JKS de Release (en minuscules hex)
const OFFICIAL_JKS_SHA256: &str = "94e3dfbcac6e9dfccbafb07320728c468dbce38ec3f0e9501ee9703fe06a9ff7";

/// Initialise le moteur Aegis avec hardening Seccomp, interdiction de dump et attestation JKS.
/// 
/// # Safety
/// Retourne 0 en cas de succès, -1 si l'intégrité du système est compromise.
#[no_mangle]
pub unsafe extern "C" fn aegis_init() -> i32 {
    ffi_security::execute_constant_time_ffi(10, || {
        // 1. Interdiction des memory dumps et de la lecture de /proc/self/mem
        crypto::memory::prevent_core_dumps();

        // 2. Application du filtre Seccomp-BPF strict (Noyau Linux/Android)
        seccomp::apply_strict_seccomp_filter();

        // 3. Démarrage du thread de surveillance d'intégrité (Anti-Debugging, Anti-Hooking & Ptrace Lock)
        crypto::integrity::AegisIntegrityMonitor::start();

        // 4. Contrôle d'intégrité matérielle TPM 2.0 / StrongBox
        match crypto::tpm::AegisTpmManager::verify_kernel_integrity() {
            Ok(_) => 0,
            Err(_) => -1,
        }
    })
}

/// Vérifie l'empreinte JKS reçue du package manager Android. Déclenche le Silent Burn en cas d'altération.
/// 
/// # Safety
/// Le pointeur `apk_signature_hash_ptr` doit être une chaîne C valide.
#[no_mangle]
pub unsafe extern "C" fn aegis_verify_apk_signature_or_burn(apk_signature_hash_ptr: FfiStr) {
    ffi_security::execute_constant_time_ffi(10, || {
        let hash = match apk_signature_hash_ptr.as_opt_str() {
            Some(h) => h,
            None => {
                panic::PanicPurge::execute_silent_burn();
            }
        };

        if hash.len() != OFFICIAL_JKS_SHA256.len()
            || hash.as_bytes().ct_eq(OFFICIAL_JKS_SHA256.as_bytes()).unwrap_u8() != 1
        {
            panic::PanicPurge::execute_silent_burn();
        }
    });
}

/// Génère une nouvelle phrase mnémonique BIP-39 (12 mots).
/// 
/// # Safety
/// Retourne un pointeur de chaîne C (*mut c_char) à libérer via `aegis_free_string`.
#[no_mangle]
pub unsafe extern "C" fn aegis_generate_mnemonic() -> *mut c_char {
    ffi_security::execute_constant_time_ffi(10, || {
        match crypto::keys::generate_mnemonic(12) {
            Ok(phrase) => ffi_support::rust_string_to_c(phrase),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Calcule le Hash d'Identité Publique à partir d'une phrase mnémonique.
/// 
/// # Safety
/// Prend en entrée un `mnemonic_ptr` valide terminé par un octet nul.
#[no_mangle]
pub unsafe extern "C" fn aegis_derive_identity_hash(mnemonic_ptr: FfiStr) -> *mut c_char {
    ffi_security::execute_constant_time_ffi(10, || {
        let mnemonic = match mnemonic_ptr.as_opt_str() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };

        match crypto::keys::derive_keys_from_mnemonic(mnemonic) {
            Ok(keys) => {
                let hash = keys.public_identity_hash();
                ffi_support::rust_string_to_c(hash)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Chiffre un texte avec une clé via ChaCha20-Poly1305 avec Nonce aléatoire unique.
/// 
/// # Safety
/// Les pointeurs `secret_key_ptr` et `message_ptr` doivent être valides.
#[no_mangle]
pub unsafe extern "C" fn aegis_encrypt_message(
    secret_key_ptr: FfiStr,
    message_ptr: FfiStr,
) -> *mut c_char {
    ffi_security::execute_constant_time_ffi(10, || {
        let secret = match secret_key_ptr.as_opt_str() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let msg = match message_ptr.as_opt_str() {
            Some(m) => m,
            None => return std::ptr::null_mut(),
        };

        use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return std::ptr::null_mut(),
        };

        let mut nonce_bytes = [0u8; 12];
        if getrandom::getrandom(&mut nonce_bytes).is_err() {
            return std::ptr::null_mut();
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.encrypt(nonce, msg.as_bytes()) {
            Ok(ciphertext) => {
                let mut payload = Vec::with_capacity(12 + ciphertext.len());
                payload.extend_from_slice(&nonce_bytes);
                payload.extend_from_slice(&ciphertext);
                ffi_support::rust_string_to_c(hex::encode(payload))
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Déchiffre un message hexadécimal chiffré (Nonce + Ciphertext).
/// 
/// # Safety
/// Les pointeurs `secret_key_ptr` et `hex_payload_ptr` doivent être valides.
#[no_mangle]
pub unsafe extern "C" fn aegis_decrypt_message(
    secret_key_ptr: FfiStr,
    hex_payload_ptr: FfiStr,
) -> *mut c_char {
    ffi_security::execute_constant_time_ffi(10, || {
        let secret = match secret_key_ptr.as_opt_str() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let hex_payload = match hex_payload_ptr.as_opt_str() {
            Some(h) => h,
            None => return std::ptr::null_mut(),
        };

        let raw_payload = match hex::decode(hex_payload) {
            Ok(bytes) if bytes.len() > 12 => bytes,
            _ => return std::ptr::null_mut(),
        };

        let (nonce_bytes, ciphertext) = raw_payload.split_at(12);

        use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();

        let cipher = match ChaCha20Poly1305::new_from_slice(&key) {
            Ok(c) => c,
            Err(_) => return std::ptr::null_mut(),
        };

        let nonce = Nonce::from_slice(nonce_bytes);
        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => match String::from_utf8(plaintext) {
                Ok(s) => ffi_support::rust_string_to_c(s),
                Err(_) => std::ptr::null_mut(),
            },
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Dissimule un secret dans un poème via stéganographie Unicode invisible (`drowning.rs`).
/// 
/// # Safety
/// Les pointeurs `secret_ptr` et `cover_text_ptr` doivent être valides.
#[no_mangle]
pub unsafe extern "C" fn aegis_stegano_hide(
    secret_ptr: FfiStr,
    cover_text_ptr: FfiStr,
) -> *mut c_char {
    ffi_security::execute_constant_time_ffi(10, || {
        let secret = match secret_ptr.as_opt_str() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };
        let cover_opt = cover_text_ptr.as_opt_str();

        match stegano::drowning::hide_mnemonic_in_text(secret, cover_opt) {
            Ok(stego) => ffi_support::rust_string_to_c(stego),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Extrait un secret dissimulé dans un texte stéganographié.
/// 
/// # Safety
/// Le pointeur `stego_text_ptr` doit être valide.
#[no_mangle]
pub unsafe extern "C" fn aegis_stegano_extract(stego_text_ptr: FfiStr) -> *mut c_char {
    ffi_security::execute_constant_time_ffi(10, || {
        let stego = match stego_text_ptr.as_opt_str() {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        };

        match stegano::drowning::extract_mnemonic_from_text(stego) {
            Ok(secret) => ffi_support::rust_string_to_c(secret),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aegis_init() {
        unsafe {
            let res = aegis_init();
            assert_eq!(res, 0);
        }
    }

    #[test]
    fn test_ffi_exports_flow() {
        unsafe {
            let c_phrase = aegis_generate_mnemonic();
            assert!(!c_phrase.is_null());

            let rust_phrase = std::ffi::CStr::from_ptr(c_phrase).to_str().unwrap();
            assert_eq!(rust_phrase.split_whitespace().count(), 12);

            let ffi_str = FfiStr::from_raw(c_phrase);
            let c_hash = aegis_derive_identity_hash(ffi_str);
            assert!(!c_hash.is_null());

            let rust_hash = std::ffi::CStr::from_ptr(c_hash).to_str().unwrap();
            assert_eq!(rust_hash.len(), 32);

            aegis_free_string(c_phrase);
            aegis_free_string(c_hash);
        }
    }
}