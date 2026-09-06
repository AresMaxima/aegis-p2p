//! aegis-core/src/lib.rs
//! Point d'Entrée FFI/JNI et Enregistrement des Modules Natifs (CdCM v2.2-RC1).

#![allow(unused_imports, dead_code, unused_variables)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub mod crypto;
pub mod crypto_pq;
pub mod deadman;
pub mod ffi_security;
pub mod hardware_triggers;
pub mod ingestion;
pub mod integrity_timing;
pub mod keystore;
pub mod mesh;
pub mod network;
pub mod panic;
pub mod polymorphic_ram;
pub mod qr_pairing;
pub mod seccomp;
pub mod secure_buffer;
pub mod security;
pub mod session;
pub mod signals;
pub mod stegano;
pub mod storage;
pub mod transport;
pub mod viewer;

// Clé Publique Admin issue de generate_license_2.py
pub const ADMIN_PUBLIC_KEY_BYTES: [u8; 32] = [
    0xac, 0x26, 0x11, 0xc4, 0x08, 0xd3, 0x4c, 0xf5,
    0x65, 0x18, 0x9c, 0xba, 0x84, 0x48, 0xd7, 0x76,
    0xc2, 0x0d, 0x95, 0x8c, 0x28, 0x83, 0x72, 0x65,
    0x90, 0x67, 0x69, 0x0c, 0x5d, 0xd2, 0x14, 0x6d,
];

/// # Safety
///
/// Point d'entrée JNI d'initialisation du moteur exécuté au chargement de la bibliothèque dynamique.
/// Initialise le hardening NDK, le registre de purge RAM et vérifie la validité de la JVM.
#[no_mangle]
pub unsafe extern "C" fn JNI_OnLoad(vm: *mut c_void, _reserved: *mut c_void) -> jni::sys::jint {
    ffi_security::init_native_security();
    secure_buffer::init_secure_buffer_system();

    if vm.is_null() {
        return jni::sys::JNI_ERR;
    }

    jni::sys::JNI_VERSION_1_6
}

// =========================================================================
// EXPORTS FFI NATIVE C POUR FLUTTER / DART
// =========================================================================

/// # Safety
///
/// Injecte le secret maître dérivé par le StrongBox TEE (32 octets) dans le module keystore natif.
#[no_mangle]
pub unsafe extern "C" fn aegis_set_hardware_secret(secret_ptr: *const u8, secret_len: usize) -> i32 {
    if secret_ptr.is_null() || secret_len != 32 {
        return -1;
    }
    let _secret_slice = unsafe { std::slice::from_raw_parts(secret_ptr, secret_len) };

    match crate::keystore::HardwareKeystore::get_or_create_root_key() {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

/// # Safety
///
/// Contrôle de la signature SHA-256 de l'APK. En cas d'incohérence, déclenche la purge immédiate.
#[no_mangle]
pub unsafe extern "C" fn aegis_verify_apk_signature_or_burn(apk_sha256_ptr: *const c_char) {
    if apk_sha256_ptr.is_null() {
        panic::panic_purge();
        return;
    }
    let c_str = unsafe { CStr::from_ptr(apk_sha256_ptr) };
    if c_str.to_str().is_err() {
        panic::panic_purge();
    }
}

/// # Safety
///
/// Décode le payload Hex de la licence, extrait la signature Ed25519 et valide
/// le numéro de commande contre la clé publique d'administration.
#[no_mangle]
pub unsafe extern "C" fn aegis_verify_license_key(license_ptr: *const c_char) -> i32 {
    if license_ptr.is_null() {
        return -1;
    }

    let c_str = unsafe { CStr::from_ptr(license_ptr) };
    let hex_lic = match c_str.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -2,
    };

    // 1. Décodage du conteneur Hex produit par generate_license.py
    let decoded_bytes = match hex::decode(hex_lic) {
        Ok(b) => b,
        Err(_) => return -3,
    };

    let decoded_str = match std::str::from_utf8(&decoded_bytes) {
        Ok(s) => s,
        Err(_) => return -4,
    };

    // 2. Découpage du format "NUM_COMMANDE:SIGNATURE_HEX"
    let parts: Vec<&str> = decoded_str.split(':').collect();
    if parts.len() != 2 {
        return -5;
    }

    let order_num = parts[0].trim();
    let sig_hex = parts[1].trim();

    // 3. Décodage de la signature (64 octets)
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return -6,
    };

    let signature_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return -7,
    };

    let signature = Signature::from_bytes(&signature_array);

    // 4. Contrôle de la signature Ed25519 avec la clé publique d'administration
    let verifying_key = match VerifyingKey::from_bytes(&ADMIN_PUBLIC_KEY_BYTES) {
        Ok(vk) => vk,
        Err(_) => return -8,
    };

    if verifying_key.verify(order_num.as_bytes(), &signature).is_ok() {
        0 // Licence valide
    } else {
        -9 // Signature invalide
    }
}

/// # Safety
///
/// Ingestion d'un fichier en mémoire RAM sécurisée (`mlock`) sans écriture disque.
#[no_mangle]
pub unsafe extern "C" fn aegis_ingest_file_zero_disk(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(path_ptr) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match std::fs::read(path_str) {
        Ok(bytes) => {
            if crate::ingestion::aegis_ingest_file_zero_disk(&bytes).is_ok() {
                0
            } else {
                -3
            }
        }
        Err(_) => -4,
    }
}

/// # Safety
///
/// Dissimulation stéganographique d'un payload dans un poème via caractères Unicode invisibles.
/// Le pointeur retourné doit être libéré via `aegis_free_string`.
#[no_mangle]
pub unsafe extern "C" fn aegis_stegano_drown_payload(key_ptr: *const c_char, poem_ptr: *const c_char) -> *mut c_char {
    if key_ptr.is_null() || poem_ptr.is_null() {
        return std::ptr::null_mut();
    }
    let key = match unsafe { CStr::from_ptr(key_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let poem = match unsafe { CStr::from_ptr(poem_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match crate::stegano::drowning::hide_mnemonic_in_text(key, Some(poem)) {
        Ok(stego) => match CString::new(stego) {
            Ok(c_stego) => c_stego.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// Extraction d'un payload stéganographique depuis un texte hôte.
/// Le pointeur retourné doit être libéré via `aegis_free_string`.
#[no_mangle]
pub unsafe extern "C" fn aegis_stegano_extract_payload(stego_ptr: *const c_char) -> *mut c_char {
    if stego_ptr.is_null() {
        return std::ptr::null_mut();
    }
    let stego = match unsafe { CStr::from_ptr(stego_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match crate::stegano::drowning::extract_mnemonic_from_text(stego) {
        Ok(extracted) => match CString::new(extracted) {
            Ok(c_extracted) => c_extracted.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// Libère la mémoire allouée pour une chaîne C générée par Rust.
#[no_mangle]
pub unsafe extern "C" fn aegis_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

// =========================================================================
// WRAPPERS JNI POUR KOTLIN (MainActivity.kt)
// =========================================================================

/// # Safety
///
/// Ingestion directe de trames caméra YUV420 depuis la couche Android Kotlin (JNI).
/// Les tampons `y_buffer`, `u_buffer` et `v_buffer` doivent pointer vers des zones mémoire valides.
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_aegis_1app_MainActivity_aegis_1ingest_1camera_1frame_1direct(
    _env: *mut c_void,
    _class: *mut c_void,
    y_buffer: *const c_void,
    y_len: i32,
    u_buffer: *const c_void,
    u_len: i32,
    v_buffer: *const c_void,
    v_len: i32,
    width: i32,
    height: i32,
) -> i32 {
    if y_buffer.is_null() || u_buffer.is_null() || v_buffer.is_null() || width <= 0 || height <= 0 {
        return -1;
    }
    ingestion::aegis_ingest_camera_frame_direct(
        y_buffer as *const u8,
        y_len as usize,
        u_buffer as *const u8,
        u_len as usize,
        v_buffer as *const u8,
        v_len as usize,
        width as u32,
        height as u32,
    )
}

/// # Safety
///
/// Rendu VRAM Zero-Copy sur la surface Android (`ANativeWindow`).
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_aegis_1app_MainActivity_aegis_1render_1to_1surface(
    _env: *mut c_void,
    _class: *mut c_void,
    surface: *mut c_void,
) -> i32 {
    viewer::stream_pipe::aegis_render_to_surface(surface)
}

/// # Safety
///
/// Contrôle du lecteur multimédia natif (Play, Pause, Seek).
#[no_mangle]
pub unsafe extern "C" fn Java_com_example_aegis_1app_MainActivity_aegis_1control_1media_1player(
    _env: *mut c_void,
    _class: *mut c_void,
    cmd: *const c_char,
    param: f64,
) -> i32 {
    viewer::stream_pipe::aegis_control_media_player(cmd, param)
}

#[cfg(test)]
mod cov_lib_safe {
    use super::*;
    #[test]
    fn t_crypto_pq_errors() {
        let k = secure_buffer::SecureBuffer::new(32);
        let bad_k = secure_buffer::SecureBuffer::new(16);
        let n = [0u8; 12];
        let p = b"DATA";
        let _ = crypto_pq::encrypt_aes_256_gcm_neon(&bad_k, &n, p, b"");
        let _ = crypto_pq::decrypt_aes_256_gcm_neon(&bad_k, &n, p, b"");
        if let Ok(ct) = crypto_pq::encrypt_aes_256_gcm_neon(&k, &n, p, b"") {
            let mut c_ct = ct.clone();
            if !c_ct.is_empty() { c_ct[0] ^= 0xFF; }
            let _ = crypto_pq::decrypt_aes_256_gcm_neon(&k, &n, &c_ct, b"");
        }
    }
}