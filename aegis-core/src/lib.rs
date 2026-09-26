//! aegis-core/src/lib.rs
//! Point d'Entrée FFI/JNI et Enregistrement des Modules Natifs (CdCM v2.2-RC3).

#![allow(unused_imports, dead_code, unused_variables)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::OnceLock;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use jni::{
    objects::{
        GlobalRef, JByteArray, JByteBuffer, JClass, JObject, JString, JValue, JValueOwned,
    },
    sys::{jdouble, jint, JNI_ERR, JNI_VERSION_1_6},
    JavaVM, JNIEnv,
};

pub mod attestation;
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

pub const ADMIN_PUBLIC_KEY_BYTES: [u8; 32] = [
    0xac, 0x26, 0x11, 0xc4, 0x08, 0xd3, 0x4c, 0xf5,
    0x65, 0x18, 0x9c, 0xba, 0x84, 0x48, 0xd7, 0x76,
    0xc2, 0x0d, 0x95, 0x8c, 0x28, 0x83, 0x72, 0x65,
    0x90, 0x67, 0x69, 0x0c, 0x5d, 0xd2, 0x14, 0x6d,
];

// =========================================================================
// ÉTAT GLOBAL JNI
// =========================================================================

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static MAIN_ACTIVITY: OnceLock<GlobalRef> = OnceLock::new();

// =========================================================================
// JNI_OnLoad
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut c_void,
) -> jint {
    ffi_security::init_native_security();
    secure_buffer::init_secure_buffer_system();

    if vm.is_null() {
        return JNI_ERR;
    }

    let java_vm = match JavaVM::from_raw(vm) {
        Ok(v) => v,
        Err(_) => return JNI_ERR,
    };

    let _ = JAVA_VM.set(java_vm);

    JNI_VERSION_1_6
}

// =========================================================================
// ENREGISTREMENT DE MAINACTIVITY
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegisRegisterMainActivity(
    env: JNIEnv,
    _this: JObject,
    activity: JObject,
) {
    match env.new_global_ref(activity) {
        Ok(global) => {
            if MAIN_ACTIVITY.set(global).is_err() {
                eprintln!("AEGIS: MainActivity déjà enregistrée, on garde l'ancienne");
            } else {
                eprintln!("AEGIS: MainActivity enregistrée avec succès");
            }
        }
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS: new_global_ref a échoué: {}", e);
        }
    }
}

// =========================================================================
// CAPTURE CAMÉRA — DÉLÉGUÉE À KOTLIN VIA JNI
// =========================================================================

#[no_mangle]
pub unsafe extern "C" fn aegis_capture_ndk_camera() -> i32 {
    let jvm = match JAVA_VM.get() {
        Some(jvm) => jvm,
        None => {
            eprintln!("AEGIS: JNI_OnLoad n'a pas initialisé JAVA_VM");
            return -1;
        }
    };

    let activity = match MAIN_ACTIVITY.get() {
        Some(a) => a,
        None => {
            eprintln!("AEGIS: MainActivity non enregistrée.");
            return -2;
        }
    };

    let mut env = match jvm.attach_current_thread_as_daemon() {
        Ok(env) => env,
        Err(e) => {
            eprintln!("AEGIS: attach_current_thread_as_daemon a échoué: {}", e);
            return -3;
        }
    };

    match env.call_method(
        activity.as_obj(),
        "aegisStartHardwareCapture",
        "()I",
        &[] as &[JValue],
    ) {
        Ok(JValueOwned::Int(code)) => code,
        Ok(other) => {
            eprintln!("AEGIS: type de retour inattendu: {:?}", other);
            -4
        }
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS: appel aegisStartHardwareCapture a échoué: {}", e);
            -5
        }
    }
}

// =========================================================================
// APPELS FFI EXISTANTS (C ABI — Dart/Flutter)
// =========================================================================

// FIX Phase 3.5 : `aegis_set_hardware_secret` enregistre désormais la clé
// au lieu de tenter de la générer localement (backdoor crypto supprimée).
#[no_mangle]
pub unsafe extern "C" fn aegis_set_hardware_secret(secret_ptr: *const u8, secret_len: usize) -> i32 {
    if secret_ptr.is_null() || secret_len != 32 {
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(secret_ptr, secret_len) };
    match crate::keystore::HardwareKeystore::set_root_key(bytes) {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_verify_apk_signature_or_burn(apk_sha256_ptr: *const c_char) {
    if apk_sha256_ptr.is_null() {
        panic::panic_purge();
        return;
    }
    if unsafe { CStr::from_ptr(apk_sha256_ptr) }.to_str().is_err() {
        panic::panic_purge();
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_verify_license_key(license_ptr: *const c_char) -> i32 {
    if license_ptr.is_null() {
        return -1;
    }
    let hex_lic = match unsafe { CStr::from_ptr(license_ptr) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -2,
    };
    let decoded_bytes = match hex::decode(hex_lic) {
        Ok(b) => b,
        Err(_) => return -3,
    };
    let decoded_str = match std::str::from_utf8(&decoded_bytes) {
        Ok(s) => s,
        Err(_) => return -4,
    };
    let parts: Vec<&str> = decoded_str.split(':').collect();
    if parts.len() != 2 {
        return -5;
    }

    let order_num = parts[0].trim();
    let sig_bytes = match hex::decode(parts[1].trim()) {
        Ok(b) => b,
        Err(_) => return -6,
    };
    let signature_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return -7,
    };
    let signature = Signature::from_bytes(&signature_array);
    let verifying_key = match VerifyingKey::from_bytes(&ADMIN_PUBLIC_KEY_BYTES) {
        Ok(vk) => vk,
        Err(_) => return -8,
    };

    if verifying_key.verify(order_num.as_bytes(), &signature).is_ok() {
        0
    } else {
        -9
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ingest_file_zero_disk(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() {
        return -1;
    }
    let path_str = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
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

#[no_mangle]
pub unsafe extern "C" fn aegis_stegano_drown_payload(
    key_ptr: *const c_char,
    poem_ptr: *const c_char,
) -> *mut c_char {
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
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

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
            Ok(c) => c.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_apply_prnu_and_save(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() {
        return -1;
    }
    let path_str = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match std::fs::read(path_str) {
        Ok(bytes) => match crate::ingestion::aegis_ingest_file_zero_disk(&bytes) {
            Ok(secure_buf) => {
                if std::fs::write(path_str, secure_buf.as_slice()).is_ok() {
                    0
                } else {
                    -3
                }
            }
            Err(_) => -4,
        },
        Err(_) => -5,
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_send_p2p_tor(
    path_ptr: *const c_char,
    target_ptr: *const c_char,
) -> i32 {
    if path_ptr.is_null() || target_ptr.is_null() {
        return -1;
    }

    let path = match std::ffi::CStr::from_ptr(path_ptr).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -2,
    };
    let target = match std::ffi::CStr::from_ptr(target_ptr).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -3,
    };

    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            rt.block_on(async move {
                if let Err(e) =
                    crate::network::tor::AegisTorClient::bootstrap(&target, &path).await
                {
                    eprintln!("AEGIS_FATAL: Échec tunnel Tor vers {} — {}", target, e);
                }
            });
        }
    });
    0
}

// =========================================================================
// WRAPPERS JNI — MainActivity
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ingest_1camera_1frame_1direct(
    env: JNIEnv,
    _this: JObject,
    y_buffer: JByteBuffer,
    y_len: jint,
    u_buffer: JByteBuffer,
    u_len: jint,
    v_buffer: JByteBuffer,
    v_len: jint,
    width: jint,
    height: jint,
) -> jint {
    if width <= 0 || height <= 0 {
        return -1;
    }

    let y_ptr = match env.get_direct_buffer_address(&y_buffer) {
        Ok(p) if !p.is_null() => p,
        _ => { let _ = env.exception_clear(); return -10; }
    };
    let u_ptr = match env.get_direct_buffer_address(&u_buffer) {
        Ok(p) if !p.is_null() => p,
        _ => { let _ = env.exception_clear(); return -11; }
    };
    let v_ptr = match env.get_direct_buffer_address(&v_buffer) {
        Ok(p) if !p.is_null() => p,
        _ => { let _ = env.exception_clear(); return -12; }
    };

    if let Ok(cap) = env.get_direct_buffer_capacity(&y_buffer) {
        if (y_len as usize) > cap { return -13; }
    }
    if let Ok(cap) = env.get_direct_buffer_capacity(&u_buffer) {
        if (u_len as usize) > cap { return -14; }
    }
    if let Ok(cap) = env.get_direct_buffer_capacity(&v_buffer) {
        if (v_len as usize) > cap { return -15; }
    }

    crate::ingestion::aegis_ingest_camera_frame_direct(
        y_ptr as *const u8, y_len as usize,
        u_ptr as *const u8, u_len as usize,
        v_ptr as *const u8, v_len as usize,
        width as u32, height as u32,
    )
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1render_1to_1surface(
    env: JNIEnv,
    _this: JObject,
    surface: JObject,
) -> jint {
    crate::viewer::stream_pipe::aegis_render_to_surface(env, surface.as_raw())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1release_1surface(
    _env: JNIEnv,
    _this: JObject,
) -> jint {
    crate::viewer::stream_pipe::aegis_release_surface()
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1control_1media_1player(
    mut env: JNIEnv,
    _this: JObject,
    cmd: JString,
    param: jdouble,
) -> jint {
    let cmd_rust: String = match env.get_string(&cmd) {
        Ok(s) => s.into(),
        Err(_) => { let _ = env.exception_clear(); return -1; }
    };

    let cmd_c = match CString::new(cmd_rust) {
        Ok(c) => c,
        Err(_) => return -2,
    };

    crate::viewer::stream_pipe::aegis_control_media_player(cmd_c.as_ptr(), param)
}

// =========================================================================
// WRAPPERS JNI — ProtectedConfirmation
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_ProtectedConfirmation_aegisPanicSilentBurn(
    _env: JNIEnv,
    _this: JObject,
) {
    crate::panic::panic_purge();
}

// =========================================================================
// WRAPPER JNI — Master Key derivation (Option 2)
// =========================================================================
//
// Phase 3.5+ (audit 2026-09-20) :
//   Dérive la master_key à partir du vault PIN saisi par l'utilisateur,
//   combiné avec la ROOT_KEY fournie par le StrongBox/TEE.
//
//   HKDF-SHA256(IKM = ROOT_KEY || PIN, salt, info) → MASTER_KEY
//
// Kotlin : `external fun aegis_derive_and_set_master_key(pin: String): Int`
//
// NOTE : `mut env` OBLIGATOIRE — `get_string` prend `&mut self` en jni 0.21
// (contrairement à `convert_byte_array` et `exception_clear`).

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1derive_1and_1set_1master_1key(
    mut env: JNIEnv,
    _this: JObject,
    pin: JString,
) -> jint {
    let pin_str: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS-MASTER: get_string(pin) a échoué: {}", e);
            return -1;
        }
    };

    match crate::keystore::HardwareKeystore::derive_master_key(&pin_str) {
        Ok(_) => {
            eprintln!("AEGIS-MASTER: master_key dérivée (HKDF-SHA256)");
            0
        }
        Err(msg) => {
            eprintln!("AEGIS-MASTER: derive_master_key refusé: {}", msg);
            if msg.contains("vide") {
                -2
            } else if msg.contains("non initialisée") {
                -3
            } else {
                -4
            }
        }
    }
}

// =========================================================================
// WRAPPER JNI — Android Key Attestation (Niveau 3)
// =========================================================================

/// Vérifie la chaîne d'attestation matérielle Android.
///
/// Kotlin : `external fun aegis_verify_attestation_chain(chain: ByteArray, challenge: ByteArray): Int`
///
/// Retours :
///   0   = attestation OK (device + APK intègres)
///  -1..-11 = code d'erreur (voir AttestationStatus::to_code)
///  -100..-102 = erreurs JNI (conversion byte[] échouée, challenge invalide)
///
/// Si le statut est critique (APK modifié, bootloader unlocked, root),
/// `panic_purge()` est appelé AVANT de retourner le code négatif.
///
/// FIX 2 : `convert_byte_array` et `exception_clear` prennent tous deux `&self`
/// → pas de `mut env` nécessaire (warning corrigé).
#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1verify_1attestation_1chain(
    env: JNIEnv,
    _this: JObject,
    chain: JByteArray,
    challenge: JByteArray,
) -> jint {
    // 1) Extraire la chaîne DER
    let chain_vec: Vec<u8> = match env.convert_byte_array(&chain) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS-ATTEST: convert_byte_array(chain) a échoué: {}", e);
            return -100;
        }
    };

    // 2) Extraire le challenge (SHA-256 APK)
    let challenge_vec: Vec<u8> = match env.convert_byte_array(&challenge) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS-ATTEST: convert_byte_array(challenge) a échoué: {}", e);
            return -101;
        }
    };

    // 3) Vérifier le challenge (doit faire 32 octets = SHA-256)
    if challenge_vec.len() != 32 {
        eprintln!(
            "AEGIS-ATTEST: challenge invalide ({} octets, attendu 32)",
            challenge_vec.len()
        );
        return -102;
    }

    // 4) Vérifier la chaîne d'attestation
    let status = crate::attestation::verify_attestation_chain(&chain_vec, &challenge_vec);

    eprintln!(
        "AEGIS-ATTEST: status={:?} (code={})",
        status,
        status.to_code()
    );

    // 5) Si critique → PanicPurge immédiat
    if status.is_critical() {
        eprintln!("AEGIS-ATTEST: COMPROMISSION CRITIQUE — PanicPurge déclenché");
        crate::panic::panic_purge();
        // Note : panic_purge() appelle exit(137), donc on ne retourne pas.
        // Ce code n'est atteint qu'en mode test.
    }

    status.to_code()
}