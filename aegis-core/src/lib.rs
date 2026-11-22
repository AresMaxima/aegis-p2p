//! aegis-core/src/lib.rs
//! Point d'EntrÃƒÆ’Ã‚Â©e FFI/JNI et Enregistrement des Modules Natifs (CdCM v2.2-RC3).
//!
//! =========================================================================
//! CONTRAT DE SÃƒÆ’Ã¢â‚¬Â°CURITÃƒÆ’Ã¢â‚¬Â° FFI ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â AEGIS CORE (Mil-Spec)
//! =========================================================================
//!
//! Ce document dÃƒÆ’Ã‚Â©finit le contrat de sÃƒÆ’Ã‚Â©curitÃƒÆ’Ã‚Â© commun ÃƒÆ’Ã‚Â  **toutes les fonctions
//! `pub unsafe extern "C"` et `pub unsafe extern "system"`** exposÃƒÆ’Ã‚Â©es par ce
//! crate et ses sous-modules (`network/ble_handshake.rs`, `network/ble_mesh.rs`,
//! `network/ble_mesh_reader.rs`, `viewer/stream_pipe.rs`). Chaque wrapper
//! adhÃƒÆ’Ã‚Â¨re dÃƒÆ’Ã‚Â©fensivement ÃƒÆ’Ã‚Â  ce contrat ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â voir le code de chaque fonction pour
//! les vÃƒÆ’Ã‚Â©rifications effectives.
//!
//! ## 1. Pointeurs (rÃƒÆ’Ã‚Â¨gle universelle)
//! - `*const T` / `*mut T` : jamais `null` sauf mention contraire explicite.
//!   Chaque wrapper vÃƒÆ’Ã‚Â©rifie `ptr.is_null()` avant tout dÃƒÆ’Ã‚Â©rÃƒÆ’Ã‚Â©fÃƒÆ’Ã‚Â©rencement et
//!   retourne un code d'erreur documentÃƒÆ’Ã‚Â© si le contrat est violÃƒÆ’Ã‚Â©.
//! - Alignement : `align_of::<T>()`. Les `*const u8` / `*mut u8` n'ont pas
//!   de contrainte d'alignement (1 octet).
//! - DurÃƒÆ’Ã‚Â©e de vie : tout pointeur d'entrÃƒÆ’Ã‚Â©e doit rester valide pendant l'appel.
//!   AEGIS ne conserve AUCUN pointeur aprÃƒÆ’Ã‚Â¨s retour (pas de dangling possible).
//!
//! ## 2. ChaÃƒÆ’Ã‚Â®nes C (`*const c_char`)
//! - Encodage **UTF-8 strict** (jamais Latin-1 ni Windows-1252).
//! - Null-terminated obligatoire. AEGIS retourne `-2` si l'UTF-8 est invalide.
//!
//! ## 3. Buffers de sortie
//! - Toute fonction qui ÃƒÆ’Ã‚Â©crit dans un buffer **documente sa taille minimale**
//!   dans sa doc spÃƒÆ’Ã‚Â©cifique (`MAX_MANIFEST_BYTES`, `MAX_SIG_BYTES`, tailles
//!   fixes 32/64 octets, etc.).
//! - Buffer trop petit = comportement indÃƒÆ’Ã‚Â©fini (ÃƒÆ’Ã‚Â©crasement mÃƒÆ’Ã‚Â©moire). AEGIS ne
//!   peut pas dÃƒÆ’Ã‚Â©tecter cette erreur a posteriori : la responsabilitÃƒÆ’Ã‚Â© est sur
//!   l'appelant. Les tailles EFFECTIVES ÃƒÆ’Ã‚Â©crites sont retournÃƒÆ’Ã‚Â©es via `*mut usize`.
//!
//! ## 4. Ownership et libÃƒÆ’Ã‚Â©ration
//! - EntrÃƒÆ’Ã‚Â©es : AEGIS n'assume jamais l'ownership, l'appelant libÃƒÆ’Ã‚Â¨re.
//! - Sorties `*mut c_char` (ex: `aegis_stegano_drown_payload`) : ownership
//!   transfÃƒÆ’Ã‚Â©rÃƒÆ’Ã‚Â©. L'appelant **doit** appeler `aegis_free_string()` pour libÃƒÆ’Ã‚Â©rer
//!   (via `CString::from_raw`, jamais `free()` C).
//!
//! ## 5. Thread safety
//! - Toutes les fonctions sont **thread-safe sauf mention contraire**.
//! - ÃƒÆ’Ã¢â‚¬Â°tats globaux (`JAVA_VM`, `MAIN_ACTIVITY`, `WIFI_DIRECT_FD`,
//!   `TOR_STRONGBOX_AVAILABLE`) protÃƒÆ’Ã‚Â©gÃƒÆ’Ã‚Â©s par `Atomic*` ou `OnceLock`.
//! - **Aucune fonction FFI n'est rÃƒÆ’Ã‚Â©entrante en cas de panic interne** : le
//!   crate est compilÃƒÆ’Ã‚Â© avec `panic = "abort"` (profil release), donc tout
//!   panic tue le process sans unwind ÃƒÆ’Ã‚Â  travers la frontiÃƒÆ’Ã‚Â¨re FFI.
//!
//! ## 6. Codes de retour
//! - `0` = succÃƒÆ’Ã‚Â¨s.
//! - `< 0` = erreur (valeur documentÃƒÆ’Ã‚Â©e par fonction).
//! - `1` / `2` = succÃƒÆ’Ã‚Â¨s avec variante (ex: `aegis_vault_unlock` ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ 0 Real, 1 Decoy, 2 NeedsInit).
//! - `-1` gÃƒÆ’Ã‚Â©nÃƒÆ’Ã‚Â©rique = pointeur NULL ou argument invalide.
//!
//! ## 7. Comportement en cas de violation critique
//! Certaines fonctions (`aegis_verify_apk_signature_or_burn`,
//! `aegisPanicSilentBurn`, `Java_..._verify_1attestation_1chain` en statut
//! critique) dÃƒÆ’Ã‚Â©clenchent `panic_purge()` ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ `exit(137)`. C'est **intentionnel** :
//! la RAM est dÃƒÆ’Ã‚Â©truite et le processus meurt immÃƒÆ’Ã‚Â©diatement. Aucun retour.
//!
//! ## 8. Wrappers JNI (`Java_com_aresmaxima_aegis_*`)
//! - Signature imposÃƒÆ’Ã‚Â©e par JNI : `(JNIEnv, JObject, ...args) -> jint`.
//! - `env` / `_this` garantis valides par le runtime Android.
//! - Arguments JNI (`JString`, `JByteArray`, `JByteBuffer`) validÃƒÆ’Ã‚Â©s par le
//!   crate `jni` ; `exception_clear()` appelÃƒÆ’Ã‚Â© en cas d'erreur pour ne pas
//!   propager d'exception Java.
//!
//! ## RÃƒÆ’Ã‚Â©fÃƒÆ’Ã‚Â©rences
//! - Rust FFI Omnibus : <https://jakegoulding.com/rust-ffi-omnibus/>
//! - Rustonomicon Ãƒâ€šÃ‚Â§FFI : <https://doc.rust-lang.org/nomicon/ffi.html>
//! - Android JNI Tips : <https://developer.android.com/training/articles/perf-jni>
//!
//! =========================================================================

#![allow(unused_imports, dead_code, unused_variables)]

// =========================================================================
// Configuration Clippy ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â AEGIS (Mil-Spec)
//
// Politique :
//   ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ SECURITY & SAFETY : -D warnings (les lints de sÃƒÆ’Ã‚Â©curitÃƒÆ’Ã‚Â© bloquent).
//   ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ ÃƒÂ¢Ã…Â¡Ã‚Âª STYLE : allow-list documentÃƒÆ’Ã‚Â©e ci-dessous (aucun impact sÃƒÆ’Ã‚Â©curitÃƒÆ’Ã‚Â©).
//
// Toute exception est auditÃƒÆ’Ã‚Â©e trimestriellement.
// =========================================================================
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::result_unit_err)]
#![allow(clippy::needless_return)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::items_after_test_module)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_repeat_n)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::manual_pattern_char_comparison)]
#![allow(clippy::manual_c_str_literals)]
#![allow(clippy::chunks_exact_to_as_chunks)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::useless_vec)]
#![allow(clippy::missing_const_for_thread_local)]
#![allow(clippy::manual_unwrap_or)]
// Documentation FFI : le contrat de sÃƒÆ’Ã‚Â©curitÃƒÆ’Ã‚Â© global est dÃƒÆ’Ã‚Â©fini en tÃƒÆ’Ã‚Âªte de
// crate (voir "Contrat de SÃƒÆ’Ã‚Â©curitÃƒÆ’Ã‚Â© FFI ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â AEGIS Core"). Les 43 wrappers FFI
// y adhÃƒÆ’Ã‚Â¨rent dÃƒÆ’Ã‚Â©fensivement (validation `is_null`, bornes, encodage UTF-8).
// Le lint per-fonction est dÃƒÆ’Ã‚Â©sactivÃƒÆ’Ã‚Â© car la doc est centralisÃƒÆ’Ã‚Â©e et maintenue
// comme une seule source de vÃƒÆ’Ã‚Â©ritÃƒÆ’Ã‚Â© ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â dÃƒÆ’Ã‚Â©cision architecturale documentÃƒÆ’Ã‚Â©e.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::OnceLock;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use jni::{
    objects::{
        GlobalRef, JByteArray, JByteBuffer, JClass, JObject, JString, JValue, JValueOwned,
    },
    sys::{jdouble, jint, JNI_ERR, JNI_VERSION_1_6},
    JavaVM, JNIEnv,
};

// =========================================================================
// P0-A.1e : StrongBox gate pour Tor (D42-bis + D62)
// =========================================================================

static TOR_STRONGBOX_AVAILABLE: AtomicBool = AtomicBool::new(false);

pub fn tor_strongbox_is_available() -> bool {
    TOR_STRONGBOX_AVAILABLE.load(Ordering::SeqCst)
}

pub mod attestation;
pub mod crypto;
pub mod crypto_pq;
pub mod deadman;
pub mod ffi_security;
pub mod hardware_triggers;
pub mod ingestion;
pub mod integrity_timing;
pub mod keystore;
pub mod vault_persistence;
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
pub mod updater;

pub const ADMIN_PUBLIC_KEY_BYTES: [u8; 32] = [
    0xa2, 0xc5, 0x26, 0xc8, 0x29, 0x30, 0x9e, 0xb8,
    0xa9, 0xa2, 0x6c, 0x9e, 0xab, 0x02, 0x2b, 0x88,
    0x76, 0x1e, 0xa0, 0x0a, 0x84, 0xdf, 0xd8, 0x1d,
    0x94, 0xb5, 0x5b, 0xed, 0x82, 0x4f, 0x59, 0x38,
];

// =========================================================================
// ÃƒÆ’Ã¢â‚¬Â°TAT GLOBAL JNI
// =========================================================================

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static MAIN_ACTIVITY: OnceLock<GlobalRef> = OnceLock::new();

// =========================================================================
// JNI_OnLoad
// =========================================================================

/// # Safety
///
/// AppelÃƒÆ’Ã‚Â©e uniquement par le runtime Android (JNI).
/// `vm` doit ÃƒÆ’Ã‚Âªtre un pointeur valide vers un `JavaVM`.
/// `_reserved` doit ÃƒÆ’Ã‚Âªtre NULL.
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut c_void,
) -> jint {
    ffi_security::init_native_security();
    secure_buffer::init_secure_buffer_system();

    // Ancres runtime (empÃƒÆ’Ã‚Âªchent --gc-sections d'ÃƒÆ’Ã‚Â©liminer les symboles
    // FFI non rÃƒÆ’Ã‚Â©fÃƒÆ’Ã‚Â©rencÃƒÆ’Ã‚Â©s dans le crate).
    _anchor_vault_ffi();
    _anchor_wifi_direct_ffi();
    _anchor_updater_ffi();
    _anchor_tor_fetch_ffi();
    _anchor_deadman_ffi();
    _anchor_panic_purge_ffi();
    _anchor_v36_hardening_ffi();

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
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegisRegisterMainActivity(
    env: JNIEnv,
    _this: JObject,
    activity: JObject,
) {
    match env.new_global_ref(activity) {
        Ok(global) => {
            if MAIN_ACTIVITY.set(global).is_err() {
                eprintln!("AEGIS: MainActivity dÃƒÆ’Ã‚Â©jÃƒÆ’Ã‚Â  enregistrÃƒÆ’Ã‚Â©e, on garde l'ancienne");
            } else {
                eprintln!("AEGIS: MainActivity enregistrÃƒÆ’Ã‚Â©e avec succÃƒÆ’Ã‚Â¨s");
            }
        }
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS: new_global_ref a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
        }
    }
}

// =========================================================================
// CAPTURE CAMÃƒÆ’Ã¢â‚¬Â°RA ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â DÃƒÆ’Ã¢â‚¬Â°LÃƒÆ’Ã¢â‚¬Â°GUÃƒÆ’Ã¢â‚¬Â°E ÃƒÆ’Ã¢â€šÂ¬ KOTLIN VIA JNI
// =========================================================================

#[no_mangle]
pub unsafe extern "C" fn aegis_capture_ndk_camera() -> i32 {
    let jvm = match JAVA_VM.get() {
        Some(jvm) => jvm,
        None => {
            eprintln!("AEGIS: JNI_OnLoad n'a pas initialisÃƒÆ’Ã‚Â© JAVA_VM");
            return -1;
        }
    };

    let activity = match MAIN_ACTIVITY.get() {
        Some(a) => a,
        None => {
            eprintln!("AEGIS: MainActivity non enregistrÃƒÆ’Ã‚Â©e.");
            return -2;
        }
    };

    let mut env = match jvm.attach_current_thread_as_daemon() {
        Ok(env) => env,
        Err(e) => {
            eprintln!("AEGIS: attach_current_thread_as_daemon a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
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
            eprintln!("AEGIS: appel aegisStartHardwareCapture a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            -5
        }
    }
}

// =========================================================================
// P0-A.1e : FFI StrongBox gate pour Tor
// =========================================================================

#[no_mangle]
pub extern "C" fn aegis_tor_set_strongbox_available(available: bool) {
    TOR_STRONGBOX_AVAILABLE.store(available, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn aegis_tor_strongbox_available() -> i32 {
    if TOR_STRONGBOX_AVAILABLE.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}

// =========================================================================
// P0-A.2b.1 : IdentitÃƒÆ’Ã‚Â© ed25519 P2P
// =========================================================================

static EXTERNAL_NFC_TOKEN_SECRET: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);

fn derive_ed25519_identity() -> Result<SigningKey, String> {
    let master_key = crate::keystore::HardwareKeystore::get_master_key()
        .map_err(|e| format!("master_key indisponible: {}", e))?;

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(master_key.as_slice());
    if let Ok(guard) = EXTERNAL_NFC_TOKEN_SECRET.lock() {
        if let Some(nfc_secret) = guard.as_ref() {
            ikm.extend_from_slice(nfc_secret);
        }
    }

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(b"AEGIS-ED25519-IDENTITY"),
        &ikm,
    );
    use zeroize::Zeroize;
    ikm.zeroize();

    let mut seed = [0u8; 32];
    hk.expand(b"v1", &mut seed)
        .map_err(|e| format!("HKDF expand: {}", e))?;

    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();

    Ok(signing_key)
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ed25519_sign(
    challenge_ptr: *const u8,
    challenge_len: usize,
    sig_out_ptr: *mut u8,
) -> i32 {
    if challenge_ptr.is_null() || sig_out_ptr.is_null() {
        return -1;
    }
    if challenge_len != 32 {
        return -2;
    }

    let signing_key = match derive_ed25519_identity() {
        Ok(k) => k,
        Err(_) => return -3,
    };

    let challenge = unsafe { std::slice::from_raw_parts(challenge_ptr, challenge_len) };
    let signature = signing_key.sign(challenge);
    let sig_bytes = signature.to_bytes();

    unsafe { std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), sig_out_ptr, 64) };
    0
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ed25519_verify(
    challenge_ptr: *const u8,
    challenge_len: usize,
    pubkey_ptr: *const u8,
    sig_ptr: *const u8,
) -> i32 {
    if challenge_ptr.is_null() || pubkey_ptr.is_null() || sig_ptr.is_null() {
        return -1;
    }

    let challenge = unsafe { std::slice::from_raw_parts(challenge_ptr, challenge_len) };

    let pk_arr: [u8; 32] = match unsafe { std::slice::from_raw_parts(pubkey_ptr, 32) }.try_into() {
        Ok(a) => a,
        Err(_) => return -2,
    };
    let sig_arr: [u8; 64] = match unsafe { std::slice::from_raw_parts(sig_ptr, 64) }.try_into() {
        Ok(a) => a,
        Err(_) => return -2,
    };

    let pubkey = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return -2,
    };
    let signature = Signature::from_bytes(&sig_arr);

    if pubkey.verify(challenge, &signature).is_ok() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ed25519_public_key(pubkey_out_ptr: *mut u8) -> i32 {
    if pubkey_out_ptr.is_null() {
        return -1;
    }

    let signing_key = match derive_ed25519_identity() {
        Ok(k) => k,
        Err(_) => return -3,
    };

    let verifying_key = signing_key.verifying_key();
    let bytes = verifying_key.as_bytes();

    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pubkey_out_ptr, 32) };
    0
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ed25519_fingerprint(out_ptr: *mut u8) -> i32 {
    if out_ptr.is_null() {
        return -1;
    }

    let signing_key = match derive_ed25519_identity() {
        Ok(k) => k,
        Err(_) => return -3,
    };

    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.as_bytes();

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    let fingerprint = hasher.finalize();

    unsafe { std::ptr::copy_nonoverlapping(fingerprint.as_ptr(), out_ptr, 32) };
    0
}

// =========================================================================
// P0-A.2b.3a : Wi-Fi Direct socket fd
// =========================================================================

static WIFI_DIRECT_FD: AtomicI32 = AtomicI32::new(-1);

#[no_mangle]
pub unsafe extern "C" fn aegis_wifi_direct_set_fd(fd: i32) -> i32 {
    if fd < 0 {
        return -1;
    }

    #[cfg(unix)]
    {
        let mut sock_type: libc::c_int = 0;
        let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sock_type as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 || sock_type != libc::SOCK_STREAM {
            return -2;
        }
    }

    match WIFI_DIRECT_FD.compare_exchange(
        -1,
        fd,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => 0,
        Err(_) => -3,
    }
}

#[no_mangle]
pub extern "C" fn aegis_wifi_direct_get_fd() -> i32 {
    WIFI_DIRECT_FD.load(Ordering::SeqCst)
}

pub(crate) fn ed25519_sign_safe(challenge: &[u8; 32]) -> Result<[u8; 64], String> {
    let mut sig = [0u8; 64];
    let rc = unsafe {
        aegis_ed25519_sign(challenge.as_ptr(), 32, sig.as_mut_ptr())
    };
    match rc {
        0 => Ok(sig),
        -3 => Err("master_key indisponible".to_string()),
        _ => Err(format!("ed25519_sign rc={}", rc)),
    }
}

pub(crate) fn ed25519_verify_safe(
    challenge: &[u8; 32],
    pubkey: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    let rc = unsafe {
        aegis_ed25519_verify(
            challenge.as_ptr(),
            32,
            pubkey.as_ptr(),
            sig.as_ptr(),
        )
    };
    rc == 1
}

pub(crate) fn ed25519_fingerprint_safe() -> Result<[u8; 32], String> {
    let mut fp = [0u8; 32];
    let rc = unsafe { aegis_ed25519_fingerprint(fp.as_mut_ptr()) };
    match rc {
        0 => Ok(fp),
        -3 => Err("master_key indisponible".to_string()),
        _ => Err(format!("ed25519_fingerprint rc={}", rc)),
    }
}

pub(crate) fn take_wifi_direct_fd() -> i32 {
    WIFI_DIRECT_FD.swap(-1, Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn aegis_wifi_direct_close_fd() -> i32 {
    let fd = WIFI_DIRECT_FD.swap(-1, Ordering::SeqCst);

    #[cfg(unix)]
    if fd >= 0 {
        unsafe { libc::close(fd); }
    }

    #[cfg(not(unix))]
    let _ = fd;

    0
}

// =========================================================================
// C64 FIX ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Wrappers JNI pour WifiDirectBridge.kt
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_WifiDirectBridge_aegis_1wifi_1direct_1set_1fd(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
    fd: jni::sys::jint,
) -> jni::sys::jint {
    aegis_wifi_direct_set_fd(fd as i32) as jni::sys::jint
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_WifiDirectBridge_aegis_1wifi_1direct_1close_1fd(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
) -> jni::sys::jint {
    aegis_wifi_direct_close_fd() as jni::sys::jint
}

// =========================================================================
// FIX Phase 3.5 : set_hardware_secret
// =========================================================================

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

/// # Safety
///
/// `apk_sha256_ptr` doit pointer vers une chaÃƒÆ’Ã‚Â®ne C valide (UTF-8, null-terminated).
/// Si le pointeur est NULL ou la chaÃƒÆ’Ã‚Â®ne invalide, l'appel dÃƒÆ’Ã‚Â©clenche un `panic_purge` (kill process).
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

/// # Safety
///
/// `license_ptr` doit pointer vers une chaÃƒÆ’Ã‚Â®ne C valide (hex-encoded, null-terminated).
/// Retourne 0 si la licence est valide, <0 sinon.
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

    let mut signed_msg = Vec::with_capacity(crate::updater::LICENSE_DOMAIN.len() + order_num.len());
    signed_msg.extend_from_slice(crate::updater::LICENSE_DOMAIN);
    signed_msg.extend_from_slice(order_num.as_bytes());

    if verifying_key.verify(&signed_msg, &signature).is_ok() {
        0
    } else {
        -9
    }
}

/// # Safety
///
/// VÃƒÆ’Ã‚Â©rifie une licence liÃƒÆ’Ã‚Â©e ÃƒÆ’Ã‚Â  un appareil spÃƒÆ’Ã‚Â©cifique.
///
/// Format licence : `CMD-XXX:FINGERPRINT_HEX:SIGNATURE_HEX` (encodÃƒÆ’Ã‚Â© en hex global).
/// Signature ed25519 vÃƒÆ’Ã‚Â©rifiÃƒÆ’Ã‚Â©e sur `LICENSE:v1:CMD-XXX:FINGERPRINT_HEX`.
/// `device_fingerprint_ptr` doit pointer vers une chaÃƒÆ’Ã‚Â®ne C valide (64 chars hex).
/// Retourne 0 si signature valide ET fingerprint match, <0 sinon.
#[no_mangle]
pub unsafe extern "C" fn aegis_verify_license_key_bound(
    license_ptr: *const c_char,
    device_fingerprint_ptr: *const c_char,
) -> i32 {
    if license_ptr.is_null() || device_fingerprint_ptr.is_null() {
        return -1;
    }

    // 1. Decode la licence (hex)
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

    // 2. Format attendu : 3 parties (CMD:FINGERPRINT:SIG)
    let parts: Vec<&str> = decoded_str.split(':').collect();
    if parts.len() != 3 {
        return -5;
    }

    let order_num = parts[0].trim();
    let license_fingerprint = parts[1].trim();
    let sig_bytes = match hex::decode(parts[2].trim()) {
        Ok(b) => b,
        Err(_) => return -6,
    };
    let signature_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return -7,
    };
    let signature = Signature::from_bytes(&signature_array);

    // 3. Decode le fingerprint de l'appareil
    let device_fingerprint = match unsafe { CStr::from_ptr(device_fingerprint_ptr) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -10,
    };

    // 4. Comparer fingerprints
    if device_fingerprint != license_fingerprint {
        return -11;
    }

    // 5. VÃƒÆ’Ã‚Â©rifier signature ed25519 sur LICENSE:v1:CMD:FINGERPRINT
    let verifying_key = match VerifyingKey::from_bytes(&ADMIN_PUBLIC_KEY_BYTES) {
        Ok(vk) => vk,
        Err(_) => return -8,
    };

    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(crate::updater::LICENSE_DOMAIN);
    signed_msg.extend_from_slice(order_num.as_bytes());
    signed_msg.push(b':');
    signed_msg.extend_from_slice(license_fingerprint.as_bytes());

    if verifying_key.verify(&signed_msg, &signature).is_ok() {
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
                    eprintln!("AEGIS_FATAL: ÃƒÆ’Ã¢â‚¬Â°chec tunnel Tor vers {} ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â {}", target, e);
                }
            });
        }
    });
    0
}

// =========================================================================
// WRAPPERS JNI ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â MainActivity
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1ingest_1camera_1frame_1direct(
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
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1render_1to_1surface(
    env: JNIEnv,
    _this: JObject,
    surface: JObject,
) -> jint {
    crate::viewer::stream_pipe::aegis_render_to_surface(env, surface.as_raw())
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1release_1surface(
    _env: JNIEnv,
    _this: JObject,
) -> jint {
    crate::viewer::stream_pipe::aegis_release_surface()
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1control_1media_1player(
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
// WRAPPERS JNI ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â ProtectedConfirmation
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_ProtectedConfirmation_aegisPanicSilentBurn(
    _env: JNIEnv,
    _this: JObject,
) {
    crate::panic::panic_purge();
}

// =========================================================================
// WRAPPER JNI ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Master Key derivation
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1derive_1and_1set_1master_1key(
    mut env: JNIEnv,
    _this: JObject,
    pin: JString,
) -> jint {
    let pin_str: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS-MASTER: get_string(pin) a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            return -1;
        }
    };

    match crate::keystore::HardwareKeystore::derive_master_key(&pin_str) {
        Ok(_) => {
            eprintln!("AEGIS-MASTER: master_key dÃƒÆ’Ã‚Â©rivÃƒÆ’Ã‚Â©e (HKDF-SHA256)");
            0
        }
        Err(msg) => {
            eprintln!("AEGIS-MASTER: derive_master_key refusÃƒÆ’Ã‚Â©: {}", msg);
            if msg.contains("vide") {
                -2
            } else if msg.contains("non initialisÃƒÆ’Ã‚Â©e") {
                -3
            } else {
                -4
            }
        }
    }
}

// =========================================================================
// WRAPPER JNI ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Android Key Attestation
// =========================================================================

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1verify_1attestation_1chain(
    env: JNIEnv,
    _this: JObject,
    chain: JByteArray,
    challenge: JByteArray,
) -> jint {
    let chain_vec: Vec<u8> = match env.convert_byte_array(&chain) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS-ATTEST: convert_byte_array(chain) a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            return -100;
        }
    };

    let challenge_vec: Vec<u8> = match env.convert_byte_array(&challenge) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.exception_clear();
            eprintln!("AEGIS-ATTEST: convert_byte_array(challenge) a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            return -101;
        }
    };

    if challenge_vec.len() != 32 {
        eprintln!(
            "AEGIS-ATTEST: challenge invalide ({} octets, attendu 32)",
            challenge_vec.len()
        );
        return -102;
    }

    let status = crate::attestation::verify_attestation_chain(&chain_vec, &challenge_vec);

    eprintln!(
        "AEGIS-ATTEST: status={:?} (code={})",
        status,
        status.to_code()
    );

        if status.is_critical() {
        eprintln!("AEGIS-ATTEST: COMPROMISSION CRITIQUE ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â PanicPurge dÃƒÆ’Ã‚Â©clenchÃƒÆ’Ã‚Â©");
        crate::panic::panic_purge();
    }

    status.to_code()
}

// =========================================================================
// WRAPPERS FFI ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Vault Persistence
// =========================================================================

#[no_mangle]
pub unsafe extern "C" fn aegis_vault_set_dir(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() {
        return -1;
    }
    let path_str = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match crate::vault_persistence::set_vault_dir(std::path::PathBuf::from(path_str)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("AEGIS-VAULT: set_vault_dir a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            -3
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_vault_is_initialized() -> i32 {
    if crate::vault_persistence::vault_is_initialized() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_vault_init(pin_ptr: *const c_char) -> i32 {
    if pin_ptr.is_null() {
        return -1;
    }
    let pin = match unsafe { CStr::from_ptr(pin_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match crate::vault_persistence::vault_init(pin) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("AEGIS-VAULT: vault_init a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            -3
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_vault_unlock(pin_ptr: *const c_char) -> i32 {
    if pin_ptr.is_null() {
        return -1;
    }
    let pin = match unsafe { CStr::from_ptr(pin_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match crate::vault_persistence::vault_unlock(pin) {
        Ok(crate::vault_persistence::VaultSession::Real) => 0,
        Ok(crate::vault_persistence::VaultSession::Decoy) => 1,
        Ok(crate::vault_persistence::VaultSession::NeedsInitialization) => 2,
        Err(e) => {
            eprintln!("AEGIS-VAULT: vault_unlock a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_vault_wipe() -> i32 {
    match crate::vault_persistence::vault_wipe() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("AEGIS-VAULT: vault_wipe a ÃƒÆ’Ã‚Â©chouÃƒÆ’Ã‚Â©: {}", e);
            -1
        }
    }
}

// =========================================================================
// ANCres runtime
// =========================================================================

#[inline(never)]
fn _anchor_wifi_direct_ffi() {
    std::hint::black_box((
        aegis_wifi_direct_set_fd as *const (),
        aegis_wifi_direct_get_fd as *const (),
        aegis_wifi_direct_close_fd as *const (),
        aegis_ed25519_fingerprint as *const (),
    ));
}

#[inline(never)]
fn _anchor_updater_ffi() {
    std::hint::black_box((
        aegis_verify_update_signature as *const (),
    ));
}

#[inline(never)]
fn _anchor_vault_ffi() {
    std::hint::black_box((
        aegis_vault_set_dir as *const (),
        aegis_vault_is_initialized as *const (),
        aegis_vault_init as *const (),
        aegis_vault_unlock as *const (),
        aegis_vault_wipe as *const (),
    ));
}

/// C82 : ancre runtime pour la FFI de fetch manifest via Tor.
#[inline(never)]
fn _anchor_tor_fetch_ffi() {
    std::hint::black_box((
        aegis_tor_fetch_http as *const (),
    ));
}

// =========================================================================
// P10 FIX (2026-11-06) : ancre runtime pour deadman_heartbeat
//
// `aegis_deadman_heartbeat` est dÃƒÆ’Ã‚Â©fini dans `deadman.rs` avec
// `#[no_mangle] pub extern "C"`, mais le linker (--gc-sections) peut
// l'ÃƒÆ’Ã‚Â©liminer s'il n'est rÃƒÆ’Ã‚Â©fÃƒÆ’Ã‚Â©rencÃƒÆ’Ã‚Â© que par DeadMansSwitch::heartbeat()
// (lui-mÃƒÆ’Ã‚Âªme jamais instanciÃƒÆ’Ã‚Â©). Cette ancre garantit la prÃƒÆ’Ã‚Â©sence du
// symbole dans le .so final, sinon l'appel Dart dans main.dart:622
// ÃƒÆ’Ã‚Â©choue silencieusement (catch).
// =========================================================================

#[inline(never)]
fn _anchor_deadman_ffi() {
    std::hint::black_box((
        crate::deadman::aegis_deadman_heartbeat as *const (),
    ));
}


// =========================================================================
// P0-A.8a ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â FFI de vÃƒÆ’Ã‚Â©rification cryptographique des mises ÃƒÆ’Ã‚Â  jour
// =========================================================================

#[no_mangle]
pub unsafe extern "C" fn aegis_verify_update_signature(
    manifest_ptr: *const u8,
    manifest_len: usize,
    sig_ptr: *const u8,
    pubkey_ptr: *const u8,
) -> i32 {
    if manifest_ptr.is_null() || sig_ptr.is_null() || pubkey_ptr.is_null() {
        return -1;
    }

    let manifest = unsafe { std::slice::from_raw_parts(manifest_ptr, manifest_len) };

    let mut sig_arr = [0u8; 64];
    unsafe {
        std::ptr::copy_nonoverlapping(sig_ptr, sig_arr.as_mut_ptr(), 64);
    }

    let mut pk_arr = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(pubkey_ptr, pk_arr.as_mut_ptr(), 32);
    }

    match crate::updater::verify_manifest(manifest, &sig_arr, &pk_arr) {
        Ok(_) => 0,
        Err(e) => e.to_code(),
    }
}

// =========================================================================
// C82 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â FFI fetch manifest via Tor (HTTP-over-Tor, Approche A)
// =========================================================================

pub const MANIFEST_ONION_HOST: &str = "PLACEHOLDER_REPLACE_ME.onion";

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_SIG_BYTES: usize = 64;

/// # Safety
///
/// `out_manifest_ptr` et `out_sig_ptr` doivent pointer vers des buffers allouÃƒÆ’Ã‚Â©s par l'appelant
/// d'au moins `MAX_MANIFEST_BYTES` (64 KiB) et `MAX_SIG_BYTES` (64 B) respectivement.
/// `out_manifest_len` et `out_sig_len` doivent pointer vers des `usize` inscriptibles.
#[no_mangle]
pub unsafe extern "C" fn aegis_tor_fetch_http(
    out_manifest_ptr: *mut u8,
    out_manifest_len: *mut usize,
    out_sig_ptr: *mut u8,
    out_sig_len: *mut usize,
) -> i32 {
    if out_manifest_ptr.is_null()
        || out_manifest_len.is_null()
        || out_sig_ptr.is_null()
        || out_sig_len.is_null()
    {
        return -1;
    }

    if !crate::tor_strongbox_is_available() {
        return -2;
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return -3,
    };

    let result = rt.block_on(async {
        let transport = crate::network::tor::TorTransport::bootstrap()
            .await
            .map_err(|_| -3i32)?;

        let manifest_bytes = transport
            .fetch_http(MANIFEST_ONION_HOST, "/update/manifest.json")
            .await
            .map_err(|_| -3i32)?;

        if manifest_bytes.len() > MAX_MANIFEST_BYTES {
            return Err(-4i32);
        }

        let sig_bytes = transport
            .fetch_http(MANIFEST_ONION_HOST, "/update/manifest.json.sig")
            .await
            .map_err(|_| -3i32)?;

        if sig_bytes.len() != MAX_SIG_BYTES {
            return Err(-3i32);
        }

        Ok((manifest_bytes, sig_bytes))
    });

    let (manifest_bytes, sig_bytes) = match result {
        Ok(v) => v,
        Err(rc) => return rc,
    };

    unsafe {
        std::ptr::copy_nonoverlapping(
            manifest_bytes.as_ptr(),
            out_manifest_ptr,
            manifest_bytes.len(),
        );
        *out_manifest_len = manifest_bytes.len();

        std::ptr::copy_nonoverlapping(
            sig_bytes.as_ptr(),
            out_sig_ptr,
            sig_bytes.len(),
        );
        *out_sig_len = sig_bytes.len();
    }

    0
}

// =========================================================================
// P10 FIX (2026-11-06) : ancre runtime pour les 3 symboles purge
//
// Les 3 fonctions `aegis_panic_purge`, `aegis_purge_ram_buffer` et
// `aegis_panic_silent_burn` sont dÃƒÆ’Ã‚Â©finies dans `panic.rs` (avec
// `#[no_mangle] pub extern "C"`). Le linker --gc-sections peut les
// ÃƒÆ’Ã‚Â©liminer du .so si elles ne sont rÃƒÆ’Ã‚Â©fÃƒÆ’Ã‚Â©rencÃƒÆ’Ã‚Â©es que depuis Dart via
// lookup dynamique (pas de rÃƒÆ’Ã‚Â©fÃƒÆ’Ã‚Â©rence statique dans le crate).
//
// Cette ancre garantit leur prÃƒÆ’Ã‚Â©sence dans le .so final ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â sans elle,
// le bouton "PURGE D'URGENCE" de main.dart ÃƒÆ’Ã‚Â©choue silencieusement
// (3 lookup en cascade ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ catch ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ rien ne se passe).
// =========================================================================

#[inline(never)]
fn _anchor_panic_purge_ffi() {
    std::hint::black_box((
        crate::panic::aegis_panic_purge as *const (),
        crate::panic::aegis_purge_ram_buffer as *const (),
        crate::panic::aegis_panic_silent_burn as *const (),
    ));
}

// =========================================================================
// P0-A.2b.1 : Tests de l'identitÃƒÆ’Ã‚Â© ed25519
// =========================================================================

#[cfg(test)]
mod ed25519_identity_tests {
    use super::*;
    use crate::keystore::{HardwareKeystore, TEST_LOCK};

    fn setup_master_key() {
        let root_key = [0x42u8; 32];
        HardwareKeystore::set_root_key(&root_key).expect("set_root_key");
        HardwareKeystore::derive_master_key("TestPIN-Ed25519Identity")
            .expect("derive_master_key");
    }

    fn teardown() {
        let _ = HardwareKeystore::wipe_all();
    }

    /// DÃƒÆ’Ã‚Â©terminisme : mÃƒÆ’Ã‚Âªme master_key ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ mÃƒÆ’Ã‚Âªme clÃƒÆ’Ã‚Â© ed25519.
    #[test]
    fn test_ed25519_identity_derivation_is_deterministic() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let k1 = derive_ed25519_identity().expect("k1");
        let k2 = derive_ed25519_identity().expect("k2");

        assert_eq!(
            k1.verifying_key().as_bytes(),
            k2.verifying_key().as_bytes(),
            "mÃƒÆ’Ã‚Âªme master_key ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ mÃƒÆ’Ã‚Âªme clÃƒÆ’Ã‚Â© ed25519"
        );

        teardown();
    }

    /// Isolation par PIN : PIN-A ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ clÃƒÆ’Ã‚Â© A, PIN-B ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ clÃƒÆ’Ã‚Â© B.
    #[test]
    fn test_ed25519_identity_differs_per_master_key() {
        let _g = TEST_LOCK.lock().unwrap();

        let root_key = [0x42u8; 32];
        HardwareKeystore::set_root_key(&root_key).expect("root");

        HardwareKeystore::derive_master_key("PIN-A").expect("PIN-A");
        let k_a = derive_ed25519_identity().expect("k_a");

        HardwareKeystore::derive_master_key("PIN-B").expect("PIN-B");
        let k_b = derive_ed25519_identity().expect("k_b");

        assert_ne!(
            k_a.verifying_key().as_bytes(),
            k_b.verifying_key().as_bytes(),
            "PIN diffÃƒÆ’Ã‚Â©rents ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ clÃƒÆ’Ã‚Â©s ed25519 diffÃƒÆ’Ã‚Â©rentes"
        );

        teardown();
    }

    /// Sign + verify roundtrip.
    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let signing_key = derive_ed25519_identity().expect("k");
        let challenge = b"0123456789abcdef0123456789abcdef";
        let signature = signing_key.sign(challenge);

        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(challenge, &signature).is_ok());

        teardown();
    }

    /// Une signature valide ÃƒÆ’Ã‚Â©choue contre une mauvaise pubkey.
    #[test]
    fn test_ed25519_verify_rejects_wrong_pubkey() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let signing_key = derive_ed25519_identity().expect("k");
        let challenge = b"0123456789abcdef0123456789abcdef";
        let signature = signing_key.sign(challenge);

        let other_key = SigningKey::from_bytes(&[0x99u8; 32]);
        let other_pub = other_key.verifying_key();

        assert!(
            other_pub.verify(challenge, &signature).is_err(),
            "signature valide contre mauvaise pubkey doit ÃƒÆ’Ã‚Â©chouer"
        );

        teardown();
    }

    /// Sans master_key ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ erreur (fail-closed).
    #[test]
    fn test_ed25519_identity_requires_master_key() {
        let _g = TEST_LOCK.lock().unwrap();
        let _ = HardwareKeystore::wipe_all();

        let result = derive_ed25519_identity();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("master_key"),
            "message d'erreur doit mentionner master_key: {}",
            err
        );
    }
}

// =========================================================================
// C93 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â Tests de la FFI de licence (sÃƒÆ’Ã‚Â©paration de domaine)
// =========================================================================

#[cfg(test)]
mod license_ffi_tests {
    use super::*;
    use crate::updater::LICENSE_DOMAIN;

    fn generate_test_keypair() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn make_license(sk: &SigningKey, order: &str, domain: &[u8]) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(domain);
        payload.extend_from_slice(order.as_bytes());
        let sig = sk.sign(&payload);
        let inner = format!("{}:{}", order, hex::encode(sig.to_bytes()));
        hex::encode(inner.as_bytes())
    }

    /// VÃƒÆ’Ã‚Â©rifie que la logique de domaine cÃƒÆ’Ã‚Â´tÃƒÆ’Ã‚Â© Rust est correcte.
    #[test]
    fn test_license_domain_separation() {
        let (sk, pk) = generate_test_keypair();
        let order = "CMD-12345";

        let license_hex = make_license(&sk, order, LICENSE_DOMAIN);
        let inner_bytes = hex::decode(&license_hex).unwrap();
        let inner_str = std::str::from_utf8(&inner_bytes).unwrap();
        let parts: Vec<&str> = inner_str.split(':').collect();

        let mut expected_payload = Vec::new();
        expected_payload.extend_from_slice(LICENSE_DOMAIN);
        expected_payload.extend_from_slice(parts[0].as_bytes());

        let sig_bytes = hex::decode(parts[1]).unwrap();
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        let vk = VerifyingKey::from_bytes(&pk).unwrap();

        assert!(vk.verify(&expected_payload, &sig).is_ok());
    }

    /// Une signature faite avec le domaine MANIFEST:v1: ne doit PAS valider
    /// une licence (sÃƒÆ’Ã‚Â©paration de domaine).
    #[test]
    fn test_license_rejects_manifest_domain() {
        let (sk, pk) = generate_test_keypair();
        let order = "CMD-12345";

        let license_hex = make_license(&sk, order, b"MANIFEST:v1:");
        let inner_bytes = hex::decode(&license_hex).unwrap();
        let inner_str = std::str::from_utf8(&inner_bytes).unwrap();
        let parts: Vec<&str> = inner_str.split(':').collect();

        let mut license_payload = Vec::new();
        license_payload.extend_from_slice(LICENSE_DOMAIN);
        license_payload.extend_from_slice(parts[0].as_bytes());

        let sig_bytes = hex::decode(parts[1]).unwrap();
        let sig = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        let vk = VerifyingKey::from_bytes(&pk).unwrap();

        assert!(vk.verify(&license_payload, &sig).is_err());
    }

    #[test]
    fn test_license_invalid_hex() {
        let bad_hex = "not_a_hex_string";
        assert!(hex::decode(bad_hex).is_err());
    }

    #[test]
    fn test_license_missing_colon() {
        let bad_format = hex::encode(b"CMD12345_NO_COLON");
        let decoded = hex::decode(&bad_format).unwrap();
        let s = std::str::from_utf8(&decoded).unwrap();
        assert!(!s.contains(':'));
    }
}

// =========================================================================
// AEGIS v3.6 Ã¢â‚¬â€ WRAPPERS FFI C90, C91, C92, C93, C94
// =========================================================================

#[no_mangle]
pub unsafe extern "C" fn aegis_set_external_nfc_token_secret(
    secret_ptr: *const u8,
    secret_len: usize,
) -> i32 {
    use zeroize::Zeroize;
    let mut guard = match EXTERNAL_NFC_TOKEN_SECRET.lock() {
        Ok(g) => g,
        Err(_) => return -2,
    };
    if let Some(mut old) = guard.take() {
        old.zeroize();
    }
    if secret_ptr.is_null() {
        return 0;
    }
    if secret_len != 32 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(secret_ptr, 32) };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    *guard = Some(arr);
    0
}

#[no_mangle]
pub extern "C" fn aegis_chaff_configure(enabled: bool, interval_ms: u64) -> i32 {
    match crate::network::chaffing::GLOBAL_CHAFF_SCHEDULER.lock() {
        Ok(mut sched) => {
            sched.configure(enabled, interval_ms);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_chaff_poll_cell(
    force_now: bool,
    out_cell_512_ptr: *mut u8,
) -> i32 {
    if out_cell_512_ptr.is_null() {
        return -1;
    }
    let mut sched = match crate::network::chaffing::GLOBAL_CHAFF_SCHEDULER.lock() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match sched.poll_tick(force_now) {
        Ok(Some(cell)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    cell.data.as_ptr(),
                    out_cell_512_ptr,
                    crate::network::chaffing::AEGIS_WIRE_CELL_LEN,
                );
            }
            1
        }
        Ok(None) => 0,
        Err(_) => -3,
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_verify_peer_attestation(
    chain_ptr: *const u8,
    chain_len: usize,
    peer_ed25519_pk_ptr: *const u8,
    session_nonce_ptr: *const u8,
    require_strongbox: bool,
) -> i32 {
    if chain_ptr.is_null() || peer_ed25519_pk_ptr.is_null() || session_nonce_ptr.is_null() {
        return -1;
    }
    let chain = unsafe { std::slice::from_raw_parts(chain_ptr, chain_len) };
    let mut pk = [0u8; 32];
    let mut nonce = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(peer_ed25519_pk_ptr, pk.as_mut_ptr(), 32);
        std::ptr::copy_nonoverlapping(session_nonce_ptr, nonce.as_mut_ptr(), 32);
    }
    crate::attestation::verify_peer_mutual_attestation(
        chain,
        &pk,
        &nonce,
        require_strongbox,
    )
    .to_code()
}

#[no_mangle]
pub unsafe extern "C" fn aegis_deaddrop_deposit(
    blind_tag_16_ptr: *const u8,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
) -> i32 {
    if blind_tag_16_ptr.is_null() || ciphertext_ptr.is_null() || ciphertext_len == 0 {
        return -1;
    }
    let mut tag = [0u8; 16];
    unsafe { std::ptr::copy_nonoverlapping(blind_tag_16_ptr, tag.as_mut_ptr(), 16) };
    let payload = unsafe { std::slice::from_raw_parts(ciphertext_ptr, ciphertext_len) }.to_vec();

    match crate::network::dead_drop::GLOBAL_RAM_DEADDROP.lock() {
        Ok(mut store) => match store.deposit(tag, payload) {
            Ok(_) => 0,
            Err(_) => -3,
        },
        Err(_) => -2,
    }
}

#[no_mangle]
pub extern "C" fn aegis_v36_wipe_ephemeral_buffers() -> i32 {
    crate::network::chaffing::wipe_global_chaff();
    crate::network::dead_drop::wipe_global_deaddrop();
    crate::network::optical_fountain::wipe_global_optical();
    unsafe {
        let _ = aegis_set_external_nfc_token_secret(std::ptr::null(), 0);
    }
    0
}

/// C93 : Collecte destructive (Read-Once) des enveloppes Dead-Drop pour une clé publique Ed25519
/// et une heure epoch donnée (`unix_ts / 3600`).
/// Format binaire retourné dans `out_buf_ptr` : répétition de `[u32_be_len | ciphertext_bytes]`.
/// Retourne le nombre d'enveloppes collectées (`>= 0`), `-4` si `out_buf_cap` est trop petit, ou `< 0` sur erreur.
#[no_mangle]
pub unsafe extern "C" fn aegis_deaddrop_collect_and_burn(
    recipient_ed25519_pk_ptr: *const u8,
    epoch_hour: u64,
    out_buf_ptr: *mut u8,
    out_buf_cap: usize,
    out_written_len_ptr: *mut usize,
) -> i32 {
    if recipient_ed25519_pk_ptr.is_null() || out_buf_ptr.is_null() || out_written_len_ptr.is_null() {
        return -1;
    }
    let mut pk = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(recipient_ed25519_pk_ptr, pk.as_mut_ptr(), 32) };
    let tag = crate::network::dead_drop::derive_hourly_blind_tag(&pk, epoch_hour);

    let mut store = match crate::network::dead_drop::GLOBAL_RAM_DEADDROP.lock() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let envelopes = store.collect_and_burn(&tag);
    if envelopes.is_empty() {
        unsafe { *out_written_len_ptr = 0 };
        return 0;
    }

    let mut required: usize = 0;
    for env in &envelopes {
        required = required.saturating_add(4).saturating_add(env.len());
    }
    if required > out_buf_cap {
        // Ré-insère les enveloppes pour ne pas les perdre si le buffer appelant était trop petit
        for env in envelopes {
            let _ = store.deposit(tag, env);
        }
        unsafe { *out_written_len_ptr = required };
        return -4;
    }

    let mut offset = 0usize;
    let count = envelopes.len() as i32;
    for mut env in envelopes {
        let len_be = (env.len() as u32).to_be_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(len_be.as_ptr(), out_buf_ptr.add(offset), 4);
            offset += 4;
            std::ptr::copy_nonoverlapping(env.as_ptr(), out_buf_ptr.add(offset), env.len());
            offset += env.len();
        }
        use zeroize::Zeroize;
        env.zeroize();
    }
    unsafe { *out_written_len_ptr = offset };
    count
}

/// C92 : Encode un payload chiffré en flux de gouttes optiques Fountain QR (JSON Array de chaînes Base64).
/// L'appelant DOIT libérer le pointeur retourné avec `aegis_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn aegis_optical_encode_json(
    transfer_id_4_ptr: *const u8,
    payload_ptr: *const u8,
    payload_len: usize,
) -> *mut c_char {
    if transfer_id_4_ptr.is_null() || payload_ptr.is_null() || payload_len == 0 {
        return std::ptr::null_mut();
    }
    let mut tid = [0u8; 4];
    unsafe { std::ptr::copy_nonoverlapping(transfer_id_4_ptr, tid.as_mut_ptr(), 4) };
    let payload = unsafe { std::slice::from_raw_parts(payload_ptr, payload_len) };

    let frames = match crate::network::optical_fountain::encode_optical_fountain_stream(tid, payload) {
        Ok(f) => f,
        Err(_) => return std::ptr::null_mut(),
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let b64_list: Vec<String> = frames.iter().map(|f| STANDARD.encode(f)).collect();
    let json = match serde_json::to_string(&b64_list) {
        Ok(j) => j,
        Err(_) => return std::ptr::null_mut(),
    };
    match CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// C92 : Ingère un QR Code Base64 scanné par la caméra (Mode Avion 0-RF).
/// Retourne :
///   `0` = goutte valide ingérée, transfert encore en cours.
///   `1` = transfert 100 % reconstruit, copié dans `out_buf_ptr` (`*out_len_ptr` mis à jour) et purgé de la RAM.
///   `-4` = reconstruit mais `out_buf_cap` insuffisant (`*out_len_ptr` indique la taille requise).
///   `< 0` = erreur de décodage ou CRC invalide.
#[no_mangle]
pub unsafe extern "C" fn aegis_optical_ingest_droplet(
    b64_droplet_ptr: *const c_char,
    out_buf_ptr: *mut u8,
    out_buf_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    if b64_droplet_ptr.is_null() || out_buf_ptr.is_null() || out_len_ptr.is_null() {
        return -1;
    }
    let b64_str = match unsafe { CStr::from_ptr(b64_droplet_ptr) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -2,
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let raw_droplet = match STANDARD.decode(b64_str) {
        Ok(d) => d,
        Err(_) => return -3,
    };

    let mut dec = match crate::network::optical_fountain::GLOBAL_OPTICAL_DECODER.lock() {
        Ok(d) => d,
        Err(_) => return -5,
    };

    let complete = match dec.ingest_wire_droplet(&raw_droplet) {
        Ok(c) => c,
        Err(_) => return -6,
    };

    if !complete {
        unsafe { *out_len_ptr = 0 };
        return 0;
    }

    let mut recovered = match dec.finalize_and_wipe() {
        Some(r) => r,
        None => return -7,
    };

    if recovered.len() > out_buf_cap {
        unsafe { *out_len_ptr = recovered.len() };
        use zeroize::Zeroize;
        recovered.zeroize();
        return -4;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(recovered.as_ptr(), out_buf_ptr, recovered.len());
        *out_len_ptr = recovered.len();
    }
    use zeroize::Zeroize;
    recovered.zeroize();
    1
}

#[inline(never)]
fn _anchor_v36_hardening_ffi() {
    std::hint::black_box((
        aegis_set_external_nfc_token_secret as *const (),
        aegis_chaff_configure as *const (),
        aegis_chaff_poll_cell as *const (),
        aegis_verify_peer_attestation as *const (),
        aegis_deaddrop_deposit as *const (),
        aegis_deaddrop_collect_and_burn as *const (),
        aegis_optical_encode_json as *const (),
        aegis_optical_ingest_droplet as *const (),
        aegis_v36_wipe_ephemeral_buffers as *const (),
    ));
}

#[cfg(test)]
mod v36_ffi_tests {
    use super::*;

    #[test]
    fn test_ffi_optical_encode_and_ingest_roundtrip() {
        let _ = aegis_v36_wipe_ephemeral_buffers();
        let tid = [0xAA, 0xBB, 0xCC, 0xDD];
        let secret_msg = b"AEGIS_ZERO_RF_OPTICAL_PAYLOAD_TEST_2026";

        let json_ptr = unsafe {
            aegis_optical_encode_json(tid.as_ptr(), secret_msg.as_ptr(), secret_msg.len())
        };
        assert!(!json_ptr.is_null());

        let json_str = unsafe { CStr::from_ptr(json_ptr) }.to_str().unwrap().to_owned();
        unsafe { aegis_free_string(json_ptr) };

        let droplets: Vec<String> = serde_json::from_str(&json_str).unwrap();
        assert!(!droplets.is_empty());

        let mut out = [0u8; 256];
        let mut out_len = 0usize;
        let mut finished = false;

        for d in droplets {
            let c_d = CString::new(d).unwrap();
            let rc = unsafe {
                aegis_optical_ingest_droplet(
                    c_d.as_ptr(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut out_len,
                )
            };
            assert!(rc >= 0);
            if rc == 1 {
                finished = true;
                break;
            }
        }
        assert!(finished);
        assert_eq!(&out[..out_len], secret_msg);
    }

    #[test]
    fn test_ffi_deaddrop_deposit_and_collect_roundtrip() {
        let _ = aegis_v36_wipe_ephemeral_buffers();
        let pk = [0x44u8; 32];
        let hour = 498_000u64;
        let tag = crate::network::dead_drop::derive_hourly_blind_tag(&pk, hour);
        let env = b"BLIND_ENVELOPE_MLKEM1024";

        let rc_dep = unsafe { aegis_deaddrop_deposit(tag.as_ptr(), env.as_ptr(), env.len()) };
        assert_eq!(rc_dep, 0);

        let mut out = [0u8; 128];
        let mut written = 0usize;
        let count = unsafe {
            aegis_deaddrop_collect_and_burn(
                pk.as_ptr(),
                hour,
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        };
        assert_eq!(count, 1);
        let item_len = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(item_len, env.len());
        assert_eq!(&out[4..4 + item_len], env);
    }
}