//! aegis-core/src/lib.rs
//! Point d'Entrée FFI/JNI et Enregistrement des Modules Natifs (CdCM v2.2-RC3).

#![allow(unused_imports, dead_code, unused_variables)]

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
//
// Flag global : StrongBox est-il disponible pour Tor ?
//
// Mis à jour depuis Flutter/Dart au démarrage via FFI
// `aegis_tor_set_strongbox_available(available: bool)`.
//
// Valeur par défaut : `false` (fail-closed D42-bis).
// Si l'app ne met jamais à jour ce flag (erreur, crash),
// Tor reste désactivé — c'est le comportement voulu.
static TOR_STRONGBOX_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Helper public pour les modules internes (notamment `network::tor`).
///
/// Lit le flag `TOR_STRONGBOX_AVAILABLE` (mis à jour depuis Dart
/// via la FFI `aegis_tor_set_strongbox_available`).
///
/// Le static reste privé — cette fonction est la seule voie d'accès.
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

    // F6-C (01/10/26) : ancre runtime qui force le linker à garder les 5
    // symboles FFI aegis_vault_* (appelés uniquement depuis Dart, donc
    // invisibles pour le linker). JNI_OnLoad est TOUJOURS appelée par la
    // JVM Android → l'ancre survit.
    _anchor_vault_ffi();

    // P0-A.2b.3a : ancre pour les FFI Wi-Fi Direct (appelées via JNI
    // depuis Kotlin, invisibles pour le linker LLD).
    _anchor_wifi_direct_ffi();

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

// =========================================================================
// P0-A.1e : FFI StrongBox gate pour Tor (D42-bis + D62)
// =========================================================================

/// FFI appelée depuis Dart au démarrage.
///
/// `available = true`  → StrongBox opérationnel, Tor autorisé
/// `available = false` → StrongBox absent/cassé, Tor refusé (fail-closed)
///
/// La vérification réelle (active + cache 30 jours, D64) est faite
/// côté Kotlin (`HardwareKeystore.isStrongBoxOperational()`).
/// Rust ne fait que stocker le résultat.
#[no_mangle]
pub extern "C" fn aegis_tor_set_strongbox_available(available: bool) {
    TOR_STRONGBOX_AVAILABLE.store(available, Ordering::SeqCst);
}

/// FFI de lecture (tests Rust + debug).
///
/// Retourne 1 si StrongBox est marqué disponible, 0 sinon.
#[no_mangle]
pub extern "C" fn aegis_tor_strongbox_available() -> i32 {
    if TOR_STRONGBOX_AVAILABLE.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}

// =========================================================================
// P0-A.2b.1 (2026-10-09) : Identité ed25519 P2P (dérivée de master_key)
// =========================================================================
//
// L'utilisateur n'a pas de paire ed25519 persistée. Elle est dérivée
// à la volée depuis la master_key via HKDF-SHA256 :
//
//   ed25519_seed = HKDF-SHA256(
//       ikm  = master_key,
//       salt = "AEGIS-ED25519-IDENTITY",
//       info = "v1"
//   )
//
// Propriétés :
//   • Déterministe — même master_key → même identité ed25519
//   • Non-déductible sans master_key (HKDF-SHA256)
//   • Change si le PIN change (mode decoy = identité distincte)
//   • Aucun stockage supplémentaire (zéro-persistence respecté)
//   • Pas de backup (perte device = perte identité, comme le vault)
//
// Usage (P0-A.2b) :
//   • QR code contient deviceName + fingerprint ed25519
//   • Handshake ed25519 post-connexion Wi-Fi Direct
//   • Vérification cryptographique du peer (anti-MITM premier contact)

/// Dérive la clé ed25519 d'identité P2P depuis la master_key courante.
///
/// Retourne `Err(String)` si la master_key n'est pas disponible
/// (vault non déverrouillé).
fn derive_ed25519_identity() -> Result<SigningKey, String> {
    // 1. Récupérer la master_key
    let master_key = crate::keystore::HardwareKeystore::get_master_key()
        .map_err(|e| format!("master_key indisponible: {}", e))?;

    // 2. HKDF-SHA256 : 32 octets de sortie (seed ed25519)
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(b"AEGIS-ED25519-IDENTITY"),
        master_key.as_slice(),
    );

    let mut seed = [0u8; 32];
    hk.expand(b"v1", &mut seed)
        .map_err(|e| format!("HKDF expand: {}", e))?;

    // 3. Créer la SigningKey ed25519
    let signing_key = SigningKey::from_bytes(&seed);

    // 4. Zéroisation du seed intermédiaire
    use zeroize::Zeroize;
    seed.zeroize();

    Ok(signing_key)
}

/// Signe un challenge de 32 octets avec l'identité ed25519 du device.
///
/// # Arguments
/// - `challenge_ptr` : pointeur vers 32 octets (nonce)
/// - `challenge_len` : doit être exactement 32
/// - `sig_out_ptr`   : pointeur vers un buffer de 64 octets (sortie)
///
/// # Retour
/// -  0 : signature écrite dans `sig_out_ptr`
/// - -1 : pointeur null
/// - -2 : `challenge_len != 32`
/// - -3 : master_key indisponible (vault verrouillé)
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

/// Vérifie une signature ed25519.
///
/// # Arguments
/// - `challenge_ptr` : pointeur vers le message
/// - `challenge_len` : longueur du message
/// - `pubkey_ptr`    : pointeur vers 32 octets (clé publique ed25519)
/// - `sig_ptr`       : pointeur vers 64 octets (signature)
///
/// # Retour
/// -  1 : signature valide
/// -  0 : signature invalide
/// - -1 : pointeur null
/// - -2 : format invalide (pubkey ou signature non-parsable)
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

/// Retourne la clé publique ed25519 du device (32 octets).
///
/// # Arguments
/// - `pubkey_out_ptr` : pointeur vers un buffer de 32 octets (sortie)
///
/// # Retour
/// -  0 : clé publique écrite
/// - -1 : pointeur null
/// - -3 : master_key indisponible
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

/// Retourne la fingerprint SHA-256 de la clé publique ed25519 du device.
///
/// Utilisé par Dart pour construire le QR code (P0-A.2b.4).
///
/// # Arguments
/// - `out_ptr` : pointeur vers un buffer de 32 octets (sortie)
///
/// # Retour
/// -  0 : fingerprint écrite
/// - -1 : pointeur null
/// - -3 : master_key indisponible
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
// P0-A.2b.3a (2026-10-10) : Wi-Fi Direct socket fd (Kotlin → Rust)
// =========================================================================
//
// Kotlin ouvre un Socket TCP (ServerSocket accept côté GO, Socket côté
// Client) après connexion Wi-Fi Direct, puis transmet le fd à Rust via
// ces FFI. Le fd est stocké dans un AtomicI32 — il sera consommé par
// WifiDirectTransport (P0-A.2b.3b).
//
// Cycle de vie du fd :
//   1. Kotlin : ParcelFileDescriptor.fromSocket(socket).detachFd() → i32
//   2. Kotlin : aegis_wifi_direct_set_fd(fd) → Rust stocke
//   3. Rust (b.3b) : from_raw_fd(fd) → TcpStream
//   4. Rust (b.3b) : Drop du TcpStream → close(fd) automatique
//   5. Ou : Kotlin appelle aegis_wifi_direct_close_fd() à la déconnexion

static WIFI_DIRECT_FD: AtomicI32 = AtomicI32::new(-1);

/// Stocke le fd du socket Wi-Fi Direct.
///
/// Vérifie que le fd est bien un socket TCP (`SOCK_STREAM`).
///
/// Retour :
///   0  = OK
///  -1  = fd < 0
///  -2  = fd n'est pas un SOCK_STREAM (pas un socket TCP)
///  -3  = fd déjà occupé (appeler close_fd avant)
#[no_mangle]
pub unsafe extern "C" fn aegis_wifi_direct_set_fd(fd: i32) -> i32 {
    if fd < 0 {
        return -1;
    }

    // Défensif : vérifier que le fd est bien un socket TCP.
    //
    // NOTE (C54) : `getsockopt` + `SOL_SOCKET` + `SO_TYPE` + `SOCK_STREAM`
    // sont POSIX-only. Sur Android/Linux (Unix), la vérification s'exécute.
    // Sur Windows (dev/CI), elle est sautée — le fd ne sera jamais fourni
    // par un vrai socket Wi-Fi Direct de toute façon (Android only).
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

    // Refuser si un fd est déjà stocké (pas d'écrasement silencieux)
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

/// Lit le fd stocké (tests + debug).
///
/// Retour : fd (>= 0) ou -1 si aucun.
#[no_mangle]
pub extern "C" fn aegis_wifi_direct_get_fd() -> i32 {
    WIFI_DIRECT_FD.load(Ordering::SeqCst)
}

// =========================================================================
// P0-A.2b.3c (2026-10-11) : Helpers sûrs pour ed25519 (usage interne)
// =========================================================================
//
// Ces wrappers appellent les FFI `aegis_ed25519_*` en isolant le code
// `unsafe`. Utilisés par `network::wifi_direct` (handshake symétrique).

/// Signe un challenge de 32 octets et retourne la signature.
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

/// Vérifie une signature ed25519 contre une pubkey.
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

/// Retourne la fingerprint SHA-256 de la pubkey ed25519 du device.
pub(crate) fn ed25519_fingerprint_safe() -> Result<[u8; 32], String> {
    let mut fp = [0u8; 32];
    let rc = unsafe { aegis_ed25519_fingerprint(fp.as_mut_ptr()) };
    match rc {
        0 => Ok(fp),
        -3 => Err("master_key indisponible".to_string()),
        _ => Err(format!("ed25519_fingerprint rc={}", rc)),
    }
}

/// Helper interne : récupère le fd stocké et le remet à -1 (take ownership).
///
/// Utilisé par `WifiDirectTransport::from_global_fd()` (P0-A.2b.3b).
///
/// **Ne ferme PAS le fd** — le transport prend ownership et le fermera
/// à son Drop (via le Drop de `TcpStream`).
///
/// Retour : fd >= 0 (propriété transférée à l'appelant)
///         ou -1 (aucun fd disponible)
pub(crate) fn take_wifi_direct_fd() -> i32 {
    WIFI_DIRECT_FD.swap(-1, Ordering::SeqCst)
}

/// Ferme le fd courant et remet le slot à -1.
///
/// Appelé par Kotlin à la déconnexion Wi-Fi Direct.
///
/// Retour :
///   0  = OK (fd fermé ou rien à fermer)
#[no_mangle]
pub extern "C" fn aegis_wifi_direct_close_fd() -> i32 {
    let fd = WIFI_DIRECT_FD.swap(-1, Ordering::SeqCst);

    // NOTE (C54) : `libc::close` est POSIX-only.
    #[cfg(unix)]
    if fd >= 0 {
        unsafe { libc::close(fd); }
    }

    // Éviter un warning `unused_variables` sur Windows.
    #[cfg(not(unix))]
    let _ = fd;

    0
}

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

// =========================================================================
// WRAPPERS FFI — Vault Persistence (F6-C)
// =========================================================================
//
// API Dart ↔ Rust (C ABI).
//
//   aegis_vault_set_dir(path)   → 0=OK, -1=null ptr, -2=encoding, -3=io
//   aegis_vault_is_initialized() → 1=initialized, 0=not initialized
//   aegis_vault_init(pin)        → 0=OK, -1=null ptr, -2=encoding, -3=vault err
//   aegis_vault_unlock(pin)      → 0=Real, 1=Decoy, 2=NeedsInit, -1=err
//   aegis_vault_wipe()           → 0=OK, -1=err

/// Définit le répertoire de persistance du vault (vault.json).
///
/// Doit être appelé UNE FOIS au démarrage de l'app, avant toute autre
/// fonction vault. Côté Dart : `getApplicationDocumentsDirectory()`.
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
            eprintln!("AEGIS-VAULT: set_vault_dir a échoué: {}", e);
            -3
        }
    }
}

/// Vrai si un vault.json valide existe dans le répertoire configuré.
///
/// Retourne :
///   1 = vault initialisé (PIN déjà défini)
///   0 = vault non initialisé (ou VAULT_DIR non configuré)
#[no_mangle]
pub unsafe extern "C" fn aegis_vault_is_initialized() -> i32 {
    if crate::vault_persistence::vault_is_initialized() {
        1
    } else {
        0
    }
}

/// Initialise un nouveau vault avec le PIN fourni.
///
/// Prérequis : `aegis_set_hardware_secret` doit avoir été appelé
/// (ROOT_KEY initialisée depuis le StrongBox).
///
/// Retourne :
///   0  = init OK (vault.json écrit, MASTER_KEY en RAM)
///  -1  = pin_ptr null
///  -2  = encodage UTF-8 du PIN invalide
///  -3  = erreur vault (ROOT_KEY absente, IO, PIN vide)
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
            eprintln!("AEGIS-VAULT: vault_init a échoué: {}", e);
            -3
        }
    }
}

/// Tente de déverrouiller le vault avec le PIN fourni.
///
/// Retourne :
///   0  = Real (PIN correct → session réelle)
///   1  = Decoy (PIN incorrect → session leurre)
///   2  = NeedsInitialization (aucun vault.json)
///  -1  = erreur interne (pin null, IO, ROOT_KEY absente)
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
            eprintln!("AEGIS-VAULT: vault_unlock a échoué: {}", e);
            -1
        }
    }
}

/// Supprime vault.json et efface ROOT_KEY + MASTER_KEY de la RAM.
///
/// Retourne :
///   0  = OK
///  -1  = erreur (IO)
#[no_mangle]
pub unsafe extern "C" fn aegis_vault_wipe() -> i32 {
    match crate::vault_persistence::vault_wipe() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("AEGIS-VAULT: vault_wipe a échoué: {}", e);
            -1
        }
    }
}

// =========================================================================
// F6-C (01/10/26) — Ancre runtime pour les 5 symboles FFI aegis_vault_*
// =========================================================================
//
// Contexte :
//   Les fonctions `aegis_vault_*` sont appelées UNIQUEMENT depuis Dart
//   via `DynamicLibrary.lookupFunction` (FFI dynamique). Le linker LLD
//   du NDK n'a donc aucune référence interne vers elles → il les élimine
//   à l'étape `--gc-sections` (comportement par défaut de clang NDK).
//
// Preuve de la chaîne vivante : `aegis_vault_create/destroy` (dans
// session.rs) survivent parce qu'elles sont appelées par
// `aegis_session_vault_create/destroy` (chaîne interne).
//
// Solution :
//   Cette fonction référence explicitement les 5 fonctions via des casts
//   runtime (autorisés, contrairement au const eval) + `black_box` qui
//   empêche l'optimiseur de les éliminer. Appelée depuis `JNI_OnLoad`
//   (garanti exécuté par la JVM Android), elle crée un point vivant
//   vers les 5 symboles → le linker les garde.
//
// NE PAS retirer. Si une nouvelle fonction FFI est ajoutée et appelée
// uniquement depuis Dart, l'ajouter ici.

/// P0-A.2b.3a : ancre runtime pour les FFI Wi-Fi Direct + ed25519 fingerprint.
///
/// Même mécanisme que `_anchor_vault_ffi` : les FFI appelées via JNI
/// (Kotlin `external fun`) sont invisibles au linker LLD du NDK.
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
fn _anchor_vault_ffi() {
    std::hint::black_box((
        aegis_vault_set_dir as *const (),
        aegis_vault_is_initialized as *const (),
        aegis_vault_init as *const (),
        aegis_vault_unlock as *const (),
        aegis_vault_wipe as *const (),
    ));
}

// =========================================================================
// P0-A.2b.1 : Tests de l'identité ed25519
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

    /// Déterminisme : même master_key → même clé ed25519.
    #[test]
    fn test_ed25519_identity_derivation_is_deterministic() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let k1 = derive_ed25519_identity().expect("k1");
        let k2 = derive_ed25519_identity().expect("k2");

        assert_eq!(
            k1.verifying_key().as_bytes(),
            k2.verifying_key().as_bytes(),
            "même master_key → même clé ed25519"
        );

        teardown();
    }

    /// Isolation par PIN : PIN-A → clé A, PIN-B → clé B.
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
            "PIN différents → clés ed25519 différentes"
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

    /// Une signature valide échoue contre une mauvaise pubkey.
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
            "signature valide contre mauvaise pubkey doit échouer"
        );

        teardown();
    }

    /// Sans master_key → erreur (fail-closed).
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