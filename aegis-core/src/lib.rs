//! aegis-core/src/lib.rs
//! Point d'Entrée FFI/JNI et Enregistrement des Modules Natifs (CdCM v2.2-RC1).

#![allow(unused_imports, dead_code, unused_variables)]

use std::os::raw::{c_char, c_void};

pub mod crypto;
pub mod crypto_pq;
pub mod deadman;
pub mod ffi_security;
pub mod hardware_triggers;
pub mod ingestion;
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

/// # Safety
///
/// Point d'entrée JNI d'initialisation du moteur exécuté au chargement de la bibliothèque dynamique.
/// Initialise le hardening NDK, le registre de purge RAM et vérifie la validité de la JVM.
#[no_mangle]
pub unsafe extern "C" fn JNI_OnLoad(vm: *mut c_void, _reserved: *mut c_void) -> jni::sys::jint {
    // 1. Hardening NDK (prctl, sigaction, stdio redirection)
    ffi_security::init_native_security();

    // 2. Enregistrement du registre de purge RAM lock-free
    secure_buffer::init_secure_buffer_system();

    if vm.is_null() {
        return jni::sys::JNI_ERR;
    }

    jni::sys::JNI_VERSION_1_6
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