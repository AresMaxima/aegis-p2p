// src/network/ble_mesh.rs
//
// P0-A.3c.1 (2026-10-12) — BLE Mesh : FFI Rust + validation fd.
//
// Ce module expose deux points d'entrée FFI :
//   - aegis_ble_mesh_set_pipes(in_fd, out_fd) : enregistre les fd POSIX
//     créés côté Kotlin via ParcelFileDescriptor.createPipe()
//   - aegis_ble_mesh_shutdown() : libère les fd et arrête les threads
//
// Les threads reader/writer seront ajoutés en P0-A.3c.2.
//
// Contraintes :
//   - C56 : from_raw_fd(-1) panique → on refuse fd <= 0 AVANT tout
//     appel à from_raw_fd
//   - Les fd sont POSIX-only → pas de cfg(unix) nécessaire tant qu'on
//     ne les utilise pas (c'est le cas ici : on ne fait que les stocker).

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

// ─────────────────────────────────────────────────────────────────────
// Erreurs typées
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleMeshError {
    /// fd <= 0 (voir C56 — from_raw_fd(-1) panique).
    InvalidFd,
    /// set_pipes() appelé alors qu'une session est déjà active.
    AlreadyActive,
    /// shutdown() sans session active (idempotent — n'est pas une erreur
    /// pour l'appelant, mais on l'expose pour la distinction).
    NotActive,
}

impl BleMeshError {
    pub fn to_code(self) -> i32 {
        match self {
            BleMeshError::InvalidFd => -1,
            BleMeshError::AlreadyActive => -2,
            BleMeshError::NotActive => -3,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// État global
// ─────────────────────────────────────────────────────────────────────

static IN_FD: AtomicI32 = AtomicI32::new(-1);
static OUT_FD: AtomicI32 = AtomicI32::new(-1);
static ACTIVE: AtomicBool = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────
// API publique
// ─────────────────────────────────────────────────────────────────────

/// Enregistre les deux fd POSIX du pipe bidirectionnel BLE.
///
/// `in_fd`  : fd de lecture  — Rust lit les fragments venant de Kotlin (GATT WRITE)
/// `out_fd` : fd d'écriture — Rust écrit les fragments à envoyer via GATT NOTIFY
///
/// Retourne `Err(InvalidFd)` si l'un des fd est <= 0 (C56).
/// Retourne `Err(AlreadyActive)` si une session est déjà en cours.
pub fn set_pipes(in_fd: i32, out_fd: i32) -> Result<(), BleMeshError> {
    // C56 : refuser AVANT tout from_raw_fd.
    if in_fd <= 0 || out_fd <= 0 {
        return Err(BleMeshError::InvalidFd);
    }

    // Refus si déjà actif (set_pipes est appelé une seule fois par session).
    if ACTIVE.load(Ordering::Acquire) {
        return Err(BleMeshError::AlreadyActive);
    }

    IN_FD.store(in_fd, Ordering::Release);
    OUT_FD.store(out_fd, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);

    Ok(())
}

/// Arrête la session BLE mesh.
///
/// Idempotent : appeler shutdown() sans session active retourne Ok(()).
/// Les threads reader/writer seront join en P0-A.3c.2.
pub fn shutdown() -> Result<(), BleMeshError> {
    if !ACTIVE.swap(false, Ordering::AcqRel) {
        // Déjà inactif → idempotent, pas une erreur pour l'appelant.
        return Ok(());
    }

    IN_FD.store(-1, Ordering::Release);
    OUT_FD.store(-1, Ordering::Release);

    // TODO P0-A.3c.2 : join threads, close fd proprement.

    Ok(())
}

/// Retourne les fd courants (usage interne + tests).
pub fn current_pipes() -> Option<(i32, i32)> {
    if !ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let in_fd = IN_FD.load(Ordering::Acquire);
    let out_fd = OUT_FD.load(Ordering::Acquire);
    if in_fd <= 0 || out_fd <= 0 {
        return None;
    }
    Some((in_fd, out_fd))
}

// ─────────────────────────────────────────────────────────────────────
// FFI exporté
// ─────────────────────────────────────────────────────────────────────

/// # Safety
///
/// Appelé depuis JNI (Kotlin BleMeshBridge).
/// `in_fd` et `out_fd` doivent être des fd POSIX valides (> 0).
/// Voir C56 : from_raw_fd(-1) panique → on refuse AVANT.
#[no_mangle]
pub extern "C" fn aegis_ble_mesh_set_pipes(in_fd: i32, out_fd: i32) -> i32 {
    match set_pipes(in_fd, out_fd) {
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_shutdown() -> i32 {
    match shutdown() {
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// C64 FIX (2026-10-13) — Wrappers JNI pour MainActivity.kt
//
// Les fonctions ci-dessus sont appelées via Dart FFI (plain name).
// MainActivity.kt les appelle via `external fun` → JNI attend des
// symboles préfixés Java_..._MainActivity_...
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1mesh_1set_1pipes(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
    in_fd: jni::sys::jint,
    out_fd: jni::sys::jint,
) -> jni::sys::jint {
    aegis_ble_mesh_set_pipes(in_fd as i32, out_fd as i32) as jni::sys::jint
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1mesh_1shutdown(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
) -> jni::sys::jint {
    aegis_ble_mesh_shutdown() as jni::sys::jint
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Sérialiser les tests qui touchent l'état global ACTIVE.
    // TEST_LOCK : pattern existant du projet (keystore, session, tor_isolation).
    use std::sync::Mutex;
    static BLE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_state() {
        ACTIVE.store(false, Ordering::Release);
        IN_FD.store(-1, Ordering::Release);
        OUT_FD.store(-1, Ordering::Release);
    }

    #[test]
    fn test_set_pipes_rejects_negative_in_fd() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(set_pipes(-1, 100), Err(BleMeshError::InvalidFd));
        reset_state();
    }

    #[test]
    fn test_set_pipes_rejects_negative_out_fd() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(set_pipes(100, -1), Err(BleMeshError::InvalidFd));
        reset_state();
    }

    #[test]
    fn test_set_pipes_rejects_zero_fd() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(set_pipes(0, 100), Err(BleMeshError::InvalidFd));
        assert_eq!(set_pipes(100, 0), Err(BleMeshError::InvalidFd));
        reset_state();
    }

    #[test]
    fn test_set_pipes_valid_returns_ok() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(set_pipes(10, 20), Ok(()));
        assert_eq!(current_pipes(), Some((10, 20)));
        reset_state();
    }

    #[test]
    fn test_set_pipes_twice_returns_already_active() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(set_pipes(10, 20), Ok(()));
        assert_eq!(set_pipes(30, 40), Err(BleMeshError::AlreadyActive));
        // L'état initial reste inchangé.
        assert_eq!(current_pipes(), Some((10, 20)));
        reset_state();
    }

    #[test]
    fn test_shutdown_before_set_is_idempotent() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(shutdown(), Ok(()));
        assert_eq!(shutdown(), Ok(()));
        reset_state();
    }

    #[test]
    fn test_shutdown_after_set_returns_ok() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(set_pipes(10, 20), Ok(()));
        assert_eq!(shutdown(), Ok(()));
        assert_eq!(current_pipes(), None);
        reset_state();
    }

    #[test]
    fn test_shutdown_allows_new_session() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(set_pipes(10, 20), Ok(()));
        assert_eq!(shutdown(), Ok(()));
        // Nouvelle session possible après shutdown.
        assert_eq!(set_pipes(30, 40), Ok(()));
        assert_eq!(current_pipes(), Some((30, 40)));
        reset_state();
    }

    #[test]
    fn test_ffi_set_pipes_success() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(aegis_ble_mesh_set_pipes(10, 20), 0);
        reset_state();
    }

    #[test]
    fn test_ffi_set_pipes_invalid_fd_returns_neg() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(aegis_ble_mesh_set_pipes(-1, 20), -1);
        assert_eq!(aegis_ble_mesh_set_pipes(10, -1), -1);
        assert_eq!(aegis_ble_mesh_set_pipes(0, 0), -1);
        reset_state();
    }

    #[test]
    fn test_ffi_set_pipes_already_active_returns_neg2() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(aegis_ble_mesh_set_pipes(10, 20), 0);
        assert_eq!(aegis_ble_mesh_set_pipes(30, 40), -2);
        reset_state();
    }

    #[test]
    fn test_ffi_shutdown_idempotent() {
        let _g = BLE_TEST_LOCK.lock().unwrap();
        reset_state();
        assert_eq!(aegis_ble_mesh_shutdown(), 0);
        assert_eq!(aegis_ble_mesh_shutdown(), 0);
        reset_state();
    }
}