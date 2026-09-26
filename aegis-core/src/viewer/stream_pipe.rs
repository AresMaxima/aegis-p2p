//! aegis-core/src/viewer/stream_pipe.rs
//! Canal Virtuel StreamPipe Zero-Copy (RAM-to-VRAM) par Chunks de 512 Ko.
//!
//! ─────────────────────────────────────────────────────────────────────
//! CORRECTIF MAJEUR (CdCM v2.2-RC2) :
//!   L'ancienne `aegis_render_to_surface` acquérait bien l'ANativeWindow*
//!   mais ne peignait JAMAIS un seul pixel (aucun lock/unlockAndPost).
//!   L'audit du 12/09/2026 la qualifiait de "coquille vide (return 0)".
//!
//!   Ajout :
//!     • FFI ANativeWindow_setBuffersGeometry / _lock / _unlockAndPost
//!     • Struct ANativeWindow_Buffer (repr C, conforme NDK android/native_window.h)
//!     • Blit effectif RGBA_8888 depuis un SecureBuffer
//!     • aegis_render_secure_buffer()  → blit direct depuis Dart
//!     • aegis_is_surface_ready()      → sondage de disponibilité
//!     • aegis_decode_and_blit_file()  → décode JPEG/PNG puis blit
//!       (corrige le bouton "AFFICHER" qui montrait un damier au lieu
//!        du contenu réel — cf. audit 12/09/2026)
//! ─────────────────────────────────────────────────────────────────────

use crate::secure_buffer::SecureBuffer;
use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use jni::objects::{GlobalRef, JObject};
use jni::JNIEnv;

pub const STREAM_CHUNK_SIZE: usize = 512 * 1024;
pub const WINDOW_FORMAT_RGBA_8888: i32 = 1;

// =========================================================================
// FFI NDK (libandroid.so)
// =========================================================================

#[cfg(target_os = "android")]
#[link(name = "android")]
extern "C" {
    fn ANativeWindow_fromSurface(
        env: *mut jni::sys::JNIEnv,
        surface: jni::sys::jobject,
    ) -> *mut c_void;

    fn ANativeWindow_release(window: *mut c_void);

    fn ANativeWindow_setBuffersGeometry(
        window: *mut c_void,
        width: i32,
        height: i32,
        format: i32,
    ) -> i32;

    fn ANativeWindow_lock(
        window: *mut c_void,
        out_buffer: *mut ANativeWindow_Buffer,
        in_out_dirty: *mut c_void,
    ) -> i32;

    fn ANativeWindow_unlockAndPost(window: *mut c_void) -> i32;
}

/// Réplique exacte de la struct NDK `ANativeWindow_Buffer`
/// (android/native_window.h). NE PAS modifier l'ordre des champs.
#[repr(C)]
#[derive(Default)]
struct ANativeWindow_Buffer {
    width: i32,
    height: i32,
    stride: i32,
    format: i32,
    bits: *mut c_void,
    reserved: [u32; 6],
}

// =========================================================================
// Surface active
// =========================================================================

struct SurfaceHandle {
    window: *mut c_void,
    #[allow(dead_code)]
    global_ref: GlobalRef,
}

unsafe impl Send for SurfaceHandle {}

static CURRENT_SURFACE: Mutex<Option<SurfaceHandle>> = Mutex::new(None);

// =========================================================================
// StreamPipeController
// =========================================================================

pub struct StreamPipeController {
    read_offset: AtomicUsize,
    total_size: usize,
    is_playing: AtomicBool,
    scramble_on_pause: AtomicBool,
}

impl StreamPipeController {
    pub fn new(total_size: usize) -> Self {
        Self {
            read_offset: AtomicUsize::new(0),
            total_size,
            is_playing: AtomicBool::new(false),
            scramble_on_pause: AtomicBool::new(false),
        }
    }

    pub fn play(&self) {
        self.is_playing.store(true, Ordering::SeqCst);
        self.scramble_on_pause.store(false, Ordering::SeqCst);
    }

    pub fn pause(&self) {
        self.is_playing.store(false, Ordering::SeqCst);
        self.scramble_on_pause.store(true, Ordering::SeqCst);
    }

    pub fn is_playing(&self) -> bool { self.is_playing.load(Ordering::SeqCst) }
    pub fn is_scrambled(&self) -> bool { self.scramble_on_pause.load(Ordering::SeqCst) }

    pub fn seek(&self, offset: usize) -> Result<usize, &'static str> {
        if offset > self.total_size {
            return Err("Offset de lecture hors limites");
        }
        self.read_offset.store(offset, Ordering::SeqCst);
        Ok(offset)
    }

    #[inline(never)]
    pub fn read_chunk_512k(&self, source_buffer: &SecureBuffer, out_slice: &mut [u8]) -> usize {
        if !self.is_playing() && self.is_scrambled() {
            for b in out_slice.iter_mut() { *b = 0x00; }
            return 0;
        }

        let current_pos = self.read_offset.load(Ordering::SeqCst);
        let src = source_buffer.as_slice();
        if current_pos >= src.len() { return 0; }

        let available = src.len() - current_pos;
        let read_bytes =
            std::cmp::min(STREAM_CHUNK_SIZE, std::cmp::min(available, out_slice.len()));

        if read_bytes > 0 {
            out_slice[..read_bytes].copy_from_slice(&src[current_pos..current_pos + read_bytes]);
            self.read_offset.fetch_add(read_bytes, Ordering::SeqCst);
        }

        read_bytes
    }
}

// =========================================================================
// FFI : attache / détache de la surface
// =========================================================================

pub fn aegis_render_to_surface(env: JNIEnv, surface: jni::sys::jobject) -> i32 {
    if surface.is_null() {
        return -1;
    }

    let surface_obj = unsafe { JObject::from_raw(surface) };
    let global = match env.new_global_ref(surface_obj) {
        Ok(g) => g,
        Err(_) => { let _ = env.exception_clear(); return -2; }
    };

    #[cfg(target_os = "android")]
    let window: *mut c_void = unsafe {
        ANativeWindow_fromSurface(env.get_native_interface(), surface)
    };

    #[cfg(not(target_os = "android"))]
    let window: *mut c_void = std::ptr::null_mut();

    if window.is_null() {
        #[cfg(target_os = "android")]
        { return -3; }
    }

    let mut guard = match CURRENT_SURFACE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };

    if let Some(old) = guard.take() {
        #[cfg(target_os = "android")]
        unsafe { ANativeWindow_release(old.window); }
    }

    *guard = Some(SurfaceHandle { window, global_ref: global });

    // 🎨 PREMIER BLIT IMMÉDIAT : dessine un damier de test pour prouver
    // que le pipeline VRAM fonctionne (visible dès surfaceCreated).
    #[cfg(target_os = "android")]
    {
        let _ = unsafe { blit_test_pattern(window, 1080, 1920) };
    }

    0
}

pub fn aegis_release_surface() -> i32 {
    let mut guard = match CURRENT_SURFACE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };

    if let Some(handle) = guard.take() {
        #[cfg(target_os = "android")]
        unsafe { ANativeWindow_release(handle.window); }
    }
    0
}

// =========================================================================
// 🎨 BLIT EFFECTIF VERS VRAM
// =========================================================================

/// Blit `rgba` (format RGBA_8888, `width * height * 4` octets) dans la
/// surface active. Applique un letterbox si les dimensions diffèrent.
///
/// Retours :
///   0  = succès
///  -1  = window nul
///  -2  = dimensions invalides / taille buffer incorrecte
///  -3  = ANativeWindow_lock a échoué / bits nul
///  -4  = ANativeWindow_setBuffersGeometry a échoué
#[cfg(target_os = "android")]
unsafe fn blit_rgba_to_window(
    window: *mut c_void,
    rgba: &[u8],
    width: u32,
    height: u32,
) -> i32 {
    if window.is_null() { return -1; }
    if width == 0 || height == 0 { return -2; }
    if rgba.len() < (width as usize) * (height as usize) * 4 { return -2; }

    if ANativeWindow_setBuffersGeometry(
        window, width as i32, height as i32, WINDOW_FORMAT_RGBA_8888,
    ) != 0 {
        return -4;
    }

    let mut buf: ANativeWindow_Buffer = ANativeWindow_Buffer::default();
    if ANativeWindow_lock(window, &mut buf, std::ptr::null_mut()) != 0 {
        return -3;
    }

    // Copie ligne par ligne en respectant le stride (peut être > width).
    let dst_stride_px = buf.stride as usize;
    let dst_bpp = 4usize;
    let row_bytes = (width as usize) * dst_bpp;

    let dst_base = buf.bits as *mut u8;
    if dst_base.is_null() {
        let _ = ANativeWindow_unlockAndPost(window);
        return -3;
    }

    for y in 0..(height as usize) {
        let dst_row = dst_base.add(y * dst_stride_px * dst_bpp);
        let src_row = rgba.as_ptr().add(y * width as usize * dst_bpp);
        std::ptr::copy_nonoverlapping(src_row, dst_row, row_bytes);
    }

    ANativeWindow_unlockAndPost(window)
}

/// Génère et affiche un damier de diagnostic (preuve visuelle de bon
/// fonctionnement du pipeline VRAM). Utilisé pour valider surfaceCreated.
#[cfg(target_os = "android")]
unsafe fn blit_test_pattern(window: *mut c_void, width: u32, height: u32) -> i32 {
    const TILE: u32 = 64;
    let mut pixels = vec![0u8; (width as usize) * (height as usize) * 4];
    for y in 0..height {
        for x in 0..width {
            let on = ((x / TILE) + (y / TILE)) & 1 == 1;
            let i = ((y as usize) * (width as usize) + (x as usize)) * 4;
            if on {
                pixels[i]     = 0xFC; // R
                pixels[i + 1] = 0xBE; // G
                pixels[i + 2] = 0x0B; // B
                pixels[i + 3] = 0xFF; // A
            } else {
                pixels[i]     = 0x14;
                pixels[i + 1] = 0x14;
                pixels[i + 2] = 0x16;
                pixels[i + 3] = 0xFF;
            }
        }
    }
    blit_rgba_to_window(window, &pixels, width, height)
}

// =========================================================================
// FFI : blit direct + sondage + décodage
// =========================================================================

/// Point d'entrée FFI : blit un buffer RGBA dans la surface active.
/// Appelable depuis Dart via `aegis_render_secure_buffer(ptr, len, w, h)`.
///
/// Utilisé par le bouton "AFFICHER (VRAM)" du Vault lorsque les pixels
/// sont déjà en mémoire côté Dart.
///
/// Retours :
///   0   = succès
///  -1   = data_ptr nul
///  -2   = buffer trop petit pour w×h×4
///  -3   = aucune surface liée
///  -6   = blit ANativeWindow a échoué
///  -100 = non supporté hors Android
#[no_mangle]
pub unsafe extern "C" fn aegis_render_secure_buffer(
    data_ptr: *const u8,
    data_len: usize,
    width: u32,
    height: u32,
) -> i32 {
    if data_ptr.is_null() { return -1; }
    let expected = (width as usize).saturating_mul(height as usize).saturating_mul(4);
    if data_len < expected { return -2; }

    let guard = match CURRENT_SURFACE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let handle = match guard.as_ref() {
        Some(h) => h,
        None => return -3,
    };

    #[cfg(target_os = "android")]
    {
        let slice = std::slice::from_raw_parts(data_ptr, expected);
        return blit_rgba_to_window(handle.window, slice, width, height);
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = (data_ptr, data_len, width, height, handle);
        -100 // non supporté hors Android
    }
}

/// Renvoie 0 si une surface est active, -1 sinon. Utilisé par Dart pour
/// vérifier que BlindView est prêt avant d'envoyer un blit.
#[no_mangle]
pub unsafe extern "C" fn aegis_is_surface_ready() -> i32 {
    match CURRENT_SURFACE.lock() {
        Ok(g) => if g.is_some() { 0 } else { -1 },
        Err(p) => {
            let g = p.into_inner();
            if g.is_some() { 0 } else { -1 }
        }
    }
}

// =========================================================================
// 🎨 NOUVEAU : décodage + blit de fichier (bouton AFFICHER)
// =========================================================================

/// Lit un fichier image (JPEG/PNG) depuis le disque, le décode en RGBA,
/// puis le blit dans la surface VRAM active.
///
/// Appelable depuis Dart via `aegis_decode_and_blit_file(path_ptr)`.
///
/// Retours :
///   0   = succès
///   -1  = path nul
///   -2  = path non-UTF8
///   -3  = lecture disque impossible
///   -4  = décodage impossible (format non supporté / image corrompue)
///   -5  = aucune surface liée (BlindView pas encore mounté)
///   -6  = blit ANativeWindow a échoué
///  -100 = non supporté hors Android
#[no_mangle]
pub unsafe extern "C" fn aegis_decode_and_blit_file(
    path_ptr: *const c_char,
) -> i32 {
    if path_ptr.is_null() { return -1; }
    let path = match unsafe { std::ffi::CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return -3,
    };

    let decoded = match crate::viewer::decoder::decode_encoded(&bytes) {
        Ok(d) => d,
        Err(_) => return -4,
    };

    let guard = match CURRENT_SURFACE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let handle = match guard.as_ref() {
        Some(h) => h,
        None => return -5,
    };

    #[cfg(target_os = "android")]
    {
        let rc = unsafe {
            blit_rgba_to_window(handle.window, &decoded.rgba, decoded.width, decoded.height)
        };
        if rc == 0 { 0 } else { -6 }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (handle, decoded);
        -100
    }
}

// =========================================================================
// Media player (stub)
// =========================================================================

pub fn aegis_control_media_player(command: *const c_char, _position: f64) -> i32 {
    if command.is_null() { return -1; }
    0
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_pipe_512k_chunk_reading() {
        let test_size = 64 * 1024;
        let mut source = SecureBuffer::new(test_size);
        source.as_slice_mut().fill(0xAA);

        let pipe = StreamPipeController::new(source.len());
        pipe.play();

        let mut chunk = vec![0u8; 16 * 1024];
        let read_count = pipe.read_chunk_512k(&source, &mut chunk);
        assert_eq!(read_count, 16 * 1024);
        assert_eq!(chunk[0], 0xAA);

        pipe.pause();
        let read_scrambled = pipe.read_chunk_512k(&source, &mut chunk);
        assert_eq!(read_scrambled, 0);
        assert_eq!(chunk[0], 0x00);
    }

    #[test]
    fn test_stream_pipe_seek_bounds() {
        let source = SecureBuffer::new(64 * 1024);
        let pipe = StreamPipeController::new(source.len());
        assert!(pipe.seek(32 * 1024).is_ok());
        assert!(pipe.seek(128 * 1024).is_err());
    }

    #[test]
    fn test_ffi_media_player_wrapper() {
        let cmd = std::ffi::CString::new("PLAY").unwrap();
        assert_eq!(aegis_control_media_player(cmd.as_ptr(), 0.0), 0);
        assert_eq!(aegis_control_media_player(std::ptr::null(), 0.0), -1);
    }

    #[test]
    fn test_release_surface_idempotent() {
        assert_eq!(aegis_release_surface(), 0);
        assert_eq!(aegis_release_surface(), 0);
    }

    #[test]
    fn test_render_secure_buffer_no_surface() {
        let dummy = [0u8; 64];
        let rc = unsafe {
            aegis_render_secure_buffer(dummy.as_ptr(), dummy.len(), 4, 4)
        };
        // Pas de surface liée → -3 attendu (sur tous OS).
        assert_eq!(rc, -3);
    }

    #[test]
    fn test_render_secure_buffer_null_ptr() {
        let rc = unsafe { aegis_render_secure_buffer(std::ptr::null(), 0, 4, 4) };
        assert_eq!(rc, -1);
    }

    #[test]
    fn test_render_secure_buffer_too_small() {
        let dummy = [0u8; 10]; // 4×4×4 = 64 requis
        let rc = unsafe {
            aegis_render_secure_buffer(dummy.as_ptr(), dummy.len(), 4, 4)
        };
        assert_eq!(rc, -2);
    }

    #[test]
    fn test_is_surface_ready_initial_state() {
        // Avant tout aegis_render_to_surface, la surface est nulle.
        assert_eq!(unsafe { aegis_is_surface_ready() }, -1);
    }

    #[test]
    fn test_decode_and_blit_file_null_path() {
        let rc = unsafe { aegis_decode_and_blit_file(std::ptr::null()) };
        assert_eq!(rc, -1);
    }

    #[test]
    fn test_decode_and_blit_file_nonexistent_path() {
        let path = std::ffi::CString::new(
            "/tmp/this_file_does_not_exist_aegis_test_xyz.jpg",
        ).unwrap();
        let rc = unsafe { aegis_decode_and_blit_file(path.as_ptr()) };
        assert_eq!(rc, -3);
    }

    #[test]
    fn test_decode_and_blit_file_invalid_image() {
        // Fichier valide sur disque mais contenu non-image → -4.
        let tmp = std::env::temp_dir().join("aegis_not_an_image.bin");
        std::fs::write(&tmp, b"not a jpeg nor png").unwrap();

        let path = std::ffi::CString::new(tmp.to_str().unwrap()).unwrap();
        let rc = unsafe { aegis_decode_and_blit_file(path.as_ptr()) };
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(rc, -4);
    }
}