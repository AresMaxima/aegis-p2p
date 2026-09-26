//! aegis-core/src/ingestion.rs
//! Ingestion Furtive NDK Directe et Filtre Anti-PRNU (Lissage Gaussien /
//! Perturbation CMOS) — CdCM v2.2-RC2.
//!
//! ─────────────────────────────────────────────────────────────────────
//! CORRECTIF MAJEUR (CdCM v2.2-RC2) :
//!   L'audit du 12/09/2026 relevait que le bouton "DÉPURER & SCELLER"
//!   restait grisé après une CAPTURE NDK, car la capture vivait en RAM
//!   sous la sentinelle `vram://live_camera_feed` (aucun chemin disque).
//!
//!   Ajout :
//!     • LAST_CAMERA_FRAME : stockage RAM du dernier frame capturé
//!       (avec PRNU déjà appliqué, cf. process_camera_frame_direct).
//!     • aegis_has_ram_capture()  → interrogation de présence
//!     • aegis_seal_ram_to_disk() → YUV420 → RGBA → JPEG q85 →
//!       strip APP/COM → écriture disque (nouveau chemin "scellé").
//! ─────────────────────────────────────────────────────────────────────

use crate::network::p2p_transfer::MetadataStripper;
use crate::secure_buffer::SecureBuffer;
use rand::RngCore;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::Mutex;
use zeroize::Zeroize;

// =========================================================================
// Pipeline d'ingestion caméra + anti-PRNU
// =========================================================================

pub struct CameraIngestionPipeline;

impl CameraIngestionPipeline {
    /// Traite une trame YUV420/RAW capturée par Camera2 NDK, applique le
    /// filtre anti-PRNU et neutralise la signature capteur.
    pub fn process_camera_frame_direct(
        raw_yuv_buffer: &[u8],
        width: usize,
        height: usize,
    ) -> Result<SecureBuffer, &'static str> {
        if raw_yuv_buffer.len() < width * height {
            return Err("Taille du tampon YUV invalide pour la résolution spécifiée");
        }

        let mut secure_frame = SecureBuffer::new(raw_yuv_buffer.len());
        secure_frame.as_slice_mut().copy_from_slice(raw_yuv_buffer);

        // Perturbation localisée du plan Y (Luma) pour détruire la
        // signature PRNU du capteur CMOS.
        Self::apply_anti_prnu_gaussian_filter(secure_frame.as_slice_mut(), width, height);

        // Stripping immédiat de toute métadonnée résiduelle.
        // Pour un buffer YUV (aucun magic byte connu), strip_and_normalize
        // tombe dans le cas `Unknown` → copie intégrale (taille inchangée).
        let normalized = MetadataStripper::strip_and_normalize(&secure_frame);

        Ok(normalized)
    }

    /// Filtre anti-PRNU : Lissage gaussien 3×3 sur la composante Y.
    fn apply_anti_prnu_gaussian_filter(yuv_data: &mut [u8], width: usize, height: usize) {
        let y_plane_size = width * height;
        if yuv_data.len() < y_plane_size || width < 3 || height < 3 {
            return;
        }

        for y in 1..height - 1 {
            for x in 1..width - 1 {
                let idx = y * width + x;

                let sum = (yuv_data[idx - width - 1] as u32)
                    + (yuv_data[idx - width] as u32 * 2)
                    + (yuv_data[idx - width + 1] as u32)
                    + (yuv_data[idx - 1] as u32 * 2)
                    + (yuv_data[idx] as u32 * 4)
                    + (yuv_data[idx + 1] as u32 * 2)
                    + (yuv_data[idx + width - 1] as u32)
                    + (yuv_data[idx + width] as u32 * 2)
                    + (yuv_data[idx + width + 1] as u32);

                let filtered = (sum / 16) as u8;

                // Micro-bruit d'entropie pour effacer le bruit fixe du
                // capteur (FPN).
                let noise = (rand::thread_rng().next_u32() % 3) as i8 - 1;
                yuv_data[idx] = (filtered as i16 + noise as i16).clamp(0, 255) as u8;
            }
        }
    }
}

// =========================================================================
// 🎥 DERNIER FRAME CAMÉRA EN RAM (post-PRNU)
// =========================================================================

/// Un frame YUV420 planar (Y + U + V) issu de CameraX, après application
/// du filtre anti-PRNU. Stocké dans `LAST_CAMERA_FRAME` jusqu'à ce que
/// `aegis_seal_ram_to_disk` le consomme.
struct CapturedFrame {
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
    width: u32,
    height: u32,
}

impl Drop for CapturedFrame {
    fn drop(&mut self) {
        // Effacement cryptographique des 3 plans à la destruction
        // (remplacement par un nouveau frame, ou consommation par seal).
        self.y.zeroize();
        self.u.zeroize();
        self.v.zeroize();
    }
}

/// Slot unique protégé par Mutex. Contient au plus 1 frame en attente.
static LAST_CAMERA_FRAME: Mutex<Option<CapturedFrame>> = Mutex::new(None);

// =========================================================================
// FFI : interrogation de présence
// =========================================================================

/// Renvoie 1 si un frame caméra est présent en RAM, 0 sinon.
///
/// Appelable depuis Dart pour savoir si le bouton DÉPURER doit être
/// activé (avant tout appel à `aegis_seal_ram_to_disk`).
#[no_mangle]
pub extern "C" fn aegis_has_ram_capture() -> i32 {
    match LAST_CAMERA_FRAME.lock() {
        Ok(g) => if g.is_some() { 1 } else { 0 },
        Err(p) => if p.into_inner().is_some() { 1 } else { 0 },
    }
}

// =========================================================================
// FFI : ingestion d'un frame caméra
// =========================================================================

/// Point d'entrée FFI/NDK appelé par `src/lib.rs` (8 arguments, retour i32).
///
/// Le frame reçu est :
///   1. Concaténé (Y|U|V) dans un SecureBuffer de travail
///   2. Filtré (anti-PRNU) par `CameraIngestionPipeline::process_camera_frame_direct`
///   3. Stocké dans `LAST_CAMERA_FRAME` (post-PRNU) pour seal ultérieur
///
/// Retours :
///   0  = succès
///  -1  = argument invalide (pointeur nul ou dimensions nulles)
///  -2  = traitement anti-PRNU échoué
///  -3  = incohérence de taille après strip (défense en profondeur)
///
/// # Safety
///
/// Les pointeurs `y_buffer`, `u_buffer` et `v_buffer` doivent pointer vers
/// des tampons valides en lecture de respectivement `y_len`, `u_len` et
/// `v_len` octets. Les tailles ne sont pas vérifiées contre `width*height`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn aegis_ingest_camera_frame_direct(
    y_buffer: *const u8,
    y_len: usize,
    u_buffer: *const u8,
    u_len: usize,
    v_buffer: *const u8,
    v_len: usize,
    width: u32,
    height: u32,
) -> i32 {
    if y_buffer.is_null() || y_len == 0 || width == 0 || height == 0 {
        return -1;
    }

    let y_slice = unsafe { std::slice::from_raw_parts(y_buffer, y_len) };
    let u_slice = if !u_buffer.is_null() && u_len > 0 {
        unsafe { std::slice::from_raw_parts(u_buffer, u_len) }
    } else {
        &[]
    };
    let v_slice = if !v_buffer.is_null() && v_len > 0 {
        unsafe { std::slice::from_raw_parts(v_buffer, v_len) }
    } else {
        &[]
    };

    // 1) Concaténation Y|U|V dans un SecureBuffer de travail.
    let total_len = y_len + u_len + v_len;
    let mut secure_yuv = SecureBuffer::new(total_len);
    let buf = secure_yuv.as_slice_mut();

    buf[..y_len].copy_from_slice(y_slice);
    if !u_slice.is_empty() {
        buf[y_len..y_len + u_len].copy_from_slice(u_slice);
    }
    if !v_slice.is_empty() {
        buf[y_len + u_len..total_len].copy_from_slice(v_slice);
    }

    // 2) Filtre anti-PRNU.
    let processed = match CameraIngestionPipeline::process_camera_frame_direct(
        buf,
        width as usize,
        height as usize,
    ) {
        Ok(p) => p,
        Err(_) => return -2,
    };

    // 3) Défense en profondeur : strip_and_normalize ne devrait pas
    //    modifier la longueur sur un buffer YUV (Unknown type), mais on
    //    refuse tout changement inattendu pour éviter une extraction
    //    d'offset erronée.
    if processed.len() != total_len {
        return -3;
    }

    // 4) Extraction des plans (copie locale vers Vec<u8>).
    let proc_slice = processed.as_slice();
    let y_proc = proc_slice[..y_len].to_vec();
    let u_proc = if u_len > 0 {
        proc_slice[y_len..y_len + u_len].to_vec()
    } else {
        Vec::new()
    };
    let v_proc = if v_len > 0 {
        proc_slice[y_len + u_len..total_len].to_vec()
    } else {
        Vec::new()
    };

    // 5) Remplacement atomique du frame stocké.
    //    L'ancien frame, s'il existe, est drop() → Zeroize (cf. Drop impl).
    {
        let mut guard = match LAST_CAMERA_FRAME.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(CapturedFrame {
            y: y_proc,
            u: u_proc,
            v: v_proc,
            width,
            height,
        });
    }

    0
}

// =========================================================================
// FFI : scellement du frame RAM vers disque (bouton DÉPURER après CAPTURE)
// =========================================================================

/// Encode le dernier frame caméra RAM en JPEG (qualité 85), strip les
/// segments APP/COM (défense en profondeur), puis écrit le résultat sur
/// disque. Le frame RAM est consommé (et zeroizé) par cette opération.
///
/// Retours :
///   0   = succès
///   -1   = path nul
///   -2   = path non-UTF8
///   -3   = aucun frame caméra en RAM
///   -4   = conversion YUV→RGBA échouée (planes vides ou dimensions KO)
///   -5   = encodage JPEG échoué
///   -6   = écriture disque échouée
///
/// # Safety
///
/// `path_ptr` doit pointer vers une chaîne C valide (NUL-terminée) et
/// accessible en lecture.
#[no_mangle]
pub unsafe extern "C" fn aegis_seal_ram_to_disk(path_ptr: *const c_char) -> i32 {
    if path_ptr.is_null() { return -1; }
    let path = match unsafe { CStr::from_ptr(path_ptr) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // Retrait atomique du frame. Sur un chemin d'erreur ultérieur, le
    // frame sera perdu — l'utilisateur devra re-capturer. Choix assumé :
    // minimiser le temps de séjour en RAM.
    let frame = {
        let mut guard = match LAST_CAMERA_FRAME.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match guard.take() {
            Some(f) => f,
            None => return -3,
        }
    };
    // Le frame est drop() à la fin de cette fonction → Zeroize automatique.

    // YUV420 → RGBA (BT.601 limited-range).
    let decoded = crate::viewer::decoder::yuv420_to_rgba(
        &frame.y, &frame.u, &frame.v,
        frame.width, frame.height,
    );
    if decoded.rgba.is_empty() {
        return -4;
    }

    // RGBA → JPEG q85.
    let jpeg = match crate::viewer::decoder::encode_rgba_as_jpeg(
        &decoded.rgba, decoded.width, decoded.height, 85,
    ) {
        Ok(j) => j,
        Err(_) => return -5,
    };

    // Strip APP/COM (défense en profondeur : l'encodeur `image` n'ajoute
    // pas d'EXIF, mais on garantit un flux propre même si un encodeur
    // futur venait à en injecter).
    let stripped =
        crate::network::p2p_transfer::MediaStripper::strip_jpeg_app_segments(&jpeg);

    match std::fs::write(path, &stripped) {
        Ok(_) => 0,
        Err(_) => -6,
    }
}

// =========================================================================
// Ingestion fichier générique (Zero-Disk)
// =========================================================================

/// Ingestion de fichier Zero-Disk générique.
pub fn aegis_ingest_file_zero_disk(input_data: &[u8]) -> Result<SecureBuffer, &'static str> {
    let mut buf = SecureBuffer::new(input_data.len());
    buf.as_slice_mut().copy_from_slice(input_data);
    Ok(MetadataStripper::strip_and_normalize(&buf))
}

/// Ingestion générique de données brutes.
pub fn aegis_ingest(data: &[u8]) -> Result<SecureBuffer, &'static str> {
    aegis_ingest_file_zero_disk(data)
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as TestMutex;

    /// Sérialise les tests qui manipulent LAST_CAMERA_FRAME (état global).
    /// Sans ce verrou, les tests parallèles de `cargo test` se marcheraient
    /// dessus.
    static TEST_LOCK: TestMutex<()> = TestMutex::new(());

    fn reset_frame() {
        let mut g = LAST_CAMERA_FRAME.lock().unwrap();
        *g = None;
    }

    #[test]
    fn test_camera_frame_processing_anti_prnu() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_frame();

        let width = 16u32;
        let height = 16u32;
        let y = vec![128u8; (width * height) as usize];
        let u = vec![128u8; (width * height / 4) as usize];
        let v = vec![128u8; (width * height / 4) as usize];

        let res = unsafe {
            aegis_ingest_camera_frame_direct(
                y.as_ptr(), y.len(),
                u.as_ptr(), u.len(),
                v.as_ptr(), v.len(),
                width, height,
            )
        };
        assert_eq!(res, 0);
        assert_eq!(aegis_has_ram_capture(), 1);

        // Le frame doit avoir été stocké avec les bonnes dimensions.
        {
            let g = LAST_CAMERA_FRAME.lock().unwrap();
            let f = g.as_ref().unwrap();
            assert_eq!(f.width, width);
            assert_eq!(f.height, height);
            assert_eq!(f.y.len(), y.len());
            assert_eq!(f.u.len(), u.len());
            assert_eq!(f.v.len(), v.len());
        }

        reset_frame();
    }

    #[test]
    fn test_zero_disk_ingestion_functions() {
        let sample = b"TEST_DATA_HEADER";
        let res = aegis_ingest(sample).unwrap();
        assert_eq!(res.len(), sample.len());
    }

    #[test]
    fn test_has_ram_capture_initial_state() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_frame();
        assert_eq!(aegis_has_ram_capture(), 0);
    }

    #[test]
    fn test_seal_without_capture() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_frame();

        let path = CStr::from_bytes_with_nul(b"/tmp/never.jpg\0").unwrap();
        let rc = unsafe { aegis_seal_ram_to_disk(path.as_ptr()) };
        assert_eq!(rc, -3);
    }

    #[test]
    fn test_seal_with_capture_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_frame();

        // Injecte un frame YUV factice.
        let w = 16u32;
        let h = 16u32;
        let y = vec![200u8; (w * h) as usize];
        let u = vec![128u8; ((w / 2) * (h / 2)) as usize];
        let v = vec![128u8; ((w / 2) * (h / 2)) as usize];

        let rc_ingest = unsafe {
            aegis_ingest_camera_frame_direct(
                y.as_ptr(), y.len(),
                u.as_ptr(), u.len(),
                v.as_ptr(), v.len(),
                w, h,
            )
        };
        assert_eq!(rc_ingest, 0);
        assert_eq!(aegis_has_ram_capture(), 1);

        let tmp = std::env::temp_dir().join("aegis_seal_test.jpg");
        let tmp_c = std::ffi::CString::new(tmp.to_str().unwrap()).unwrap();
        let rc_seal = unsafe { aegis_seal_ram_to_disk(tmp_c.as_ptr()) };
        assert_eq!(rc_seal, 0);

        // Le fichier doit commencer par SOI (FF D8).
        let bytes = std::fs::read(&tmp).unwrap();
        assert!(bytes.len() > 100);
        assert_eq!(&bytes[0..2], &[0xFF, 0xD8]);

        // Après seal, plus rien en RAM.
        assert_eq!(aegis_has_ram_capture(), 0);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_seal_null_path() {
        let rc = unsafe { aegis_seal_ram_to_disk(std::ptr::null()) };
        assert_eq!(rc, -1);
    }

    #[test]
    fn test_ingest_invalid_args() {
        let res = unsafe {
            aegis_ingest_camera_frame_direct(
                std::ptr::null(), 0,
                std::ptr::null(), 0,
                std::ptr::null(), 0,
                0, 0,
            )
        };
        assert_eq!(res, -1);
    }
}