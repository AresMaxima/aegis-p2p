//! aegis-core/src/ingestion.rs
//! Ingestion Furtive NDK Directe et Filtre Anti-PRNU (Lissage Gaussien / Perturbation CMOS) - CdCM v2.2-RC1.

use crate::network::p2p_transfer::MetadataStripper;
use crate::secure_buffer::SecureBuffer;
use rand::RngCore;

pub struct CameraIngestionPipeline;

impl CameraIngestionPipeline {
    /// Traite une trame YUV420/RAW capturée par Camera2 NDK, applique le filtre anti-PRNU et neutralise la signature capteur
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

        // Perturbation localisée du plan Y (Luma) pour détruire la signature PRNU du capteur CMOS
        Self::apply_anti_prnu_gaussian_filter(secure_frame.as_slice_mut(), width, height);

        // Stripping immédiat de toute métadonnée résiduelle
        let normalized = MetadataStripper::strip_and_normalize(&secure_frame);

        Ok(normalized)
    }

    /// Filtre anti-PRNU : Lissage adaptatif gaussien 3x3 sur la composante de luminance Y
    fn apply_anti_prnu_gaussian_filter(yuv_data: &mut [u8], width: usize, height: usize) {
        let y_plane_size = width * height;
        if yuv_data.len() < y_plane_size || width < 3 || height < 3 {
            return;
        }

        // Perturbation contrôlée sur les pixels de bordure et bruits haute fréquence
        for y in 1..height - 1 {
            for x in 1..width - 1 {
                let idx = y * width + x;

                // Noyau Gaussien 3x3
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

                // Injecte un micro-bruit d'entropie pour effacer le bruit fixe du capteur (FPN)
                let noise = (rand::thread_rng().next_u32() % 3) as i8 - 1;
                yuv_data[idx] = (filtered as i16 + noise as i16).clamp(0, 255) as u8;
            }
        }
    }
}

/// Point d'entrée FFI/NDK appelé par `src/lib.rs` (8 arguments, retour i32)
///
/// # Safety
///
/// Les pointeurs `y_buffer`, `u_buffer` et `v_buffer` doivent pointer vers des tampons mémoire
/// valides en lecture contenant respectivement au moins `y_len`, `u_len` et `v_len` octets.
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

    match CameraIngestionPipeline::process_camera_frame_direct(
        buf,
        width as usize,
        height as usize,
    ) {
        Ok(_processed) => 0,
        Err(_) => -2,
    }
}

/// Ingestion de fichier Zero-Disk générique
pub fn aegis_ingest_file_zero_disk(input_data: &[u8]) -> Result<SecureBuffer, &'static str> {
    let mut buf = SecureBuffer::new(input_data.len());
    buf.as_slice_mut().copy_from_slice(input_data);
    Ok(MetadataStripper::strip_and_normalize(&buf))
}

/// Ingestion générique de données brutes
pub fn aegis_ingest(data: &[u8]) -> Result<SecureBuffer, &'static str> {
    aegis_ingest_file_zero_disk(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camera_frame_processing_anti_prnu() {
        let width = 16u32;
        let height = 16u32;
        let y = vec![128u8; (width * height) as usize];
        let u = vec![128u8; (width * height / 4) as usize];
        let v = vec![128u8; (width * height / 4) as usize];

        let res = unsafe {
            aegis_ingest_camera_frame_direct(
                y.as_ptr(),
                y.len(),
                u.as_ptr(),
                u.len(),
                v.as_ptr(),
                v.len(),
                width,
                height,
            )
        };
        assert_eq!(res, 0);
    }

    #[test]
    fn test_zero_disk_ingestion_functions() {
        let sample = b"TEST_DATA_HEADER";
        let res = aegis_ingest(sample).unwrap();
        assert_eq!(res.len(), sample.len());
    }
}