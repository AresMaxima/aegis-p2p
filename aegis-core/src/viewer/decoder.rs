//! aegis-core/src/viewer/decoder.rs
//! Décodeur d'images vers RGBA pour le pipeline VRAM.
//!
//! Corrige la lacune "damier au lieu du fichier réel" relevée dans
//! l'audit du 12/09/2026 (bouton AFFICHER → écran noir).

/// Image décodée en RGBA_8888, prête pour blit VRAM.
pub struct DecodedImage {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

// =========================================================================
// Décodage JPEG / PNG (disque)
// =========================================================================

/// Décode un flux encodé (JPEG, PNG) en RGBA.
///
/// Le format est auto-détecté par `image` (magic bytes).
///
/// Limite OOM : refuse les images > 32 Mpx (132 Mo RGBA max).
pub fn decode_encoded(bytes: &[u8]) -> Result<DecodedImage, &'static str> {
    use image::GenericImageView;

    const MAX_PIXELS: u64 = 32 * 1024 * 1024;

    let img = image::load_from_memory(bytes).map_err(|_| "decode failed")?;
    let (w, h) = img.dimensions();
    if (w as u64) * (h as u64) > MAX_PIXELS {
        return Err("image trop grande");
    }

    let rgba = img.to_rgba8();
    Ok(DecodedImage {
        rgba: rgba.into_raw(),
        width: w,
        height: h,
    })
}

// =========================================================================
// Conversion YUV420 planar (CameraX) → RGBA
// =========================================================================

/// Convertit un buffer YUV420 planar (I420, sortie CameraX) en RGBA.
///
/// Formule : **BT.601 limited-range** (standard Camera2 YUV_420_888).
///   Y' = (Y - 16) * 1.164      → ramené à [0..255]
///   R = Y' + 1.596 * (V - 128)
///   G = Y' - 0.391 * (U - 128) - 0.813 * (V - 128)
///   B = Y' + 2.018 * (U - 128)
///
/// Implémentation fixed-point (×1024) : pas de float dans le hot path.
///
/// ⚠️ Suppose `stride == width` pour les 3 plans (cas CameraX par défaut
/// sur SM-G985F). Si des artefacts de cisaillement apparaissent sur
/// d'autres appareils, voir `p2p_transfer.rs` / patch Kotlin pour
/// transmettre les `rowStride` réels via arguments supplémentaires.
pub fn yuv420_to_rgba(y: &[u8], u: &[u8], v: &[u8], width: u32, height: u32) -> DecodedImage {
    let w = width as usize;
    let h = height as usize;

    if w == 0 || h == 0 || y.len() < w * h {
        return DecodedImage { rgba: Vec::new(), width: 0, height: 0 };
    }

    let uv_w = (w + 1) / 2;
    let uv_h = (h + 1) / 2;
    let uv_len_needed = uv_w * uv_h;

    // Bounds check strict : U et V doivent contenir au moins la moitié
    // (arrondi sup) de la résolution.
    if u.len() < uv_len_needed || v.len() < uv_len_needed {
        return DecodedImage { rgba: Vec::new(), width: 0, height: 0 };
    }

    let mut rgba = vec![0u8; w * h * 4];

    // Coefficients fixed-point (×1024) pour BT.601 limited-range.
    //   1.164 × 1024 = 1192
    //   1.596 × 1024 = 1634
    //   0.391 × 1024 =  400
    //   0.813 × 1024 =  833
    //   2.018 × 1024 = 2066
    const C_Y:   i32 = 1192;
    const C_RV:  i32 = 1634;
    const C_GU:  i32 =  400;
    const C_GV:  i32 =  833;
    const C_BU:  i32 = 2066;

    for j in 0..h {
        for i in 0..w {
            let y_raw = y[j * w + i] as i32;
            let uv_idx = (j / 2) * uv_w + (i / 2);

            let u_val = u[uv_idx] as i32 - 128;
            let v_val = v[uv_idx] as i32 - 128;

            // Y' = (Y - 16) * 1.164
            let y_scaled = ((y_raw - 16) * C_Y) >> 10;

            let r = (y_scaled + ((C_RV * v_val) >> 10)).clamp(0, 255) as u8;
            let g = (y_scaled - ((C_GU * u_val + C_GV * v_val) >> 10)).clamp(0, 255) as u8;
            let b = (y_scaled + ((C_BU * u_val) >> 10)).clamp(0, 255) as u8;

            let idx = (j * w + i) * 4;
            rgba[idx]     = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = 0xFF;
        }
    }

    DecodedImage { rgba, width, height }
}

// =========================================================================
// Encodage JPEG
// =========================================================================

/// Encode des octets RGB (3 octets/pixel) en JPEG avec qualité donnée.
pub fn encode_jpeg(
    rgb: &[u8],
    width: u32,
    height: u32,
    quality: u8,
) -> Result<Vec<u8>, &'static str> {
    use image::codecs::jpeg::JpegEncoder;

    if rgb.len() < (width as usize) * (height as usize) * 3 {
        return Err("buffer RGB trop petit");
    }

    let mut out = Vec::new();
    let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
    enc.encode(rgb, width, height, image::ExtendedColorType::Rgb8)
        .map_err(|_| "jpeg encode failed")?;
    Ok(out)
}

/// Encode un buffer RGBA (4 octets/pixel) en JPEG (alpha ignoré).
pub fn encode_rgba_as_jpeg(
    rgba: &[u8],
    width: u32,
    height: u32,
    quality: u8,
) -> Result<Vec<u8>, &'static str> {
    let mut rgb = Vec::with_capacity((width as usize) * (height as usize) * 3);
    for chunk in rgba.chunks_exact(4) {
        rgb.push(chunk[0]);
        rgb.push(chunk[1]);
        rgb.push(chunk[2]);
    }
    encode_jpeg(&rgb, width, height, quality)
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yuv420_to_rgba_dimensions() {
        let w = 4u32;
        let h = 4u32;
        let y = vec![128u8; (w * h) as usize];
        let u = vec![128u8; ((w / 2) * (h / 2)) as usize];
        let v = vec![128u8; ((w / 2) * (h / 2)) as usize];
        let img = yuv420_to_rgba(&y, &u, &v, w, h);
        assert_eq!(img.width, 4);
        assert_eq!(img.height, 4);
        assert_eq!(img.rgba.len(), 64);
        // Y=128 limited-range ≈ Y'=130, U=V=128 → gris neutre.
        // La valeur exacte dépend de l'arrondi fixed-point ;
        // on tolère ±4 autour de 130 (Y' attendu).
        let gray = img.rgba[0];
        assert!(gray >= 126 && gray <= 134, "gris attendu ~130, obtenu {}", gray);
    }

    #[test]
    fn test_yuv420_rejects_short_u_v() {
        let w = 4u32;
        let h = 4u32;
        let y = vec![128u8; (w * h) as usize];
        let u_short = vec![128u8; 1];  // trop petit
        let v = vec![128u8; ((w / 2) * (h / 2)) as usize];
        let img = yuv420_to_rgba(&y, &u_short, &v, w, h);
        assert!(img.rgba.is_empty(), "U trop court doit être rejeté");
    }

    #[test]
    fn test_encode_jpeg_roundtrip() {
        let rgb = vec![0x80u8; 16 * 16 * 3];
        let jpeg = encode_jpeg(&rgb, 16, 16, 80).unwrap();
        assert!(jpeg.len() > 100);
        assert_eq!(&jpeg[0..2], &[0xFF, 0xD8]); // SOI
    }

    #[test]
    fn test_decode_invalid_data() {
        assert!(decode_encoded(b"not an image").is_err());
    }

    #[test]
    fn test_encode_rgba_as_jpeg() {
        let rgba = vec![0x80u8; 8 * 8 * 4];
        let jpeg = encode_rgba_as_jpeg(&rgba, 8, 8, 85).unwrap();
        assert_eq!(&jpeg[0..2], &[0xFF, 0xD8]);
    }
}