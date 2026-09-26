//! aegis-core/tests/phase3_v22_test.rs
//! Tests d'Intégration Phase 3 (Ingestion Caméra YUV420 & Zero-Disk File Ingestion) — CdCM v2.2-RC1.

#[cfg(test)]
mod tests {
    use aegis_core::ingestion::{aegis_ingest, aegis_ingest_camera_frame_direct};

    #[test]
    fn test_phase3_camera_ingestion_direct() {
        let width = 32u32;
        let height = 32u32;
        let y = vec![200u8; (width * height) as usize];
        let u = vec![128u8; (width * height / 4) as usize];
        let v = vec![128u8; (width * height / 4) as usize];

        let status = unsafe {
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
        assert_eq!(status, 0, "L'ingestion caméra directe doit renvoyer 0");
    }

    #[test]
    fn test_phase3_zero_disk_file_ingestion() {
        let raw_payload = b"EXIF_DUMMY_HEADER_METADATA_CLEANUP_TEST";
        let secure_buf = aegis_ingest(raw_payload).expect("L'ingestion Zero-Disk doit réussir");
        assert!(!secure_buf.as_slice().is_empty());
    }
}