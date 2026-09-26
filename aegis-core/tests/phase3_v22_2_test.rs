//! aegis-core/tests/phase3_v22_2_test.rs
//! Tests d'Intégration Phase 3.2 (Ingestion Directe Caméra & Fragmentation P2P) — CdCM v2.2-RC1.

#[cfg(test)]
mod tests {
    use aegis_core::ingestion::{aegis_ingest, aegis_ingest_camera_frame_direct};
    use aegis_core::network::p2p_transfer::{FramePaddings, FRAME_SIZE};

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

    #[test]
    fn test_phase3_p2p_frame_packing_512() {
        let payload = vec![0xAAu8; 1500];
        let frames = FramePaddings::pack_to_512_frames(&payload);

        // 1500 octets / 504 octets utiles par trame = 3 trames
        assert_eq!(frames.len(), 3);
        for frame in frames {
            assert_eq!(frame.len(), FRAME_SIZE);
        }
    }
}