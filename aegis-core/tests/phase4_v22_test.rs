#[cfg(test)]
mod tests {
    use aegis_core::secure_buffer::SecureBuffer;
    use aegis_core::viewer::stream_pipe::{
        aegis_control_media_player, aegis_render_to_surface, StreamPipeController,
    };
    use std::ffi::c_void;

    #[test]
    fn test_phase4_stream_pipe_zero_copy_and_scramble() {
        let payload_size = 64 * 1024; // 64 Ko
        let mut source = SecureBuffer::new(payload_size);
        source.as_slice_mut().fill(0x77);

        let pipe = StreamPipeController::new(payload_size);
        pipe.play();

        let mut out_chunk = vec![0u8; 16 * 1024];
        let read_bytes = pipe.read_chunk_512k(&source, &mut out_chunk);

        assert_eq!(read_bytes, 16 * 1024);
        assert_eq!(out_chunk[0], 0x77);

        // Validation du scrambling GPU sur pause (M5)
        pipe.pause();
        let scrambled_bytes = pipe.read_chunk_512k(&source, &mut out_chunk);
        assert_eq!(scrambled_bytes, 0);
        assert_eq!(out_chunk[0], 0x00);
    }

    #[test]
    fn test_phase4_ffi_viewer_bindings() {
        let mut dummy = 100i32;
        let surface_ptr = &mut dummy as *mut _ as *mut c_void;
        assert_eq!(aegis_render_to_surface(surface_ptr), 0);
        assert_eq!(aegis_render_to_surface(std::ptr::null_mut()), -1);

        let play_cmd = std::ffi::CString::new("PLAY").unwrap();
        assert_eq!(aegis_control_media_player(play_cmd.as_ptr(), 0.0), 0);
        assert_eq!(aegis_control_media_player(std::ptr::null(), 0.0), -1);
    }
}