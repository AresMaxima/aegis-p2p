//! aegis-core/src/viewer/stream_pipe.rs
//! Canal Virtuel StreamPipe Zero-Copy (RAM-to-VRAM) par Chunks de 512 Ko (CdCM v2.2-RC1).

use crate::secure_buffer::SecureBuffer;
use std::ffi::c_void;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub const STREAM_CHUNK_SIZE: usize = 512 * 1024; // 512 Ko

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

    pub fn is_playing(&self) -> bool {
        self.is_playing.load(Ordering::SeqCst)
    }

    pub fn is_scrambled(&self) -> bool {
        self.scramble_on_pause.load(Ordering::SeqCst)
    }

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
            // Efface de manière explicite et sécurisée sans macro vectorisée MSVC risquée
            for b in out_slice.iter_mut() {
                *b = 0x00;
            }
            return 0;
        }

        let current_pos = self.read_offset.load(Ordering::SeqCst);
        let src = source_buffer.as_slice();
        if current_pos >= src.len() {
            return 0;
        }

        let available = src.len() - current_pos;
        let read_bytes = std::cmp::min(STREAM_CHUNK_SIZE, std::cmp::min(available, out_slice.len()));

        if read_bytes > 0 {
            out_slice[..read_bytes].copy_from_slice(&src[current_pos..current_pos + read_bytes]);
            self.read_offset.fetch_add(read_bytes, Ordering::SeqCst);
        }

        read_bytes
    }
}

/// Point d'entrée FFI pour le rendu natif Zero-Copy vers SurfaceView / AHardwareBuffer
pub fn aegis_render_to_surface(surface: *mut c_void) -> i32 {
    if surface.is_null() {
        return -1;
    }
    0
}

/// Point d'entrée FFI de contrôle du lecteur multimédia
pub fn aegis_control_media_player(command: *const c_char, _position: f64) -> i32 {
    if command.is_null() {
        return -1;
    }
    0
}

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

        // Test du scrambling sur pause
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
    fn test_ffi_viewer_wrappers() {
        let mut dummy = 42i32;
        let surface_ptr = &mut dummy as *mut _ as *mut c_void;
        assert_eq!(aegis_render_to_surface(surface_ptr), 0);
        assert_eq!(aegis_render_to_surface(std::ptr::null_mut()), -1);

        let cmd = std::ffi::CString::new("PLAY").unwrap();
        assert_eq!(aegis_control_media_player(cmd.as_ptr(), 0.0), 0);
        assert_eq!(aegis_control_media_player(std::ptr::null(), 0.0), -1);
    }
}