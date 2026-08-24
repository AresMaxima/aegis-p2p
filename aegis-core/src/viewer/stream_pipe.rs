//! aegis-core/src/viewer/stream_pipe.rs
//! Moteur de Rendu Blind Viewer - FFI Stream Pipe constant (512 Ko) sans écriture disque

use crate::secure_buffer::SecureBuffer;
use std::sync::Arc;

pub struct BlindStreamPipe {
    buffer: Arc<SecureBuffer>,
    cursor: usize,
}

impl BlindStreamPipe {
    /// Paquets éphémères de 512 Ko (Constant-Bitrate Read)
    pub const CHUNK_SIZE: usize = 524_288;

    pub fn new(buffer: SecureBuffer) -> Self {
        Self {
            buffer: Arc::new(buffer),
            cursor: 0,
        }
    }

    /// Lit le prochain bloc de 512 Ko directement depuis le SecureBuffer en RAM mlock
    pub fn read_next_chunk(&mut self, out_buffer: &mut [u8]) -> usize {
        let total_len = self.buffer.as_slice().len();
        if self.cursor >= total_len {
            return 0;
        }

        let remaining = total_len - self.cursor;
        let bytes_to_read = std::cmp::min(remaining, std::cmp::min(out_buffer.len(), Self::CHUNK_SIZE));

        out_buffer[..bytes_to_read]
            .copy_from_slice(&self.buffer.as_slice()[self.cursor..self.cursor + bytes_to_read]);
        self.cursor += bytes_to_read;

        bytes_to_read
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
    }
}