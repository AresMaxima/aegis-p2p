//! aegis-core/src/viewer/mod.rs
//! Module `viewer` : pipeline VRAM (StreamPipe) + décodage JPEG/PNG (decoder).
//!
//! - `stream_pipe` : FFI ANativeWindow (blit VRAM), StreamPipeController
//! - `decoder`     : JPEG/PNG → RGBA, YUV420 → RGBA, RGBA → JPEG
//!                   (utilisé par `stream_pipe::aegis_decode_and_blit_file`
//!                    et par `ingestion::aegis_seal_ram_to_disk`)

pub mod decoder;
pub mod stream_pipe;

pub use stream_pipe::*;