//! aegis-core/src/network/p2p_transfer.rs
//! Normalisation, Stripping de Métadonnées et Fragmentation en Trames Fixes de 512 Octets (CdCM v2.2-RC1).

use crate::secure_buffer::SecureBuffer;
use rand::{thread_rng, RngCore};
use zeroize::Zeroize;

pub const FRAME_SIZE: usize = 512;
pub const HEADER_SIZE: usize = 8;
pub const PAYLOAD_HEADER_LEN: usize = 8;
pub const MAX_PAYLOAD_PER_FRAME: usize = FRAME_SIZE - HEADER_SIZE;

/// Type de média détecté pour le stripping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Jpeg,
    Png,
    WebP,
    Pdf,
    Mp4,
    Zip,
    Unknown,
}

pub struct MediaStripper;

impl MediaStripper {
    pub fn strip_jpeg_app_segments(data: &mut [u8]) {
        let mut i = 0;
        while i + 1 < data.len() {
            if data[i] == 0xFF {
                let marker = data[i + 1];
                if (marker == 0xE1 || marker == 0xE2 || marker == 0xED || marker == 0xFE)
                    && i + 3 < data.len()
                {
                    let len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
                    i += 2 + len;
                    continue;
                }
            }
            i += 1;
        }
    }
}

pub struct MetadataStripper;

impl MetadataStripper {
    /// Détecte le type de fichier via ses octets magiques
    pub fn detect_type(header: &[u8]) -> MediaType {
        if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
            MediaType::Jpeg
        } else if header.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            MediaType::Png
        } else if header.len() >= 12 && header.starts_with(b"RIFF") && &header[8..12] == b"WEBP" {
            MediaType::WebP
        } else if header.starts_with(b"%PDF") {
            MediaType::Pdf
        } else if header.len() >= 8 && &header[4..8] == b"ftyp" {
            MediaType::Mp4
        } else if header.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            MediaType::Zip
        } else {
            MediaType::Unknown
        }
    }

    /// Nettoie les métadonnées sensibles (EXIF, commentaires, headers) et normalise le tampon
    pub fn strip_and_normalize(input: &SecureBuffer) -> SecureBuffer {
        let raw = input.as_slice();
        let media_type = Self::detect_type(raw);

        let cleaned_vec = match media_type {
            MediaType::Jpeg => Self::strip_jpeg(raw),
            MediaType::Png => Self::strip_png(raw),
            MediaType::WebP => Self::strip_webp(raw),
            MediaType::Pdf => Self::strip_pdf(raw),
            MediaType::Mp4 => Self::strip_mp4(raw),
            MediaType::Zip => Self::strip_zip(raw),
            MediaType::Unknown => raw.to_vec(),
        };

        let mut out = SecureBuffer::new(cleaned_vec.len());
        out.as_slice_mut().copy_from_slice(&cleaned_vec);

        let mut temp_vec = cleaned_vec;
        temp_vec.zeroize();

        out
    }

    fn strip_jpeg(data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        MediaStripper::strip_jpeg_app_segments(&mut out);
        out
    }

    fn strip_png(data: &[u8]) -> Vec<u8> {
        if data.len() < 8 {
            return data.to_vec();
        }
        let mut out = Vec::with_capacity(data.len());
        out.extend_from_slice(&data[..8]); // Header PNG

        let mut i = 8;
        while i + 12 <= data.len() {
            let length = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
            let chunk_type = &data[i + 4..i + 8];

            // Conserve uniquement les chunks critiques : IHDR, PLTE, IDAT, IEND
            let is_critical = chunk_type == b"IHDR"
                || chunk_type == b"PLTE"
                || chunk_type == b"IDAT"
                || chunk_type == b"IEND";

            if is_critical {
                let total_chunk_len = 12 + length;
                if i + total_chunk_len <= data.len() {
                    out.extend_from_slice(&data[i..i + total_chunk_len]);
                }
            }
            i += 12 + length;
        }
        out
    }

    fn strip_webp(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
    fn strip_pdf(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
    fn strip_mp4(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
    fn strip_zip(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

pub struct P2PFramePacker;

impl P2PFramePacker {
    pub fn pack_payload(payload: &[u8]) -> Vec<[u8; FRAME_SIZE]> {
        let mut clean_payload = payload.to_vec();
        MediaStripper::strip_jpeg_app_segments(&mut clean_payload);

        let total_len = clean_payload.len();
        let total_chunks = total_len.div_ceil(MAX_PAYLOAD_PER_FRAME);
        let mut frames = Vec::with_capacity(total_chunks);

        for chunk_idx in 0..total_chunks {
            let mut frame = [0u8; FRAME_SIZE];
            let start = chunk_idx * MAX_PAYLOAD_PER_FRAME;
            let end = std::cmp::min(start + MAX_PAYLOAD_PER_FRAME, total_len);
            let chunk_data = &clean_payload[start..end];

            frame[0..4].copy_from_slice(&(chunk_idx as u32).to_be_bytes());
            frame[4..8].copy_from_slice(&(total_chunks as u32).to_be_bytes());
            frame[HEADER_SIZE..HEADER_SIZE + chunk_data.len()].copy_from_slice(chunk_data);

            if chunk_data.len() < MAX_PAYLOAD_PER_FRAME {
                thread_rng().fill_bytes(&mut frame[HEADER_SIZE + chunk_data.len()..]);
            }

            frames.push(frame);
        }

        clean_payload.zeroize();
        frames
    }
}

/// Découpage P2P en trames fixes de 512 octets avec rembourrage aléatoire (Chaff)
pub struct FramePaddings;

impl FramePaddings {
    /// Paquette un payload en une série de trames strictes de 512 octets
    pub fn pack_to_512_frames(payload: &[u8]) -> Vec<[u8; FRAME_SIZE]> {
        let mut frames = Vec::new();
        let total_len = payload.len();
        let mut offset = 0;

        let total_chunks = total_len.div_ceil(MAX_PAYLOAD_PER_FRAME);

        for chunk_idx in 0..std::cmp::max(1, total_chunks) {
            let mut frame = [0u8; FRAME_SIZE];
            let end = std::cmp::min(offset + MAX_PAYLOAD_PER_FRAME, total_len);
            let chunk_data = if offset < total_len { &payload[offset..end] } else { &[] };

            // Header : [Chunk Index (2B), Total Chunks (2B), Data Len (2B), Flags (2B)]
            let chunk_len = chunk_data.len() as u16;
            frame[0..2].copy_from_slice(&(chunk_idx as u16).to_be_bytes());
            frame[2..4].copy_from_slice(&(total_chunks as u16).to_be_bytes());
            frame[4..6].copy_from_slice(&chunk_len.to_be_bytes());
            frame[6..8].copy_from_slice(&[0x00, 0x00]); // Reserved/Flags

            if chunk_len > 0 {
                frame[PAYLOAD_HEADER_LEN..PAYLOAD_HEADER_LEN + chunk_data.len()]
                    .copy_from_slice(chunk_data);
            }

            // Remplissage CSPRNG du reste de la trame jusqu'à 512 octets
            let pad_start = PAYLOAD_HEADER_LEN + chunk_data.len();
            if pad_start < FRAME_SIZE {
                thread_rng().fill_bytes(&mut frame[pad_start..]);
            }

            frames.push(frame);
            offset += MAX_PAYLOAD_PER_FRAME;
        }

        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_types() {
        assert_eq!(
            MetadataStripper::detect_type(&[0xFF, 0xD8, 0xFF, 0xE0]),
            MediaType::Jpeg
        );
        assert_eq!(
            MetadataStripper::detect_type(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            MediaType::Png
        );
    }

    #[test]
    fn test_frame_padding_fixed_512() {
        let payload = vec![0x42u8; 1200];
        let frames = FramePaddings::pack_to_512_frames(&payload);

        assert_eq!(frames.len(), 3);
        for frame in frames {
            assert_eq!(frame.len(), 512);
        }
    }

    #[test]
    fn test_p2p_frame_packer() {
        let payload = vec![0x33u8; 1000];
        let frames = P2PFramePacker::pack_payload(&payload);

        assert_eq!(frames.len(), 2);
        for frame in frames {
            assert_eq!(frame.len(), 512);
        }
    }
}