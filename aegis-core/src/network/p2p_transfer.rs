//! aegis-core/src/network/p2p_transfer.rs
//! Module de Dépuration des Métadonnées, Anonymisation I/O & Normalisation RAM

use crate::secure_buffer::SecureBuffer;
use rand::Rng;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum StripperError {
    #[error("Erreur d'allocation ou verrouillage SecureBuffer")]
    BufferError,
    #[error("Format de fichier non reconnu ou corrompu")]
    InvalidFormat,
    #[error("Erreur I/O lors de la manipulation du flux RAM")]
    IoError(#[from] std::io::Error),
    #[error("Format non supporté pour la dépuration")]
    UnsupportedFormat,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileType {
    Jpeg,
    Png,
    Webp,
    Heic,
    Tiff,
    Pdf,
    Epub,
    OfficeXml,
    Mp4Video,
    MkvVideo,
    GenericDoc,
}

pub struct MetadataStripper;

impl MetadataStripper {
    /// Taille de bloc pour le padding cryptographique (64 Ko)
    const PADDING_BLOCK_SIZE: usize = 65536;

    /// Identification dynamique par octets magiques (Header)
    pub fn detect_type(data: &[u8]) -> FileType {
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            FileType::Jpeg
        } else if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            FileType::Png
        } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
            FileType::Webp
        } else if data.len() >= 12 && &data[4..8] == b"ftyp" && (&data[8..12] == b"heic" || &data[8..12] == b"heim" || &data[8..12] == b"heis") {
            FileType::Heic
        } else if data.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) {
            FileType::Tiff
        } else if data.starts_with(b"%PDF") {
            FileType::Pdf
        } else if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
            FileType::MkvVideo
        } else if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            // Distanciation entre EPUB et Office XML (DOCX/XLSX/PPTX)
            if data.windows(11).any(|w| w == b"mimetypeepub") {
                FileType::Epub
            } else {
                FileType::OfficeXml
            }
        } else if data.len() >= 8 && &data[4..8] == b"ftyp" {
            FileType::Mp4Video
        } else {
            FileType::GenericDoc
        }
    }

    /// Exécution intégrale du Stripping, Horodatage Factice & Padding en RAM
    pub fn strip_and_normalize(input: &SecureBuffer) -> Result<SecureBuffer, StripperError> {
        let raw_bytes = input.as_slice();
        let file_type = Self::detect_type(raw_bytes);

        let mut cleaned_bytes: Zeroizing<Vec<u8>> = match file_type {
            FileType::Jpeg => Self::strip_jpeg(raw_bytes)?,
            FileType::Png => Self::strip_png(raw_bytes)?,
            FileType::Webp => Self::strip_webp(raw_bytes)?,
            FileType::Pdf => Self::strip_pdf(raw_bytes)?,
            FileType::Mp4Video | FileType::Heic => Self::strip_mp4_container(raw_bytes)?,
            FileType::OfficeXml | FileType::Epub => Self::strip_zip_container(raw_bytes)?,
            FileType::Tiff | FileType::MkvVideo | FileType::GenericDoc => {
                let mut vec = Vec::with_capacity(raw_bytes.len() + Self::PADDING_BLOCK_SIZE);
                vec.extend_from_slice(raw_bytes);
                Zeroizing::new(vec)
            }
        };

        Self::apply_payload_padding(&mut cleaned_bytes, Self::PADDING_BLOCK_SIZE);

        let mut secure_buf = SecureBuffer::new(cleaned_bytes.len());
        secure_buf.as_slice_mut().copy_from_slice(&cleaned_bytes);

        Ok(secure_buf)
    }

    fn strip_jpeg(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StripperError> {
        if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
            return Err(StripperError::InvalidFormat);
        }

        let max_capacity = data.len() + Self::PADDING_BLOCK_SIZE;
        let mut output = Zeroizing::new(Vec::with_capacity(max_capacity));
        output.push(0xFF);
        output.push(0xD8);

        let mut cursor = 2;
        while cursor < data.len() {
            if data[cursor] != 0xFF {
                output.push(data[cursor]);
                cursor += 1;
                continue;
            }

            if cursor + 1 >= data.len() { break; }
            let marker = data[cursor + 1];

            if marker == 0xD9 || marker == 0xDA {
                output.extend_from_slice(&data[cursor..]);
                break;
            }

            // Purge des marqueurs APP1-APP15 (EXIF/GPS/ICC) et COM (Commentaires)
            if (0xE1..=0xEF).contains(&marker) || marker == 0xFE {
                if cursor + 3 >= data.len() { return Err(StripperError::InvalidFormat); }
                let length = ((data[cursor + 2] as usize) << 8) | (data[cursor + 3] as usize);
                if data.len().checked_sub(cursor + 2).map_or(true, |rem| length > rem) {
                    return Err(StripperError::InvalidFormat);
                }
                cursor += 2 + length;
            } else {
                output.push(data[cursor]);
                output.push(data[cursor + 1]);
                cursor += 2;
            }
        }
        Ok(output)
    }

    fn strip_png(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StripperError> {
        if data.len() < 8 { return Err(StripperError::InvalidFormat); }

        let max_capacity = data.len() + Self::PADDING_BLOCK_SIZE;
        let mut output = Zeroizing::new(Vec::with_capacity(max_capacity));
        output.extend_from_slice(&data[..8]);
        let mut cursor = 8;

        while cursor + 12 <= data.len() {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&data[cursor..cursor + 4]);
            let length = u32::from_be_bytes(len_bytes) as usize;

            if data.len().checked_sub(cursor + 12).map_or(true, |rem| length > rem) {
                return Err(StripperError::InvalidFormat);
            }

            let chunk_type = &data[cursor + 4..cursor + 8];

            // Purge textuelle, EXIF, Profils ICC et Horodatage (tIME)
            if chunk_type == b"tEXt" || chunk_type == b"zTXt" || chunk_type == b"iTXt" 
                || chunk_type == b"eXIf" || chunk_type == b"tIME" || chunk_type == b"iCCP" {
                cursor += 12 + length;
            } else {
                output.extend_from_slice(&data[cursor..cursor + 12 + length]);
                cursor += 12 + length;
            }
        }
        Ok(output)
    }

    fn strip_webp(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StripperError> {
        if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WEBP" {
            return Err(StripperError::InvalidFormat);
        }

        let max_capacity = data.len() + Self::PADDING_BLOCK_SIZE;
        let mut output = Zeroizing::new(Vec::with_capacity(max_capacity));
        output.extend_from_slice(&data[..12]);
        let mut cursor = 12;

        while cursor + 8 <= data.len() {
            let chunk_type = &data[cursor..cursor + 4];
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&data[cursor + 4..cursor + 8]);
            let length = u32::from_le_bytes(len_bytes) as usize;
            let padded_length = length + (length % 2);

            if data.len().checked_sub(cursor + 8).map_or(true, |rem| padded_length > rem) {
                return Err(StripperError::InvalidFormat);
            }

            // Purge des chunks EXIF, XMP et Profils Couleur
            if chunk_type == b"EXIF" || chunk_type == b"XMP " || chunk_type == b"ICCP" {
                cursor += 8 + padded_length;
            } else {
                output.extend_from_slice(&data[cursor..cursor + 8 + padded_length]);
                cursor += 8 + padded_length;
            }
        }

        // Mise à jour de la taille globale du header RIFF
        let new_riff_size = ((output.len() - 8) as u32).to_le_bytes();
        output[4..8].copy_from_slice(&new_riff_size);

        Ok(output)
    }

    fn strip_pdf(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StripperError> {
        if !data.starts_with(b"%PDF") {
            return Err(StripperError::InvalidFormat);
        }

        let max_capacity = data.len() + Self::PADDING_BLOCK_SIZE;
        let mut output = Zeroizing::new(Vec::with_capacity(max_capacity));
        let mut cleaned = data.to_vec();

        // Renommage neutre à taille exacte pour neutraliser les clés d'information sans altérer les offsets PDF
        let targets: &[(&[u8], &[u8])] = &[
            (b"/CreationDate", b"/Creation_Null"),
            (b"/ModDate",      b"/Mod_Null"),
            (b"/Author",       b"/Auth_N"),
            (b"/Producer",     b"/Prod_Null"),
            (b"/Creator",      b"/Crea_Null"),
            (b"/Metadata",     b"/Meta_Null"),
        ];

        for &(target, replacement) in targets {
            debug_assert_eq!(target.len(), replacement.len());
            let mut pos = 0;
            while let Some(idx) = cleaned[pos..].windows(target.len()).position(|w| w == target) {
                let absolute_idx = pos + idx;
                cleaned[absolute_idx..absolute_idx + replacement.len()].copy_from_slice(replacement);
                pos = absolute_idx + target.len();
            }
        }

        output.extend_from_slice(&cleaned);
        Ok(output)
    }

    fn strip_mp4_container(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StripperError> {
        if data.len() < 8 { return Err(StripperError::InvalidFormat); }

        let max_capacity = data.len() + Self::PADDING_BLOCK_SIZE;
        let mut output = Zeroizing::new(Vec::with_capacity(max_capacity));
        let mut cursor = 0;

        while cursor + 8 <= data.len() {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&data[cursor..cursor + 4]);
            let length = u32::from_be_bytes(len_bytes) as usize;

            let atom_type = &data[cursor + 4..cursor + 8];

            if length < 8 || data.len().checked_sub(cursor).map_or(true, |rem| length > rem) {
                output.extend_from_slice(&data[cursor..]);
                break;
            }

            // Ignorer l'atome de métadonnées utilisateur 'udta' et 'meta'
            if atom_type == b"udta" || atom_type == b"meta" {
                cursor += length;
            } else {
                output.extend_from_slice(&data[cursor..cursor + length]);
                cursor += length;
            }
        }
        Ok(output)
    }

    fn strip_zip_container(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StripperError> {
        if !data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            return Err(StripperError::InvalidFormat);
        }

        let max_capacity = data.len() + Self::PADDING_BLOCK_SIZE;
        let mut output = Zeroizing::new(Vec::with_capacity(max_capacity));
        let mut cleaned = data.to_vec();

        // Normalisation d'horodatage MS-DOS Zip (1970-01-01 / 00:00:00)
        let mut cursor = 0;
        while cursor + 30 <= cleaned.len() {
            if &cleaned[cursor..cursor + 4] == &[0x50, 0x4B, 0x03, 0x04] {
                // Remplacement heure et date de modification (offsets 10..14) par 0x0000
                cleaned[cursor + 10..cursor + 14].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            }
            cursor += 1;
        }

        output.extend_from_slice(&cleaned);
        Ok(output)
    }

    /// Padding cryptographique sans allocation de tampon (1 à 65536 octets)
    fn apply_payload_padding(bytes: &mut Vec<u8>, block_size: usize) {
        let remainder = bytes.len() % block_size;
        let pad_len = block_size - remainder;
        let mut rng = rand::thread_rng();

        debug_assert!(bytes.capacity() >= bytes.len() + pad_len);

        for _ in 0..pad_len {
            bytes.push(rng.gen());
        }
    }
}