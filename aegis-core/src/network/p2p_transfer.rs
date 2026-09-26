//! aegis-core/src/network/p2p_transfer.rs
//! Normalisation, Stripping de Métadonnées et Fragmentation en Trames
//! Fixes de 512 Octets (CdCM v2.2-RC1).
//!
//! ─────────────────────────────────────────────────────────────────────
//! CORRECTIF MAJEUR (CdCM v2.2-RC2) :
//!   L'ancienne `MediaStripper::strip_jpeg_app_segments` parcourait le
//!   flux sans jamais retirer un seul octet (bug logique : elle se
//!   contentait de "sauter" les segments APP en incrémentant `i`, mais
//!   la sortie restait identique à l'entrée). Résultat : EXIF, XMP, IPTC,
//!   commentaires Photoshop et IFD GPS étaient tous transmis tels quels.
//!
//!   La nouvelle implémentation parse réellement la structure JPEG et
//!   reconstruit un Vec<u8> ne contenant que les segments conservés.
//! ─────────────────────────────────────────────────────────────────────

use crate::secure_buffer::SecureBuffer;
use rand::{thread_rng, RngCore};
use zeroize::Zeroize;

pub const FRAME_SIZE: usize = 512;
pub const HEADER_SIZE: usize = 8;
pub const PAYLOAD_HEADER_LEN: usize = 8;
pub const MAX_PAYLOAD_PER_FRAME: usize = FRAME_SIZE - HEADER_SIZE;

/// Type de média détecté pour le stripping.
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

// =========================================================================
// Stripping réel des segments APP / COM JPEG
// =========================================================================

pub struct MediaStripper;

impl MediaStripper {
    /// Supprime **réellement** les segments APP1-APP15 et COM d'un flux JPEG.
    ///
    /// Politique de conservation :
    ///   • SOI (FF D8)        : conservé
    ///   • APP0 (FF E0, JFIF) : **conservé** — nécessaire à la compatibilité
    ///     d'affichage (déclare la version JFIF et les unités de densité).
    ///   • APP1-APP15         : **supprimés**
    ///       - APP1  → EXIF / XMP / GPS / IFD
    ///       - APP2  → ICC / FlashPix
    ///       - APP12 → Ducky / commentaires
    ///       - APP13 → Photoshop IRB / 8BIM
    ///       - APP14 → Adobe (CMYK) — supprimé aussi (rare en mobile)
    ///       - APP15 → metadata diverse
    ///   • COM  (FF FE)       : **supprimé** (commentaires libres)
    ///   • DQT/DHT/SOF/DRI/…  : conservés (nécessaires au décodage)
    ///   • SOS  (FF DA)       : conservé + **tout ce qui suit** est copié
    ///     tel quel (data entropique, pas de parsing possible sans décodeur).
    ///   • EOI  (FF D9)       : conservé
    ///
    /// Retourne un **nouveau** Vec<u8> — la taille change, un stripping
    /// in-place est impossible.
    ///
    /// Si `data` n'est pas un JPEG valide (pas de SOI), retourne une copie
    /// inchangée (fail-safe : jamais de corruption).
    pub fn strip_jpeg_app_segments(data: &[u8]) -> Vec<u8> {
        // Validation minimale : SOI obligatoire (FF D8).
        if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
            return data.to_vec();
        }

        let mut out = Vec::with_capacity(data.len());
        // Copie du SOI.
        out.push(0xFF);
        out.push(0xD8);

        let mut i = 2usize;
        while i + 1 < data.len() {
            // Tout marqueur JPEG commence par 0xFF.
            if data[i] != 0xFF {
                // Structure invalide en cours de route : copie du reste
                // et sortie (fail-safe).
                out.extend_from_slice(&data[i..]);
                break;
            }

            let marker = data[i + 1];

            // Padding : plusieurs 0xFF consécutifs avant le vrai marqueur
            // (rare, autorisé par la spec comme "fill bytes").
            if marker == 0xFF {
                i += 1;
                continue;
            }

            // SOS (Start of Scan) : à partir d'ici c'est de la data
            // entropique (VLC + EOB). On copie intégralement jusqu'à
            // l'EOI. Aucun parsing de segments n'est possible sans un
            // décodeur Huffman complet.
            if marker == 0xDA {
                out.extend_from_slice(&data[i..]);
                break;
            }

            // EOI (End of Image).
            if marker == 0xD9 {
                out.push(0xFF);
                out.push(0xD9);
                break;
            }

            // Marqueurs sans champ de longueur (RST0-RST7 = D0..D7, TEM = 01).
            if (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
                out.push(0xFF);
                out.push(marker);
                i += 2;
                continue;
            }

            // Marqueurs avec longueur (segment structuré).
            if i + 3 >= data.len() {
                // Tronqué : copie du reste et sortie.
                out.extend_from_slice(&data[i..]);
                break;
            }

            let seg_len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);

            // La longueur inclut les 2 octets du champ lui-même.
            // Valeur minimale légale : 2.
            if seg_len < 2 {
                out.extend_from_slice(&data[i..]);
                break;
            }

            let seg_end = i + 2 + seg_len;
            if seg_end > data.len() {
                // Segment tronqué : copie du reste et sortie.
                out.extend_from_slice(&data[i..]);
                break;
            }

            // Décision de stripping.
            //
            // is_app0        : APP0/JFIF   → CONSERVÉ
            // is_app_other   : APP1..APP15 → SUPPRIMÉ
            // is_comment     : COM         → SUPPRIMÉ
            // autres         : DQT, DHT, SOF0..SOF15, DRI, DAC… → CONSERVÉS
            let is_app0 = marker == 0xE0;
            let is_app_other = (0xE1..=0xEF).contains(&marker);
            let is_comment = marker == 0xFE;

            let should_strip = is_app_other || is_comment;

            if is_app0 || !should_strip {
                // Recopie intégrale du segment (FF marker len_hi len_lo data).
                out.extend_from_slice(&data[i..seg_end]);
            }
            // Si should_strip : on saute le segment (i avance à seg_end).

            i = seg_end;
        }

        out.shrink_to_fit();
        out
    }
}

// =========================================================================
// Détection de type et normalisation par conteneur
// =========================================================================

pub struct MetadataStripper;

impl MetadataStripper {
    /// Détecte le type de fichier via ses octets magiques.
    pub fn detect_type(header: &[u8]) -> MediaType {
        if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
            MediaType::Jpeg
        } else if header.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            MediaType::Png
        } else if header.len() >= 12
            && header.starts_with(b"RIFF")
            && &header[8..12] == b"WEBP"
        {
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

    /// Nettoie les métadonnées sensibles (EXIF, commentaires, headers) et
    /// normalise le tampon dans un nouveau `SecureBuffer`.
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

        // Zeroize du tampon intermédiaire.
        let mut temp_vec = cleaned_vec;
        temp_vec.zeroize();

        out
    }

    fn strip_jpeg(data: &[u8]) -> Vec<u8> {
        // Délègue au stripper APP/COM réel.
        MediaStripper::strip_jpeg_app_segments(data)
    }

    /// Retire les chunks PNG non critiques (tEXt, iTXt, zTXt, tIME, eXIf,
    /// gAMA, cHRM, sRGB, iCCP…). Conserve IHDR, PLTE, IDAT, IEND.
    fn strip_png(data: &[u8]) -> Vec<u8> {
        if data.len() < 8 {
            return data.to_vec();
        }
        let mut out = Vec::with_capacity(data.len());
        out.extend_from_slice(&data[..8]); // Signature PNG

        let mut i = 8;
        while i + 12 <= data.len() {
            let length =
                u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
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

    // Conteneurs non encore implémentés : copie brute en attendant un
    // parseur dédié. À terme : WebP (RIFF/EXIF), PDF (XMP), MP4 (moov/udta),
    // ZIP (commentaires globaux).
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

// =========================================================================
// Fragmentation en trames de 512 octets
// =========================================================================

pub struct P2PFramePacker;

impl P2PFramePacker {
    /// Fragmente un payload en trames fixes de 512 octets, après stripping
    /// APP/COM JPEG (no-op si le payload n'est pas un JPEG).
    pub fn pack_payload(payload: &[u8]) -> Vec<[u8; FRAME_SIZE]> {
        // CORRECTIF : l'ancienne API modifiait en place un Vec temporaire
        // sans jamais le retourner. La nouvelle API retourne un Vec frais
        // contenant uniquement les octets effectivement conservés.
        let mut clean_payload = MediaStripper::strip_jpeg_app_segments(payload);

        let total_len = clean_payload.len();
        let total_chunks = total_len.div_ceil(MAX_PAYLOAD_PER_FRAME);
        let mut frames = Vec::with_capacity(total_chunks);

        for chunk_idx in 0..total_chunks {
            let mut frame = [0u8; FRAME_SIZE];
            let start = chunk_idx * MAX_PAYLOAD_PER_FRAME;
            let end = std::cmp::min(start + MAX_PAYLOAD_PER_FRAME, total_len);
            let chunk_data = &clean_payload[start..end];

            // En-tête : [chunk_idx (u32 BE) | total_chunks (u32 BE)]
            frame[0..4].copy_from_slice(&(chunk_idx as u32).to_be_bytes());
            frame[4..8].copy_from_slice(&(total_chunks as u32).to_be_bytes());
            frame[HEADER_SIZE..HEADER_SIZE + chunk_data.len()].copy_from_slice(chunk_data);

            // Remplissage CSPRNG du reste de la trame (chaff anti-fingerprint).
            if chunk_data.len() < MAX_PAYLOAD_PER_FRAME {
                thread_rng().fill_bytes(&mut frame[HEADER_SIZE + chunk_data.len()..]);
            }

            frames.push(frame);
        }

        clean_payload.zeroize();
        frames
    }
}

/// Découpage P2P en trames fixes de 512 octets avec rembourrage aléatoire (Chaff).
pub struct FramePaddings;

impl FramePaddings {
    /// Paquette un payload en une série de trames strictes de 512 octets.
    pub fn pack_to_512_frames(payload: &[u8]) -> Vec<[u8; FRAME_SIZE]> {
        let mut frames = Vec::new();
        let total_len = payload.len();
        let mut offset = 0;

        let total_chunks = total_len.div_ceil(MAX_PAYLOAD_PER_FRAME);

        for chunk_idx in 0..std::cmp::max(1, total_chunks) {
            let mut frame = [0u8; FRAME_SIZE];
            let end = std::cmp::min(offset + MAX_PAYLOAD_PER_FRAME, total_len);
            let chunk_data = if offset < total_len {
                &payload[offset..end]
            } else {
                &[]
            };

            // En-tête : [Chunk Index (2B) | Total Chunks (2B) | Data Len (2B) | Flags (2B)]
            let chunk_len = chunk_data.len() as u16;
            frame[0..2].copy_from_slice(&(chunk_idx as u16).to_be_bytes());
            frame[2..4].copy_from_slice(&(total_chunks as u16).to_be_bytes());
            frame[4..6].copy_from_slice(&chunk_len.to_be_bytes());
            frame[6..8].copy_from_slice(&[0x00, 0x00]); // Reserved/Flags

            if chunk_len > 0 {
                frame[PAYLOAD_HEADER_LEN..PAYLOAD_HEADER_LEN + chunk_data.len()]
                    .copy_from_slice(chunk_data);
            }

            // Remplissage CSPRNG du reste de la trame jusqu'à 512 octets.
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

// =========================================================================
// Tests
// =========================================================================

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

    /// Vérifie que le stripping EXIF est **réel** : on injecte deux segments
    /// APP1 (EXIF) entre le SOI et le SOS, et on vérifie qu'ils ne sont plus
    /// présents dans la sortie.
    #[test]
    fn test_jpeg_stripping_removes_app_segments() {
        // Faux JPEG minimal :
        //   SOI (FF D8)
        //   APP1 (FF E1 00 10 <14 bytes "EXIF\0\0fake-exif!" >)
        //   APP0 (FF E0 00 04 <2 bytes>)
        //   SOS (FF DA 00 02)
        //   data entropique (2 bytes quelconques)
        //   EOI (FF D9)
        let mut jpeg: Vec<u8> = Vec::new();
        jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI

        // APP1 EXIF (à supprimer)
        jpeg.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x10]);
        jpeg.extend_from_slice(b"EXIF\x00\x00fake-exif!"); // 14 octets

        // APP0 JFIF (à conserver)
        jpeg.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x04, 0x4A, 0x46]);

        // COM (à supprimer)
        jpeg.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x06, b'h', b'e', b'l', b'l']);

        // SOS + data
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0xAA, 0xBB]);
        // EOI
        jpeg.extend_from_slice(&[0xFF, 0xD9]);

        let stripped = MediaStripper::strip_jpeg_app_segments(&jpeg);

        // Doit être plus court.
        assert!(stripped.len() < jpeg.len(), "stripping n'a rien retiré");

        // L'EXIF doit avoir disparu.
        assert!(
            !stripped.windows(4).any(|w| w == b"EXIF"),
            "APP1/EXIF n'a pas été retiré"
        );

        // Le commentaire doit avoir disparu.
        assert!(
            !stripped.windows(4).any(|w| w == b"hell"),
            "COM n'a pas été retiré"
        );

        // APP0/JFIF doit être conservé.
        assert!(
            stripped.windows(2).any(|w| w == [0xFF, 0xE0]),
            "APP0/JFIF a été supprimé à tort"
        );

        // Le SOI / SOS / EOI doivent rester.
        assert_eq!(&stripped[0..2], &[0xFF, 0xD8], "SOI perdu");
        assert!(
            stripped.windows(2).any(|w| w == [0xFF, 0xDA]),
            "SOS perdu"
        );
        assert!(
            stripped.windows(2).any(|w| w == [0xFF, 0xD9]),
            "EOI perdu"
        );
    }
}