//! aegis-core/src/network/optical_fountain.rs
//! Chantier C92 Ã¢â‚¬â€ Canal Optique Air-Gap ("0-RF Fountain QR Codes").
//! Permet ÃƒÂ  deux smartphones en Mode Avion strict (0 ÃƒÂ©mission Wi-Fi / BLE / GSM)
//! d'ÃƒÂ©changer un message chiffrÃƒÂ© ou un fichier via un flux cyclique de QR codes animÃƒÂ©s
//! rÃƒÂ©sistant aux trames manquÃƒÂ©es par la camÃƒÂ©ra (dÃƒÂ©codage par pelage / Peeling XOR).

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const OPTICAL_SLICE_BYTES: usize = 160;
pub const OPTICAL_MAGIC: [u8; 2] = [0xAE, 0x0F];

/// Une goutte optique ("Droplet") prÃƒÂªte ÃƒÂ  ÃƒÂªtre encodÃƒÂ©e en Base64 dans un QR Code individuel.
#[derive(Clone, Debug)]
pub struct OpticalDroplet {
    pub transfer_id: [u8; 4],
    pub total_blocks: u16,
    pub total_payload_len: u32,
    pub indices: Vec<u16>,
    pub xored_block: [u8; OPTICAL_SLICE_BYTES],
    pub crc_sha256_4b: [u8; 4],
}

impl Drop for OpticalDroplet {
    fn drop(&mut self) {
        self.xored_block.zeroize();
    }
}

impl OpticalDroplet {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.indices.len() * 2 + OPTICAL_SLICE_BYTES);
        out.extend_from_slice(&OPTICAL_MAGIC);
        out.extend_from_slice(&self.transfer_id);
        out.extend_from_slice(&self.total_blocks.to_be_bytes());
        out.extend_from_slice(&self.total_payload_len.to_be_bytes());
        out.push(self.indices.len() as u8);
        for &idx in &self.indices {
            out.extend_from_slice(&idx.to_be_bytes());
        }
        out.extend_from_slice(&self.xored_block);

        let mut h = Sha256::new();
        h.update(&out);
        let digest = h.finalize();
        out.extend_from_slice(&digest[0..4]);
        out
    }

    pub fn from_wire_bytes(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 13 + OPTICAL_SLICE_BYTES + 4 {
            return Err("AEGIS_OPTICAL_DROPLET_TOO_SHORT");
        }
        if raw[0..2] != OPTICAL_SLICE_BYTES.to_be_bytes() && raw[0..2] != OPTICAL_MAGIC {
            return Err("AEGIS_OPTICAL_BAD_MAGIC");
        }
        let body_end = raw.len() - 4;
        let mut h = Sha256::new();
        h.update(&raw[..body_end]);
        let digest = h.finalize();
        if digest[0..4] != raw[body_end..] {
            return Err("AEGIS_OPTICAL_CRC_MISMATCH");
        }

        let mut transfer_id = [0u8; 4];
        transfer_id.copy_from_slice(&raw[2..6]);
        let total_blocks = u16::from_be_bytes([raw[6], raw[7]]);
        let total_payload_len = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let deg = raw[12] as usize;
        if deg == 0 || deg > 8 || total_blocks == 0 {
            return Err("AEGIS_OPTICAL_INVALID_DEGREE");
        }
        let expected_len = 13 + deg * 2 + OPTICAL_SLICE_BYTES + 4;
        if raw.len() != expected_len {
            return Err("AEGIS_OPTICAL_LEN_MISMATCH");
        }

        let mut indices = Vec::with_capacity(deg);
        let mut pos = 13;
        for _ in 0..deg {
            let idx = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
            if idx >= total_blocks {
                return Err("AEGIS_OPTICAL_INDEX_OOB");
            }
            indices.push(idx);
            pos += 2;
        }

        let mut xored_block = [0u8; OPTICAL_SLICE_BYTES];
        xored_block.copy_from_slice(&raw[pos..pos + OPTICAL_SLICE_BYTES]);
        let mut crc_sha256_4b = [0u8; 4];
        crc_sha256_4b.copy_from_slice(&raw[body_end..]);

        Ok(Self {
            transfer_id,
            total_blocks,
            total_payload_len,
            indices,
            xored_block,
            crc_sha256_4b,
        })
    }
}

/// GÃƒÂ©nÃƒÂ¨re un train de gouttes optiques systÃƒÂ©matiques + paritÃƒÂ© XOR (redondance 1.5x)
/// permettant de reconstruire le payload mÃƒÂªme si la camÃƒÂ©ra rate des QR codes ÃƒÂ  l'ÃƒÂ©cran.
pub fn encode_optical_fountain_stream(
    transfer_id: [u8; 4],
    ciphertext: &[u8],
) -> Result<Vec<Vec<u8>>, &'static str> {
    if ciphertext.is_empty() || ciphertext.len() > 262_144 {
        return Err("AEGIS_OPTICAL_INVALID_PAYLOAD_SIZE");
    }
    let total_blocks = ((ciphertext.len() + OPTICAL_SLICE_BYTES - 1) / OPTICAL_SLICE_BYTES) as u16;
    let mut blocks: Vec<[u8; OPTICAL_SLICE_BYTES]> = Vec::with_capacity(total_blocks as usize);

    for chunk in ciphertext.chunks(OPTICAL_SLICE_BYTES) {
        let mut b = [0u8; OPTICAL_SLICE_BYTES];
        b[..chunk.len()].copy_from_slice(chunk);
        blocks.push(b);
    }

    let mut frames = Vec::with_capacity((total_blocks as usize) * 2);

    // Passe 1 : gouttes de degrÃƒÂ© 1 (systÃƒÂ©matiques)
    for i in 0..total_blocks {
        let d = OpticalDroplet {
            transfer_id,
            total_blocks,
            total_payload_len: ciphertext.len() as u32,
            indices: vec![i],
            xored_block: blocks[i as usize],
            crc_sha256_4b: [0u8; 4],
        };
        frames.push(d.to_wire_bytes());
    }

    // Passe 2 : gouttes de rÃƒÂ©paration XOR degrÃƒÂ© 2 (rÃƒÂ©cupÃƒÂ©ration immÃƒÂ©diate si une trame est ratÃƒÂ©e)
    if total_blocks > 1 {
        for i in 0..total_blocks {
            let j = (i + 1) % total_blocks;
            let mut xored = blocks[i as usize];
            for k in 0..OPTICAL_SLICE_BYTES {
                xored[k] ^= blocks[j as usize][k];
            }
            let d = OpticalDroplet {
                transfer_id,
                total_blocks,
                total_payload_len: ciphertext.len() as u32,
                indices: vec![i, j],
                xored_block: xored,
                crc_sha256_4b: [0u8; 4],
            };
            frames.push(d.to_wire_bytes());
        }
    }

    for b in blocks.iter_mut() {
        b.zeroize();
    }
    Ok(frames)
}

/// DÃƒÂ©codeur par pelage (Belief Propagation / Peeling Decoder) 100 % en RAM.
pub struct OpticalFountainDecoder {
    transfer_id: Option<[u8; 4]>,
    total_blocks: u16,
    total_len: usize,
    solved: Vec<Option<[u8; OPTICAL_SLICE_BYTES]>>,
    pending: Vec<OpticalDroplet>,
}

impl Default for OpticalFountainDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl OpticalFountainDecoder {
    pub fn new() -> Self {
        Self {
            transfer_id: None,
            total_blocks: 0,
            total_len: 0,
            solved: Vec::new(),
            pending: Vec::new(),
        }
    }

    pub fn ingest_wire_droplet(&mut self, raw: &[u8]) -> Result<bool, &'static str> {
        let mut droplet = OpticalDroplet::from_wire_bytes(raw)?;

        if self.transfer_id.is_none() {
            self.transfer_id = Some(droplet.transfer_id);
            self.total_blocks = droplet.total_blocks;
            self.total_len = droplet.total_payload_len as usize;
            self.solved = vec![None; droplet.total_blocks as usize];
        } else if self.transfer_id != Some(droplet.transfer_id) {
            return Err("AEGIS_OPTICAL_TRANSFER_ID_MISMATCH");
        }

        // RÃƒÂ©duit la goutte avec les blocs dÃƒÂ©jÃƒÂ  rÃƒÂ©solus
        let mut unknown_indices = Vec::new();
        for &idx in &droplet.indices {
            if let Some(known) = &self.solved[idx as usize] {
                for k in 0..OPTICAL_SLICE_BYTES {
                    droplet.xored_block[k] ^= known[k];
                }
            } else {
                unknown_indices.push(idx);
            }
        }
        droplet.indices = unknown_indices;

        if droplet.indices.len() == 1 {
            let solved_idx = droplet.indices[0] as usize;
            self.solved[solved_idx] = Some(droplet.xored_block);
            self.propagate_peeling();
        } else if droplet.indices.len() > 1 {
            self.pending.push(droplet);
        }

        Ok(self.is_complete())
    }

    fn propagate_peeling(&mut self) {
        let mut progress = true;
        while progress {
            progress = false;
            let mut still_pending = Vec::new();
            for mut d in self.pending.drain(..) {
                let mut rem = Vec::new();
                for &idx in &d.indices {
                    if let Some(known) = &self.solved[idx as usize] {
                        for k in 0..OPTICAL_SLICE_BYTES {
                            d.xored_block[k] ^= known[k];
                        }
                    } else {
                        rem.push(idx);
                    }
                }
                d.indices = rem;
                if d.indices.len() == 1 {
                    let s_idx = d.indices[0] as usize;
                    if self.solved[s_idx].is_none() {
                        self.solved[s_idx] = Some(d.xored_block);
                        progress = true;
                    }
                } else if d.indices.len() > 1 {
                    still_pending.push(d);
                }
            }
            self.pending = still_pending;
        }
    }

    pub fn is_complete(&self) -> bool {
        !self.solved.is_empty() && self.solved.iter().all(|b| b.is_some())
    }

    pub fn finalize_and_wipe(&mut self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut full = Vec::with_capacity(self.total_blocks as usize * OPTICAL_SLICE_BYTES);
        for slot in self.solved.iter_mut() {
            if let Some(mut blk) = slot.take() {
                full.extend_from_slice(&blk);
                blk.zeroize();
            }
        }
        full.truncate(self.total_len);
        self.wipe();
        Some(full)
    }

    pub fn wipe(&mut self) {
        for slot in self.solved.iter_mut() {
            if let Some(mut b) = slot.take() {
                b.zeroize();
            }
        }
        self.solved.clear();
        self.pending.clear();
        self.transfer_id = None;
    }
}


lazy_static::lazy_static! {
    pub static ref GLOBAL_OPTICAL_DECODER: std::sync::Mutex<OpticalFountainDecoder> =
        std::sync::Mutex::new(OpticalFountainDecoder::new());
}

pub fn wipe_global_optical() {
    if let Ok(mut dec) = GLOBAL_OPTICAL_DECODER.lock() {
        dec.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optical_fountain_recovers_dropped_qr_frame() {
        let payload = vec![0x5Au8; 400]; // 3 blocs de 160 octets
        let frames = encode_optical_fountain_stream([1, 2, 3, 4], &payload).unwrap();
        assert_eq!(frames.len(), 6); // 3 systÃƒÂ©matiques + 3 paritÃƒÂ©s XOR

        let mut dec = OpticalFountainDecoder::new();
        // Simule la perte du QR code #1 par la camÃƒÂ©ra !
        assert!(!dec.ingest_wire_droplet(&frames[0]).unwrap()); // bloc 0
        // frames[1] (bloc 1) PERDU !
        assert!(!dec.ingest_wire_droplet(&frames[2]).unwrap()); // bloc 2
        // RÃƒÂ©ception de la goutte de paritÃƒÂ© frames[3] (bloc 0 XOR bloc 1) -> reconstruit bloc 1 !
        assert!(dec.ingest_wire_droplet(&frames[3]).unwrap());

        let recovered = dec.finalize_and_wipe().unwrap();
        assert_eq!(recovered, payload);
    }
}