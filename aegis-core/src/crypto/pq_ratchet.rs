//! aegis-core/src/crypto/pq_ratchet.rs
//! C95 â€” Continuous Post-Quantum Double Ratchet (SPQR / ML-KEM-1024 Braid)
//!
//! Fournit la Post-Compromise Security (PCS) quantique continue a l'interieur
//! d'une session active en melangeant periodiquement un secret partage frais
//! ML-KEM-1024 (FIPS 203 pur Rust) dans la chaine racine HKDF-SHA384, tout en
//! fragmentant les cles EK/CT (1568 octets) en 4 cellules fixes de 512 octets.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CELL_BYTES: usize = 512;
pub const MLKEM1024_EK_BYTES: usize = 1568;
pub const MLKEM1024_DK_BYTES: usize = 3168;
pub const MLKEM1024_CT_BYTES: usize = 1568;
pub const SPQR_FRAG_PAYLOAD: usize = 480;
pub const SPQR_FRAG_COUNT: usize = 4; // 4 * 480 = 1920 >= 1568 octets

pub const CELL_KIND_SPQR_EK_FRAG: u8 = 0x51;
pub const CELL_KIND_SPQR_CT_FRAG: u8 = 0x52;
pub const CELL_KIND_SPQR_MSG: u8 = 0x53;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpqrError {
    InvalidFragment,
    InvalidKeyMaterial,
    CryptoFailure,
    PayloadTooLarge,
    EpochMismatch,
}

/// Reassembleur en RAM des 4 cellules fixes de 512 octets transportant EK ou CT (1568 B).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpqrFragmentAssembler {
    epoch: u32,
    kind: u8,
    received_mask: u8,
    buf: [u8; SPQR_FRAG_COUNT * SPQR_FRAG_PAYLOAD],
}

impl Default for SpqrFragmentAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl SpqrFragmentAssembler {
    pub const fn new() -> Self {
        Self {
            epoch: 0,
            kind: 0,
            received_mask: 0,
            buf: [0u8; SPQR_FRAG_COUNT * SPQR_FRAG_PAYLOAD],
        }
    }

    pub fn reset(&mut self) {
        self.buf.zeroize();
        self.epoch = 0;
        self.kind = 0;
        self.received_mask = 0;
    }

    /// Fragmente un objet de 1568 octets (EK ou CT ML-KEM-1024) en 4 cellules de 512 octets.
    pub fn split_1568_into_cells(
        kind: u8,
        epoch: u32,
        blob_1568: &[u8; 1568],
    ) -> [[u8; CELL_BYTES]; SPQR_FRAG_COUNT] {
        let mut out = [[0u8; CELL_BYTES]; SPQR_FRAG_COUNT];
        let mut pad_rng = [0u8; CELL_BYTES];

        for idx in 0..SPQR_FRAG_COUNT {
            let _ = getrandom::getrandom(&mut pad_rng);
            out[idx].copy_from_slice(&pad_rng);
            out[idx][0] = kind;
            out[idx][1] = idx as u8;
            out[idx][2] = SPQR_FRAG_COUNT as u8;
            out[idx][3] = 0xAE; // Magic v3.7 SPQR
            out[idx][4..8].copy_from_slice(&epoch.to_be_bytes());

            let start = idx * SPQR_FRAG_PAYLOAD;
            let remain = 1568usize.saturating_sub(start);
            let copy_len = remain.min(SPQR_FRAG_PAYLOAD);
            out[idx][8..10].copy_from_slice(&(copy_len as u16).to_be_bytes());
            if copy_len > 0 {
                out[idx][16..16 + copy_len].copy_from_slice(&blob_1568[start..start + copy_len]);
            }
        }
        pad_rng.zeroize();
        out
    }

    /// Ingere une cellule de 512 octets. Retourne `Some([u8; 1568])` des que les 4 fragments sont recus.
    pub fn ingest_cell(&mut self, cell: &[u8; CELL_BYTES]) -> Result<Option<[u8; 1568]>, SpqrError> {
        let kind = cell[0];
        if kind != CELL_KIND_SPQR_EK_FRAG && kind != CELL_KIND_SPQR_CT_FRAG {
            return Err(SpqrError::InvalidFragment);
        }
        let idx = cell[1] as usize;
        let total = cell[2] as usize;
        if cell[3] != 0xAE || total != SPQR_FRAG_COUNT || idx >= SPQR_FRAG_COUNT {
            return Err(SpqrError::InvalidFragment);
        }
        let epoch = u32::from_be_bytes([cell[4], cell[5], cell[6], cell[7]]);
        let copy_len = u16::from_be_bytes([cell[8], cell[9]]) as usize;
        if copy_len > SPQR_FRAG_PAYLOAD {
            return Err(SpqrError::InvalidFragment);
        }

        if self.received_mask == 0 || self.epoch != epoch || self.kind != kind {
            self.reset();
            self.epoch = epoch;
            self.kind = kind;
        }

        let start = idx * SPQR_FRAG_PAYLOAD;
        self.buf[start..start + copy_len].copy_from_slice(&cell[16..16 + copy_len]);
        self.received_mask |= 1u8 << idx;

        if self.received_mask == 0x0F {
            let mut full = [0u8; 1568];
            full.copy_from_slice(&self.buf[..1568]);
            self.reset();
            Ok(Some(full))
        } else {
            Ok(None)
        }
    }
}

/// Etat du cliquet Post-Quantique Continu SPQR en RAM volatile.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContinuousPqRatchet {
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    pending_dk_bytes: [u8; MLKEM1024_DK_BYTES],
    has_pending_dk: bool,
    pub pq_epoch: u32,
    pub send_seq: u32,
    pub recv_seq: u32,
    assembler: SpqrFragmentAssembler,
}

impl ContinuousPqRatchet {
    /// Initialise une session SPQR a partir d'un secret racine 32 octets (ex: sortie X3DH).
    pub fn new(initial_root: &[u8; 32], is_initiator: bool) -> Self {
        let hk = Hkdf::<Sha384>::new(Some(b"AEGIS-SPQR-INIT-v3.7"), initial_root);
        let mut okm = [0u8; 96];
        hk.expand(b"ROOT+CHAINS", &mut okm).expect("HKDF expand 96B");

        let mut rk = [0u8; 32];
        let mut c_a = [0u8; 32];
        let mut c_b = [0u8; 32];
        rk.copy_from_slice(&okm[0..32]);
        c_a.copy_from_slice(&okm[32..64]);
        c_b.copy_from_slice(&okm[64..96]);
        okm.zeroize();

        let (send_chain_key, recv_chain_key) = if is_initiator { (c_a, c_b) } else { (c_b, c_a) };

        Self {
            root_key: rk,
            send_chain_key,
            recv_chain_key,
            pending_dk_bytes: [0u8; MLKEM1024_DK_BYTES],
            has_pending_dk: false,
            pq_epoch: 0,
            send_seq: 0,
            recv_seq: 0,
            assembler: SpqrFragmentAssembler::new(),
        }
    }

    /// Etape 1 du re-encapsulage PCS : genere une nouvelle paire ephemere ML-KEM-1024
    /// et retourne les 4 cellules de 512 octets contenant EK pour envoi au pair.
    pub fn initiate_pq_step(&mut self) -> Result<[[u8; CELL_BYTES]; SPQR_FRAG_COUNT], SpqrError> {
        let (ek, dk) = ml_kem_1024::KG::try_keygen().map_err(|_| SpqrError::CryptoFailure)?;
        let ek_bytes = ek.into_bytes();
        let mut dk_bytes = dk.into_bytes();

        self.pending_dk_bytes.zeroize();
        self.pending_dk_bytes.copy_from_slice(&dk_bytes);
        dk_bytes.zeroize();
        self.has_pending_dk = true;

        let next_epoch = self.pq_epoch.wrapping_add(1);
        Ok(SpqrFragmentAssembler::split_1568_into_cells(
            CELL_KIND_SPQR_EK_FRAG,
            next_epoch,
            &ek_bytes,
        ))
    }

    /// Ingere une cellule EK ou CT de 512 octets.
    /// - Si 4 fragments EK sont complets : encapsule un secret ML-KEM-1024, fait tourner le RootKey
    ///   et retourne `Some(4 cellules CT de 512B)` a renvoyer immediatement.
    /// - Si 4 fragments CT sont complets : decapsule avec `pending_dk`, purge `pending_dk` (PCS!),
    ///   fait tourner le RootKey et retourne `Ok(None)`.
    pub fn process_control_cell(
        &mut self,
        cell: &[u8; CELL_BYTES],
    ) -> Result<Option<[[u8; CELL_BYTES]; SPQR_FRAG_COUNT]>, SpqrError> {
        let kind = cell[0];
        let cell_epoch = u32::from_be_bytes([cell[4], cell[5], cell[6], cell[7]]);
        let Some(mut blob_1568) = self.assembler.ingest_cell(cell)? else {
            return Ok(None);
        };

        if kind == CELL_KIND_SPQR_EK_FRAG {
            let ek = ml_kem_1024::EncapsKey::try_from_bytes(blob_1568)
                .map_err(|_| SpqrError::InvalidKeyMaterial)?;
            blob_1568.zeroize();
            let (ssk, ct) = ek.try_encaps().map_err(|_| SpqrError::CryptoFailure)?;
            let mut ss_bytes = ssk.into_bytes();
            let ct_bytes = ct.into_bytes();

            self.ratchet_root_with_pq_secret(&ss_bytes, false);
            ss_bytes.zeroize();
            self.pq_epoch = cell_epoch;

            let reply_cells = SpqrFragmentAssembler::split_1568_into_cells(
                CELL_KIND_SPQR_CT_FRAG,
                cell_epoch,
                &ct_bytes,
            );
            Ok(Some(reply_cells))
        } else if kind == CELL_KIND_SPQR_CT_FRAG {
            if !self.has_pending_dk {
                blob_1568.zeroize();
                return Err(SpqrError::EpochMismatch);
            }
            let mut dk_copy = [0u8; MLKEM1024_DK_BYTES];
            dk_copy.copy_from_slice(&self.pending_dk_bytes);
            // Destruction immediate de la cle privee ephemere avant meme utilisation reseau (PCS!)
            self.pending_dk_bytes.zeroize();
            self.has_pending_dk = false;

            let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_copy)
                .map_err(|_| SpqrError::InvalidKeyMaterial)?;
            dk_copy.zeroize();
            let ct = ml_kem_1024::CipherText::try_from_bytes(blob_1568)
                .map_err(|_| SpqrError::InvalidKeyMaterial)?;
            blob_1568.zeroize();

            let ssk = dk.try_decaps(&ct).map_err(|_| SpqrError::CryptoFailure)?;
            let mut ss_bytes = ssk.into_bytes();
            self.ratchet_root_with_pq_secret(&ss_bytes, true);
            ss_bytes.zeroize();
            self.pq_epoch = cell_epoch;
            Ok(None)
        } else {
            blob_1568.zeroize();
            Err(SpqrError::InvalidFragment)
        }
    }

    fn ratchet_root_with_pq_secret(&mut self, pq_ss: &[u8; 32], initiator_side: bool) {
        let hk = Hkdf::<Sha384>::new(Some(&self.root_key), pq_ss);
        let mut okm = [0u8; 96];
        hk.expand(b"AEGIS-SPQR-EPOCH-RATCHET-v3.7", &mut okm)
            .expect("HKDF expand 96B");
        self.root_key.copy_from_slice(&okm[0..32]);
        if initiator_side {
            self.send_chain_key.copy_from_slice(&okm[32..64]);
            self.recv_chain_key.copy_from_slice(&okm[64..96]);
        } else {
            self.recv_chain_key.copy_from_slice(&okm[32..64]);
            self.send_chain_key.copy_from_slice(&okm[64..96]);
        }
        okm.zeroize();
        self.send_seq = 0;
        self.recv_seq = 0;
    }

    fn advance_chain(chain_key: &mut [u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"AEGIS-SPQR-CHAIN"), chain_key);
        let mut okm = [0u8; 64];
        hk.expand(b"NEXT-CK+MSG-KEY", &mut okm)
            .expect("HKDF expand 64B");
        chain_key.copy_from_slice(&okm[0..32]);
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&okm[32..64]);
        okm.zeroize();
        mk
    }

    /// Chiffre un message applicatif (<= 468 octets) dans une cellule fixe de 512 octets.
    pub fn seal_cell(&mut self, plaintext: &[u8]) -> Result<[u8; CELL_BYTES], SpqrError> {
        const MAX_PT: usize = CELL_BYTES - 16 - 12 - 16; // 468 octets utiles
        if plaintext.len() > MAX_PT {
            return Err(SpqrError::PayloadTooLarge);
        }
        let mut mk = Self::advance_chain(&mut self.send_chain_key);
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);

        let mut cell = [0u8; CELL_BYTES];
        let _ = getrandom::getrandom(&mut cell);
        cell[0] = CELL_KIND_SPQR_MSG;
        cell[1] = 0xAE;
        cell[2..4].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
        cell[4..8].copy_from_slice(&self.pq_epoch.to_be_bytes());
        cell[8..12].copy_from_slice(&seq.to_be_bytes());

        let mut nonce_bytes = [0u8; 12];
        let _ = getrandom::getrandom(&mut nonce_bytes);
        cell[16..28].copy_from_slice(&nonce_bytes);

        let mut padded_pt = [0u8; MAX_PT];
        padded_pt[..plaintext.len()].copy_from_slice(plaintext);
        if plaintext.len() < MAX_PT {
            padded_pt[plaintext.len()..].copy_from_slice(&cell[28 + plaintext.len()..28 + MAX_PT]);
        }

        let cipher = ChaCha20Poly1305::new((&mk).into());
        mk.zeroize();

        let aad = &cell[0..16];
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &padded_pt,
                    aad,
                },
            )
            .map_err(|_| SpqrError::CryptoFailure)?;
        padded_pt.zeroize();

        cell[28..28 + ct.len()].copy_from_slice(&ct);
        Ok(cell)
    }

    /// Dechiffre et authentifie une cellule de 512 octets issue de `seal_cell`.
    pub fn open_cell(&mut self, cell: &[u8; CELL_BYTES]) -> Result<Vec<u8>, SpqrError> {
        const MAX_PT: usize = CELL_BYTES - 16 - 12 - 16;
        if cell[0] != CELL_KIND_SPQR_MSG || cell[1] != 0xAE {
            return Err(SpqrError::InvalidFragment);
        }
        let pt_len = u16::from_be_bytes([cell[2], cell[3]]) as usize;
        if pt_len > MAX_PT {
            return Err(SpqrError::PayloadTooLarge);
        }
        let msg_epoch = u32::from_be_bytes([cell[4], cell[5], cell[6], cell[7]]);
        if msg_epoch != self.pq_epoch {
            return Err(SpqrError::EpochMismatch);
        }

        let mut mk = Self::advance_chain(&mut self.recv_chain_key);
        self.recv_seq = self.recv_seq.wrapping_add(1);

        let nonce = Nonce::from_slice(&cell[16..28]);
        let aad = &cell[0..16];
        let ct_slice = &cell[28..28 + MAX_PT + 16];

        let cipher = ChaCha20Poly1305::new((&mk).into());
        mk.zeroize();

        let mut dec = cipher
            .decrypt(nonce, Payload { msg: ct_slice, aad })
            .map_err(|_| SpqrError::CryptoFailure)?;
        let out = dec[..pt_len].to_vec();
        dec.zeroize();
        Ok(out)
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_spqr_assembler_never_panics_on_arbitrary_cell() {
        let mut cell = [0u8; CELL_BYTES];
        cell[0] = kani::any();
        cell[1] = kani::any();
        cell[2] = kani::any();
        cell[3] = kani::any();
        cell[8] = kani::any();
        cell[9] = kani::any();
        let mut asm = SpqrFragmentAssembler::new();
        let _ = asm.ingest_cell(&cell);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spqr_fragment_split_and_reassemble_miri_safe() {
        let mut fake_ek = [0u8; 1568];
        for (i, b) in fake_ek.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        let cells = SpqrFragmentAssembler::split_1568_into_cells(CELL_KIND_SPQR_EK_FRAG, 7, &fake_ek);
        let mut asm = SpqrFragmentAssembler::new();
        assert!(asm.ingest_cell(&cells[2]).unwrap().is_none());
        assert!(asm.ingest_cell(&cells[0]).unwrap().is_none());
        assert!(asm.ingest_cell(&cells[3]).unwrap().is_none());
        let rebuilt = asm.ingest_cell(&cells[1]).unwrap().expect("4/4 complete");
        assert_eq!(rebuilt, fake_ek);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_continuous_pq_ratchet_pcs_healing_after_state_compromise() {
        let root = [0x42u8; 32];
        let mut alice = ContinuousPqRatchet::new(&root, true);
        let mut bob = ContinuousPqRatchet::new(&root, false);

        // Echange initial Epoque 0
        let c0 = alice.seal_cell(b"MSG_EPOCH_0").unwrap();
        assert_eq!(bob.open_cell(&c0).unwrap(), b"MSG_EPOCH_0");

        // Simulation d'un attaquant qui vole root_key + chain_keys d'Alice/Bob a l'epoque 0
        let mut attacker_clone_of_bob = ContinuousPqRatchet::new(&root, false);
        let _ = attacker_clone_of_bob.open_cell(&c0).unwrap();

        // Alice declenche un re-encapsulage ML-KEM-1024 continu (Epoque 1) en 4 cellules de 512 B
        let ek_cells = alice.initiate_pq_step().unwrap();
        let mut ct_reply = None;
        for cell in &ek_cells {
            if let Some(reply) = bob.process_control_cell(cell).unwrap() {
                ct_reply = Some(reply);
            }
        }
        let ct_cells = ct_reply.expect("Bob encapsule ML-KEM-1024");
        for cell in &ct_cells {
            assert!(alice.process_control_cell(cell).unwrap().is_none());
        }
        assert_eq!(alice.pq_epoch, 1);
        assert_eq!(bob.pq_epoch, 1);

        // Nouveau message sous Epoque 1 : Bob dechiffre, mais le clone attaquant est aveugle (PCS Quantique!)
        let c1 = alice.seal_cell(b"TOP_SECRET_POST_COMPROMISE").unwrap();
        assert_eq!(bob.open_cell(&c1).unwrap(), b"TOP_SECRET_POST_COMPROMISE");
        assert!(attacker_clone_of_bob.open_cell(&c1).is_err());
    }
}
