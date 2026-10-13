// src/network/ble_mesh_fragment.rs
//
// P0-A.3d.2 (2026-10-13) — MeshFragmenter + MeshReassembler.
//
// =====================================================================
// MODÈLE DE SÉCURITÉ — Hiérarchie à 3 niveaux (Q11-bis / D82)
// =====================================================================
//
// 1. Dédup mesh (ble_mesh_frame.rs, best-effort, anti-DoS, RAM bornée)
// 2. Ratchet replay window (F4, AUTORITAIRE, rejette tout rejeu ciphertext)
// 3. Handshake ed25519 (P0-A.3e, AUTORITAIRE, empêche device non-auth)
//
// Un attaquant peut forger le header MeshFrame (non signé). Il ne peut PAS :
//   - Faire accepter un payload forgé (AEAD ratchet rejette)
//   - Impersonner un sender légitime (handshake rejette au niveau session)
//   - Amplifier le TTL au-delà de 5 (clamp D79)
//
// Il PEUT :
//   - Générer du bruit réseau (flooding de fragments invalides)
//   - Tenter le DoS par réassemblage (mitigé par bornes Q10-bis / D81)
//   - Saturer le buffer de dédup (mitigé par purge TTL 60s)
//
// =====================================================================
// FORMAT DE FRAGMENT (fixe, 8 octets header)
// =====================================================================
//
//   offset  taille  champ
//   0       4       frame_id  (u32 BE) — identifiant du MeshFrame parent
//   4       2       frag_idx  (u16 BE) — index du fragment, 0-based
//   6       2       frag_total(u16 BE) — nombre total de fragments
//   8       N       payload   (N ≤ 236 octets)
//
// =====================================================================
// Q8 clarification : 244 = taille TOTALE max d'un fragment (header inclus).
//                    payload utile = 244 - 8 = 236 octets.
// =====================================================================

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────
// Constantes (Q8, Q10, Q10-bis)
// ─────────────────────────────────────────────────────────────────────

/// Taille fixe du header de fragment.
pub const FRAGMENT_HEADER_SIZE: usize = 8;

/// Taille TOTALE max d'un fragment sur le fil (header inclus, Q8).
pub const FRAGMENT_MAX_WIRE_SIZE: usize = 244;

/// Payload utile max par fragment (Q8 : 244 - 8 = 236).
pub const FRAGMENT_MAX_PAYLOAD: usize = FRAGMENT_MAX_WIRE_SIZE - FRAGMENT_HEADER_SIZE;

/// Nombre maximum de fragments par frame (Q10-bis, D81).
pub const MAX_FRAGMENTS_PER_FRAME: u16 = 32;

/// Nombre maximum de réassemblages concurrents (Q10-bis, D81).
pub const MAX_CONCURRENT_REASSEMBLIES: usize = 4;

/// Somme cumulée max de bytes en cours de réassemblage (Q10-bis, D81).
pub const MAX_TOTAL_REASSEMBLY_BYTES: usize = 32 * 1024;

/// Timeout d'un réassemblage partiel (Q10, D41).
pub const REASSEMBLY_TIMEOUT_SECS: u64 = 30;

// ─────────────────────────────────────────────────────────────────────
// Erreurs typées
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentError {
    /// Payload > FRAGMENT_MAX_PAYLOAD.
    PayloadTooLarge,
    /// frag_total > MAX_FRAGMENTS_PER_FRAME.
    TooManyFragments,
}

impl FragmentError {
    pub fn to_code(self) -> i32 {
        match self {
            FragmentError::PayloadTooLarge => -20,
            FragmentError::TooManyFragments => -21,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyError {
    /// Header de fragment tronqué.
    TooShort,
    /// frag_idx >= frag_total (incohérent).
    IdxOutOfRange,
    /// frag_total == 0 (incohérent).
    ZeroTotal,
    /// frag_total > MAX_FRAGMENTS_PER_FRAME (Q10-bis).
    TooManyFragments,
    /// Nombre de réassemblages concurrents dépassé (Q10-bis).
    TooManyConcurrent,
    /// Somme cumulée > MAX_TOTAL_REASSEMBLY_BYTES (Q10-bis).
    TotalBytesExceeded,
}

impl ReassemblyError {
    pub fn to_code(self) -> i32 {
        match self {
            ReassemblyError::TooShort => -30,
            ReassemblyError::IdxOutOfRange => -31,
            ReassemblyError::ZeroTotal => -32,
            ReassemblyError::TooManyFragments => -33,
            ReassemblyError::TooManyConcurrent => -34,
            ReassemblyError::TotalBytesExceeded => -35,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// MeshFragment
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshFragment {
    pub frame_id: u32,
    pub frag_idx: u16,
    pub frag_total: u16,
    pub payload: Vec<u8>,
}

impl MeshFragment {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.frame_id.to_be_bytes());
        out.extend_from_slice(&self.frag_idx.to_be_bytes());
        out.extend_from_slice(&self.frag_total.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ReassemblyError> {
        if bytes.len() < FRAGMENT_HEADER_SIZE {
            return Err(ReassemblyError::TooShort);
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&bytes[0..4]);
        let frame_id = u32::from_be_bytes(id);

        let mut idx = [0u8; 2];
        idx.copy_from_slice(&bytes[4..6]);
        let frag_idx = u16::from_be_bytes(idx);

        let mut tot = [0u8; 2];
        tot.copy_from_slice(&bytes[6..8]);
        let frag_total = u16::from_be_bytes(tot);

        if frag_total == 0 {
            return Err(ReassemblyError::ZeroTotal);
        }
        if frag_idx >= frag_total {
            return Err(ReassemblyError::IdxOutOfRange);
        }

        let payload = bytes[FRAGMENT_HEADER_SIZE..].to_vec();
        Ok(Self {
            frame_id,
            frag_idx,
            frag_total,
            payload,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// MeshFragmenter (Q8)
// ─────────────────────────────────────────────────────────────────────

pub struct MeshFragmenter;

impl MeshFragmenter {
    /// Découpe `frame_bytes` en fragments de payload ≤ 236 octets.
    ///
    /// Retourne une erreur si la fragmentation produirait
    /// > MAX_FRAGMENTS_PER_FRAME fragments.
    pub fn fragment(
        frame_bytes: &[u8],
        frame_id: u32,
    ) -> Result<Vec<MeshFragment>, FragmentError> {
        if frame_bytes.is_empty() {
            // Cas limite : un frame vide = 1 fragment à payload vide.
            return Ok(vec![MeshFragment {
                frame_id,
                frag_idx: 0,
                frag_total: 1,
                payload: Vec::new(),
            }]);
        }

        let total = frame_bytes.len().div_ceil(FRAGMENT_MAX_PAYLOAD);
        if total > MAX_FRAGMENTS_PER_FRAME as usize {
            return Err(FragmentError::TooManyFragments);
        }

        let mut fragments = Vec::with_capacity(total);
        for (idx, chunk) in frame_bytes.chunks(FRAGMENT_MAX_PAYLOAD).enumerate() {
            fragments.push(MeshFragment {
                frame_id,
                frag_idx: idx as u16,
                frag_total: total as u16,
                payload: chunk.to_vec(),
            });
        }
        Ok(fragments)
    }
}

// ─────────────────────────────────────────────────────────────────────
// MeshReassembler (Q10, Q10-bis, Q12)
// ─────────────────────────────────────────────────────────────────────

struct PartialFrame {
    frag_total: u16,
    received_mask: u32,       // bit i = fragment i reçu (max 32 fragments)
    fragments: Vec<Option<Vec<u8>>>,
    total_bytes: usize,
    started_at: Instant,
}

impl PartialFrame {
    fn new(frag_total: u16, now: Instant) -> Self {
        Self {
            frag_total,
            received_mask: 0,
            fragments: vec![None; frag_total as usize],
            total_bytes: 0,
            started_at: now,
        }
    }

    fn is_complete(&self) -> bool {
        let full_mask: u32 = if self.frag_total == 32 {
            0xFFFF_FFFF
        } else {
            (1u32 << self.frag_total) - 1
        };
        self.received_mask == full_mask
    }
}

pub struct MeshReassembler {
    partials: HashMap<u32, PartialFrame>,
    timeout: Duration,
}

impl MeshReassembler {
    pub fn new() -> Self {
        Self {
            partials: HashMap::new(),
            timeout: Duration::from_secs(REASSEMBLY_TIMEOUT_SECS),
        }
    }

    /// Insère un fragment. Retourne `Some(bytes)` si le frame est complet.
    ///
    /// `now` injecté pour testabilité.
    pub fn insert(
        &mut self,
        frag: MeshFragment,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, ReassemblyError> {
        // Q10-bis : bornes de sécurité AVANT toute allocation.
        if frag.frag_total == 0 {
            return Err(ReassemblyError::ZeroTotal);
        }
        if frag.frag_total > MAX_FRAGMENTS_PER_FRAME {
            return Err(ReassemblyError::TooManyFragments);
        }
        if frag.frag_idx >= frag.frag_total {
            return Err(ReassemblyError::IdxOutOfRange);
        }

        // Purge des timeout expirés.
        self.purge_expired(now);

        // Si le frame_id est déjà en cours → OK.
        // Sinon, vérifier les bornes concurrentes.
        if !self.partials.contains_key(&frag.frame_id) {
            if self.partials.len() >= MAX_CONCURRENT_REASSEMBLIES {
                return Err(ReassemblyError::TooManyConcurrent);
            }
            // Vérifier la borne bytes totale.
            let new_total = self.total_bytes() + frag.payload.len();
            if new_total > MAX_TOTAL_REASSEMBLY_BYTES {
                return Err(ReassemblyError::TotalBytesExceeded);
            }
            self.partials.insert(
                frag.frame_id,
                PartialFrame::new(frag.frag_total, now),
            );
        }

        // Fix E0502 : calculer existing_total AVANT le get_mut
        // (évite le conflit borrow immutable/mutable).
        let existing_total = self.total_bytes_excluding(&frag.frame_id);

        let partial = self.partials.get_mut(&frag.frame_id).unwrap();

        // frag_total incohérent avec un état partiel existant → drop.
        if partial.frag_total != frag.frag_total {
            return Err(ReassemblyError::ZeroTotal); // simplification : toute incohérence = drop
        }

        let idx = frag.frag_idx as usize;
        if partial.fragments[idx].is_some() {
            // Duplicat au niveau fragment → ignoré silencieusement.
            // (La dédup frame est gérée en aval par MeshDeduplicator.)
            return Ok(None);
        }

        // Vérifier la borne bytes cumulée pour cette insertion.
        let new_total_bytes = partial.total_bytes + frag.payload.len();
        let global_total = existing_total + new_total_bytes;
        if global_total > MAX_TOTAL_REASSEMBLY_BYTES {
            return Err(ReassemblyError::TotalBytesExceeded);
        }

        partial.fragments[idx] = Some(frag.payload);
        partial.total_bytes = new_total_bytes;
        partial.received_mask |= 1u32 << idx;

        if partial.is_complete() {
            // Extraction + suppression.
            let partial = self.partials.remove(&frag.frame_id).unwrap();
            let mut out = Vec::with_capacity(partial.total_bytes);
            for p in partial.fragments {
                out.extend_from_slice(&p.expect("is_complete ⇒ tous les fragments présents"));
            }
            return Ok(Some(out));
        }

        Ok(None)
    }

    fn total_bytes(&self) -> usize {
        self.partials.values().map(|p| p.total_bytes).sum()
    }

    fn total_bytes_excluding(&self, frame_id: &u32) -> usize {
        self.partials
            .iter()
            .filter(|(k, _)| *k != frame_id)
            .map(|(_, p)| p.total_bytes)
            .sum()
    }

    pub fn purge_expired(&mut self, now: Instant) {
        let ttl = self.timeout;
        self.partials
            .retain(|_, p| now.duration_since(p.started_at) < ttl);
    }

    /// Vide entièrement (Q12 / D83 — appelé sur shutdown).
    pub fn clear(&mut self) {
        self.partials.clear();
    }

    pub fn len(&self) -> usize {
        self.partials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }
}

impl Default for MeshReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MeshFragmenter tests (5) ────────────────────────────────────

    #[test]
    fn test_fragmenter_small_payload_single_fragment() {
        let bytes = b"hello mesh";
        let frags = MeshFragmenter::fragment(bytes, 42).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].frame_id, 42);
        assert_eq!(frags[0].frag_idx, 0);
        assert_eq!(frags[0].frag_total, 1);
        assert_eq!(frags[0].payload, bytes);
    }

    #[test]
    fn test_fragmenter_empty_input_one_fragment() {
        let frags = MeshFragmenter::fragment(&[], 1).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].frag_total, 1);
        assert!(frags[0].payload.is_empty());
    }

    #[test]
    fn test_fragmenter_exact_boundary_two_fragments() {
        // 236 + 1 octet → 2 fragments.
        let bytes = vec![0xAAu8; FRAGMENT_MAX_PAYLOAD + 1];
        let frags = MeshFragmenter::fragment(&bytes, 7).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].frag_idx, 0);
        assert_eq!(frags[0].frag_total, 2);
        assert_eq!(frags[0].payload.len(), FRAGMENT_MAX_PAYLOAD);
        assert_eq!(frags[1].frag_idx, 1);
        assert_eq!(frags[1].payload.len(), 1);
    }

    #[test]
    fn test_fragmenter_exact_multiple_no_extra_fragment() {
        // 236 × 3 exactement → 3 fragments (pas 4).
        let bytes = vec![0xBBu8; FRAGMENT_MAX_PAYLOAD * 3];
        let frags = MeshFragmenter::fragment(&bytes, 1).unwrap();
        assert_eq!(frags.len(), 3);
        for f in &frags {
            assert_eq!(f.payload.len(), FRAGMENT_MAX_PAYLOAD);
        }
    }

    #[test]
    fn test_fragmenter_rejects_too_many_fragments() {
        // > 32 fragments → erreur.
        let too_big = FRAGMENT_MAX_PAYLOAD * (MAX_FRAGMENTS_PER_FRAME as usize + 1);
        let bytes = vec![0u8; too_big];
        assert_eq!(
            MeshFragmenter::fragment(&bytes, 1),
            Err(FragmentError::TooManyFragments)
        );
    }

    // ── MeshFragment serialize/parse (3) ────────────────────────────

    #[test]
    fn test_fragment_serialize_roundtrip() {
        let f = MeshFragment {
            frame_id: 0xDEADBEEF,
            frag_idx: 3,
            frag_total: 10,
            payload: vec![0x11; 100],
        };
        let bytes = f.serialize();
        assert_eq!(bytes.len(), FRAGMENT_HEADER_SIZE + 100);
        let parsed = MeshFragment::parse(&bytes).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn test_fragment_parse_rejects_short_buffer() {
        let bytes = vec![0u8; FRAGMENT_HEADER_SIZE - 1];
        assert_eq!(
            MeshFragment::parse(&bytes),
            Err(ReassemblyError::TooShort)
        );
    }

    #[test]
    fn test_fragment_parse_rejects_zero_total() {
        // Fix unused_mut : `bytes` n'est jamais muté.
        let bytes = vec![0u8; FRAGMENT_HEADER_SIZE];
        // frag_total reste 0.
        assert_eq!(
            MeshFragment::parse(&bytes),
            Err(ReassemblyError::ZeroTotal)
        );
    }

    #[test]
    fn test_fragment_parse_rejects_idx_out_of_range() {
        let mut bytes = vec![0u8; FRAGMENT_HEADER_SIZE];
        bytes[4..6].copy_from_slice(&5u16.to_be_bytes());   // frag_idx = 5
        bytes[6..8].copy_from_slice(&5u16.to_be_bytes());   // frag_total = 5
        assert_eq!(
            MeshFragment::parse(&bytes),
            Err(ReassemblyError::IdxOutOfRange)
        );
    }

    // ── MeshReassembler tests (8) ───────────────────────────────────

    #[test]
    fn test_reassembler_single_fragment_completes() {
        let mut r = MeshReassembler::new();
        let now = Instant::now();
        let f = MeshFragment {
            frame_id: 1,
            frag_idx: 0,
            frag_total: 1,
            payload: b"hello".to_vec(),
        };
        let out = r.insert(f, now).unwrap();
        assert_eq!(out, Some(b"hello".to_vec()));
        assert!(r.is_empty());
    }

    #[test]
    fn test_reassembler_two_fragments_out_of_order() {
        let mut r = MeshReassembler::new();
        let now = Instant::now();
        // Insérer fragment 1 d'abord.
        let f1 = MeshFragment {
            frame_id: 1, frag_idx: 1, frag_total: 2, payload: b"world".to_vec(),
        };
        assert_eq!(r.insert(f1, now).unwrap(), None);
        // Puis fragment 0.
        let f0 = MeshFragment {
            frame_id: 1, frag_idx: 0, frag_total: 2, payload: b"hello ".to_vec(),
        };
        let out = r.insert(f0, now).unwrap();
        assert_eq!(out, Some(b"hello world".to_vec()));
    }

    #[test]
    fn test_reassembler_duplicate_fragment_ignored() {
        let mut r = MeshReassembler::new();
        let now = Instant::now();
        let f0 = MeshFragment {
            frame_id: 1, frag_idx: 0, frag_total: 2, payload: b"AAA".to_vec(),
        };
        let f0_dup = f0.clone();
        assert_eq!(r.insert(f0, now).unwrap(), None);
        assert_eq!(r.insert(f0_dup, now).unwrap(), None);  // duplicat ignoré
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_reassembler_rejects_too_many_concurrent() {
        let mut r = MeshReassembler::new();
        let now = Instant::now();
        // Saturer 4 frames concurrents (jamais complétés).
        for fid in 0..MAX_CONCURRENT_REASSEMBLIES as u32 {
            let f = MeshFragment {
                frame_id: fid, frag_idx: 0, frag_total: 10, payload: vec![0; 10],
            };
            assert!(r.insert(f, now).unwrap().is_none());
        }
        // 5ème → refusé.
        let f5 = MeshFragment {
            frame_id: 999, frag_idx: 0, frag_total: 10, payload: vec![0; 10],
        };
        assert_eq!(
            r.insert(f5, now),
            Err(ReassemblyError::TooManyConcurrent)
        );
    }

    #[test]
    fn test_reassembler_rejects_frag_total_above_max() {
        let mut r = MeshReassembler::new();
        let now = Instant::now();
        let f = MeshFragment {
            frame_id: 1,
            frag_idx: 0,
            frag_total: MAX_FRAGMENTS_PER_FRAME + 1,
            payload: vec![0; 10],
        };
        assert_eq!(
            r.insert(f, now),
            Err(ReassemblyError::TooManyFragments)
        );
    }

    #[test]
    fn test_reassembler_rejects_idx_out_of_range() {
        let mut r = MeshReassembler::new();
        let now = Instant::now();
        let f = MeshFragment {
            frame_id: 1,
            frag_idx: 5,
            frag_total: 5,
            payload: vec![0; 10],
        };
        assert_eq!(
            r.insert(f, now),
            Err(ReassemblyError::IdxOutOfRange)
        );
    }

    #[test]
    fn test_reassembler_timeout_purges_partial() {
        let mut r = MeshReassembler::new();
        let t0 = Instant::now();
        let f = MeshFragment {
            frame_id: 1, frag_idx: 0, frag_total: 5, payload: vec![0; 10],
        };
        r.insert(f, t0).unwrap();
        assert_eq!(r.len(), 1);

        // 31 s plus tard → expiré.
        let t1 = t0 + Duration::from_secs(REASSEMBLY_TIMEOUT_SECS + 1);
        r.purge_expired(t1);
        assert!(r.is_empty());
    }

    #[test]
    fn test_reassembler_clear_empties() {
        let mut r = MeshReassembler::new();
        let now = Instant::now();
        for fid in 0..3 {
            let f = MeshFragment {
                frame_id: fid, frag_idx: 0, frag_total: 5, payload: vec![0; 10],
            };
            r.insert(f, now).unwrap();
        }
        assert_eq!(r.len(), 3);
        r.clear();
        assert!(r.is_empty());
    }

    // ── End-to-end : fragmenter → reassembler (1) ───────────────────

    #[test]
    fn test_end_to_end_fragment_reassemble() {
        let original = vec![0xCDu8; FRAGMENT_MAX_PAYLOAD * 2 + 50]; // 3 fragments
        let frame_id = 0xCAFEBABE;

        let frags = MeshFragmenter::fragment(&original, frame_id).unwrap();
        assert_eq!(frags.len(), 3);

        let mut r = MeshReassembler::new();
        let now = Instant::now();
        let mut result = None;
        for f in frags {
            // Roundtrip serialize/parse pour simuler le transport.
            let wire = f.serialize();
            let parsed = MeshFragment::parse(&wire).unwrap();
            if let Some(bytes) = r.insert(parsed, now).unwrap() {
                result = Some(bytes);
            }
        }
        assert_eq!(result, Some(original));
    }
}