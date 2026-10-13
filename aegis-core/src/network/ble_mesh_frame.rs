// src/network/ble_mesh_frame.rs
//
// P0-A.3d.1 (2026-10-13) — MeshFrame + MeshDeduplicator.
//
// Header format (D78, Q5 Option B, 42 octets fixes) :
//   sender_id[32]  : fingerprint ed25519 du source ORIGINAL
//   seq_num[8]     : u64 BE, CSPRNG (pas compteur monotone)
//   ttl[1]         : TTL courant (initial 5, clamp haut 5)
//   flags[1]       : réservé (0 pour l'instant)
//
// Le payload chiffré (Double Ratchet) suit immédiatement le header.
//
// Dédup (D80, Q7 Option C) : clé = (sender_id[32], seq_num u64) = 40 octets.
// TTL entrée dédup : 60 s (D41).
//
// Contraintes :
//   - Header minimal (surface d'attaque passive minimale)
//   - Big-endian (network order)
//   - Purge TTL appelée périodiquement (par l'appelant)

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────
// Constantes (D78, D79, D80)
// ─────────────────────────────────────────────────────────────────────

/// Taille fixe du header MeshFrame (D78).
pub const HEADER_SIZE: usize = 42;

/// TTL maximum autorisé (D79).
pub const MAX_TTL: u8 = 5;

/// TTL des entrées de la table de dédup (D41).
pub const DEDUP_TTL_SECS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────
// Erreurs typées
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Buffer plus court que HEADER_SIZE.
    TooShort,
    /// TTL reçu > MAX_TTL (tentative d'amplification, D79).
    TtlAboveMax,
    /// TTL=0 mais tentative de serialize avec une payload (incohérent).
    TtlZeroWithPayload,
}

impl FrameError {
    pub fn to_code(self) -> i32 {
        match self {
            FrameError::TooShort => -10,
            FrameError::TtlAboveMax => -11,
            FrameError::TtlZeroWithPayload => -12,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// MeshFrame
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshFrame {
    pub sender_id: [u8; 32],
    pub seq_num: u64,
    pub ttl: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl MeshFrame {
    /// Crée un nouveau frame au source (TTL initial = MAX_TTL).
    pub fn new_source(sender_id: [u8; 32], seq_num: u64, payload: Vec<u8>) -> Self {
        Self {
            sender_id,
            seq_num,
            ttl: MAX_TTL,
            flags: 0,
            payload,
        }
    }

    /// Parse un buffer reçu. Vérifie la taille et le TTL.
    ///
    /// D79 : tout TTL > MAX_TTL reçu est droppé (anti-amplification).
    pub fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_SIZE {
            return Err(FrameError::TooShort);
        }

        let mut sender_id = [0u8; 32];
        sender_id.copy_from_slice(&bytes[..32]);

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&bytes[32..40]);
        let seq_num = u64::from_be_bytes(seq_bytes);

        let ttl = bytes[40];
        let flags = bytes[41];

        if ttl > MAX_TTL {
            return Err(FrameError::TtlAboveMax);
        }

        let payload = bytes[HEADER_SIZE..].to_vec();

        Ok(Self {
            sender_id,
            seq_num,
            ttl,
            flags,
            payload,
        })
    }

    /// Sérialise le frame (header + payload).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.sender_id);
        out.extend_from_slice(&self.seq_num.to_be_bytes());
        out.push(self.ttl);
        out.push(self.flags);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Décrémente le TTL. Retourne `true` si le frame est forwardable.
    ///
    /// D79 : si TTL == 0 → drop (pas de forward). Sinon décrémente
    /// et retourne true.
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl == 0 {
            return false;
        }
        self.ttl -= 1;
        true
    }

    /// Retourne la clé de dédup (D80).
    pub fn dedup_key(&self) -> [u8; 40] {
        dedup_key(&self.sender_id, self.seq_num)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Clé de dédup (D80)
// ─────────────────────────────────────────────────────────────────────

/// Construit la clé de dédup : sender_id[32] || seq_num[8] BE.
#[inline]
fn dedup_key(sender_id: &[u8; 32], seq_num: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(sender_id);
    key[32..].copy_from_slice(&seq_num.to_be_bytes());
    key
}

// ─────────────────────────────────────────────────────────────────────
// MeshDeduplicator (Q7, D80)
// ─────────────────────────────────────────────────────────────────────

pub struct MeshDeduplicator {
    seen: HashMap<[u8; 40], Instant>,
    ttl: Duration,
}

impl MeshDeduplicator {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            ttl: Duration::from_secs(DEDUP_TTL_SECS),
        }
    }

    /// Retourne `true` si le message est nouveau (à traiter),
    /// `false` si déjà vu (à dropper).
    ///
    /// Injecte `now` pour testabilité (pattern utilisé dans tor_rotation.rs).
    pub fn check_and_insert(
        &mut self,
        sender_id: &[u8; 32],
        seq_num: u64,
        now: Instant,
    ) -> bool {
        let key = dedup_key(sender_id, seq_num);
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, now);
        true
    }

    /// Purge les entrées plus vieilles que `ttl`.
    pub fn purge_expired(&mut self, now: Instant) {
        self.seen
            .retain(|_, inserted| now.duration_since(*inserted) < self.ttl);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn clear(&mut self) {
        self.seen.clear();
    }
}

impl Default for MeshDeduplicator {
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

    fn dummy_sender() -> [u8; 32] {
        [0xA5; 32]
    }

    // ── MeshFrame tests (8) ─────────────────────────────────────────

    #[test]
    fn test_frame_parse_valid() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x11; 32]);     // sender_id
        buf.extend_from_slice(&42u64.to_be_bytes());  // seq_num
        buf.push(3);                            // ttl
        buf.push(0);                            // flags
        buf.extend_from_slice(b"hello");        // payload

        let f = MeshFrame::parse(&buf).unwrap();
        assert_eq!(f.sender_id, [0x11; 32]);
        assert_eq!(f.seq_num, 42);
        assert_eq!(f.ttl, 3);
        assert_eq!(f.flags, 0);
        assert_eq!(f.payload, b"hello");
    }

    #[test]
    fn test_frame_parse_rejects_short_header() {
        let buf = vec![0u8; HEADER_SIZE - 1];
        assert_eq!(MeshFrame::parse(&buf), Err(FrameError::TooShort));
    }

    #[test]
    fn test_frame_parse_rejects_empty_buffer() {
        assert_eq!(MeshFrame::parse(&[]), Err(FrameError::TooShort));
    }

    #[test]
    fn test_frame_parse_rejects_ttl_above_max() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[40] = MAX_TTL + 1;  // TTL illégal
        assert_eq!(MeshFrame::parse(&buf), Err(FrameError::TtlAboveMax));
    }

    #[test]
    fn test_frame_parse_accepts_ttl_at_max() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[40] = MAX_TTL;
        assert!(MeshFrame::parse(&buf).is_ok());
    }

    #[test]
    fn test_frame_serialize_roundtrip() {
        let original = MeshFrame {
            sender_id: dummy_sender(),
            seq_num: 0xDEADBEEFCAFEBABE,
            ttl: 4,
            flags: 0x01,
            payload: b"test payload".to_vec(),
        };
        let bytes = original.serialize();
        let parsed = MeshFrame::parse(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_frame_serialize_empty_payload() {
        let f = MeshFrame::new_source(dummy_sender(), 1, Vec::new());
        let bytes = f.serialize();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let parsed = MeshFrame::parse(&bytes).unwrap();
        assert_eq!(parsed.payload.len(), 0);
    }

    #[test]
    fn test_frame_serialize_uses_big_endian_seq() {
        let f = MeshFrame {
            sender_id: [0; 32],
            seq_num: 0x0102030405060708,
            ttl: 0,
            flags: 0,
            payload: Vec::new(),
        };
        let bytes = f.serialize();
        // Les 8 octets de seq_num (offsets 32..40) doivent être BE.
        assert_eq!(&bytes[32..40], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    // ── TTL tests (3) ────────────────────────────────────────────────

    #[test]
    fn test_frame_decrement_ttl_returns_true_above_zero() {
        let mut f = MeshFrame::new_source(dummy_sender(), 1, Vec::new());
        assert_eq!(f.ttl, MAX_TTL);
        assert!(f.decrement_ttl());
        assert_eq!(f.ttl, MAX_TTL - 1);
    }

    #[test]
    fn test_frame_decrement_ttl_returns_false_at_zero() {
        let mut f = MeshFrame::new_source(dummy_sender(), 1, Vec::new());
        f.ttl = 0;
        assert!(!f.decrement_ttl());
        assert_eq!(f.ttl, 0);
    }

    #[test]
    fn test_frame_decrement_ttl_reaches_zero_after_max_hops() {
        let mut f = MeshFrame::new_source(dummy_sender(), 1, Vec::new());
        // MAX_TTL = 5 : on peut forwarder 5 fois (5→4→3→2→1→0).
        for _ in 0..MAX_TTL {
            assert!(f.decrement_ttl());
        }
        assert_eq!(f.ttl, 0);
        // 6ème tentative : refusée.
        assert!(!f.decrement_ttl());
    }

    // ── Dedup tests (7) ──────────────────────────────────────────────

    #[test]
    fn test_dedup_first_seen_returns_true() {
        let mut d = MeshDeduplicator::new();
        let now = Instant::now();
        assert!(d.check_and_insert(&[1u8; 32], 100, now));
    }

    #[test]
    fn test_dedup_second_seen_returns_false() {
        let mut d = MeshDeduplicator::new();
        let now = Instant::now();
        let s = [1u8; 32];
        assert!(d.check_and_insert(&s, 100, now));
        assert!(!d.check_and_insert(&s, 100, now));
    }

    #[test]
    fn test_dedup_different_seq_returns_true() {
        let mut d = MeshDeduplicator::new();
        let now = Instant::now();
        let s = [1u8; 32];
        assert!(d.check_and_insert(&s, 100, now));
        assert!(d.check_and_insert(&s, 101, now));
    }

    #[test]
    fn test_dedup_different_sender_returns_true() {
        let mut d = MeshDeduplicator::new();
        let now = Instant::now();
        assert!(d.check_and_insert(&[1u8; 32], 100, now));
        assert!(d.check_and_insert(&[2u8; 32], 100, now));
    }

    #[test]
    fn test_dedup_purge_expired_removes_old() {
        let mut d = MeshDeduplicator::new();
        let t0 = Instant::now();
        assert!(d.check_and_insert(&[1u8; 32], 100, t0));
        assert_eq!(d.len(), 1);

        // 61 s plus tard → expiré.
        let t1 = t0 + Duration::from_secs(DEDUP_TTL_SECS + 1);
        d.purge_expired(t1);
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn test_dedup_purge_keeps_fresh() {
        let mut d = MeshDeduplicator::new();
        let t0 = Instant::now();
        assert!(d.check_and_insert(&[1u8; 32], 100, t0));

        // 30 s plus tard → encore frais.
        let t1 = t0 + Duration::from_secs(30);
        d.purge_expired(t1);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn test_dedup_clear_empties() {
        let mut d = MeshDeduplicator::new();
        let now = Instant::now();
        d.check_and_insert(&[1u8; 32], 1, now);
        d.check_and_insert(&[2u8; 32], 2, now);
        assert_eq!(d.len(), 2);
        d.clear();
        assert!(d.is_empty());
    }

    #[test]
    fn test_dedup_is_empty_initially() {
        let d = MeshDeduplicator::new();
        assert!(d.is_empty());
        assert_eq!(d.len(), 0);
    }
}