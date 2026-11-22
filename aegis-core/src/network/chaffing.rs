//! aegis-core/src/network/chaffing.rs
//! Chantier C90 — Chasseur de trafic factice ("Constant-Rate Dummy Chaffing").
//! Neutralise l'analyse de corrélation temporelle (SIGINT / Tor / BLE / Wi-Fi Direct)
//! en émettant des cellules fixes de 512 octets indiscernables à intervalle régulier.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use getrandom::getrandom;
use zeroize::Zeroize;

pub const AEGIS_WIRE_CELL_LEN: usize = 512;
pub const AEGIS_MAX_CELL_PAYLOAD: usize = AEGIS_WIRE_CELL_LEN - 3;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireCellKind {
    DummyChaff = 0x00,
    LiveMessage = 0x01,
    BlindDeadDrop = 0x02,
}

pub struct WireCell512 {
    pub data: [u8; AEGIS_WIRE_CELL_LEN],
}

impl Drop for WireCell512 {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl WireCell512 {
    /// Empaquette un payload dans une cellule stricte de 512 octets remplie par l'OS CSPRNG.
    pub fn pack(kind: WireCellKind, payload: &[u8]) -> Result<Self, &'static str> {
        if payload.len() > AEGIS_MAX_CELL_PAYLOAD {
            return Err("AEGIS_CELL_PAYLOAD_TOO_LARGE");
        }
        let mut buf = [0u8; AEGIS_WIRE_CELL_LEN];
        getrandom(&mut buf).map_err(|_| "AEGIS_CSPRNG_FAILURE")?;

        buf[0] = kind as u8;
        let len_be = (payload.len() as u16).to_be_bytes();
        buf[1] = len_be[0];
        buf[2] = len_be[1];

        if !payload.is_empty() {
            buf[3..3 + payload.len()].copy_from_slice(payload);
        }
        Ok(Self { data: buf })
    }

    /// Génère une cellule de bruit pur (0 octet utile, 509 octets d'entropie OS).
    pub fn new_chaff() -> Result<Self, &'static str> {
        Self::pack(WireCellKind::DummyChaff, &[])
    }

    /// Dépaquette une cellule reçue après déchiffrement du tunnel AEAD.
    pub fn unpack(&self) -> Result<(WireCellKind, &[u8]), &'static str> {
        let kind = match self.data[0] {
            0x00 => WireCellKind::DummyChaff,
            0x01 => WireCellKind::LiveMessage,
            0x02 => WireCellKind::BlindDeadDrop,
            _ => return Err("AEGIS_UNKNOWN_CELL_KIND"),
        };
        let len = u16::from_be_bytes([self.data[1], self.data[2]]) as usize;
        if len > AEGIS_MAX_CELL_PAYLOAD {
            return Err("AEGIS_CORRUPTED_CELL_LEN");
        }
        Ok((kind, &self.data[3..3 + len]))
    }
}

pub struct ChaffScheduler {
    enabled: bool,
    interval: Duration,
    last_emit: Instant,
    queue: VecDeque<WireCell512>,
}

impl ChaffScheduler {
    pub fn new(interval_ms: u64) -> Self {
        let clamped = interval_ms.clamp(200, 30_000);
        Self {
            enabled: false,
            interval: Duration::from_millis(clamped),
            last_emit: Instant::now(),
            queue: VecDeque::with_capacity(64),
        }
    }

    pub fn configure(&mut self, enabled: bool, interval_ms: u64) {
        self.enabled = enabled;
        self.interval = Duration::from_millis(interval_ms.clamp(200, 30_000));
        self.last_emit = Instant::now();
    }

    pub fn enqueue(&mut self, kind: WireCellKind, payload: &[u8]) -> Result<(), &'static str> {
        if self.queue.len() >= 256 {
            return Err("AEGIS_CHAFF_QUEUE_FULL");
        }
        let cell = WireCell512::pack(kind, payload)?;
        self.queue.push_back(cell);
        Ok(())
    }

    /// Retourne une cellule de 512 octets si le tick est échu (message réel prioritaire, sinon Chaff).
    pub fn poll_tick(&mut self, force_now: bool) -> Result<Option<WireCell512>, &'static str> {
        if !self.enabled && self.queue.is_empty() && !force_now {
            return Ok(None);
        }
        if !force_now && self.last_emit.elapsed() < self.interval {
            return Ok(None);
        }
        self.last_emit = Instant::now();
        if let Some(real_cell) = self.queue.pop_front() {
            Ok(Some(real_cell))
        } else if self.enabled || force_now {
            Ok(Some(WireCell512::new_chaff()?))
        } else {
            Ok(None)
        }
    }

    pub fn wipe(&mut self) {
        self.enabled = false;
        self.queue.clear();
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_CHAFF_SCHEDULER: Mutex<ChaffScheduler> =
        Mutex::new(ChaffScheduler::new(1500));
}

pub fn wipe_global_chaff() {
    if let Ok(mut sched) = GLOBAL_CHAFF_SCHEDULER.lock() {
        sched.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_pack_unpack_roundtrip() {
        let msg = b"ORDRE_STRATEGIQUE_ALPHA";
        let cell = WireCell512::pack(WireCellKind::LiveMessage, msg).unwrap();
        assert_eq!(cell.data.len(), 512);
        let (kind, out) = cell.unpack().unwrap();
        assert_eq!(kind, WireCellKind::LiveMessage);
        assert_eq!(out, msg);
    }

    #[test]
    fn test_chaff_cell_indistinguishable_size() {
        let c1 = WireCell512::new_chaff().unwrap();
        let c2 = WireCell512::new_chaff().unwrap();
        assert_eq!(c1.data.len(), 512);
        assert_ne!(&c1.data[3..35], &c2.data[3..35]);
        let (kind, out) = c1.unpack().unwrap();
        assert_eq!(kind, WireCellKind::DummyChaff);
        assert!(out.is_empty());
    }

    #[test]
    fn test_scheduler_prioritizes_real_then_chaff() {
        let mut s = ChaffScheduler::new(200);
        s.configure(true, 200);
        s.enqueue(WireCellKind::LiveMessage, b"PING").unwrap();

        let first = s.poll_tick(true).unwrap().unwrap();
        assert_eq!(first.unpack().unwrap().0, WireCellKind::LiveMessage);

        let second = s.poll_tick(true).unwrap().unwrap();
        assert_eq!(second.unpack().unwrap().0, WireCellKind::DummyChaff);

        s.wipe();
        assert!(s.poll_tick(false).unwrap().is_none());
    }
}