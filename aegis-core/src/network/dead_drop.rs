//! aegis-core/src/network/dead_drop.rs
//! Chantier C93 & Phase 2 Boîtier MESH ("AEGIS Relay Node" BLE <-> LoRa SX1262).
//! - Boîte aux lettres morte aveugle 100 % RAM (TTL 12h-24h, Read-Once destructif).
//! - Dérivation de `blind_tag` éphémère sur fenêtre horaire (HKDF-SHA256) : le boîtier
//!   relais ne connaît ni l'expéditeur ni la clé publique du destinataire.
//! - Codec de fragmentation radio LoRa (MTU 220 octets compatible Semtech SX1262 EU868/US915).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// MTU utile LoRa SF7-SF9 (255 octets max SX1262 -> 220 octets payload + 16 octets en-tête AEGIS)
pub const LORA_MESH_CHUNK_PAYLOAD_MAX: usize = 204;
pub const LORA_MESH_HEADER_LEN: usize = 16;
pub const LORA_MESH_MAGIC: [u8; 2] = [0xAE, 0x36];

/// Calcule le tag de routage aveugle de 16 octets pour un destinataire sur une tranche horaire
/// (`epoch_hour = unix_timestamp / 3600`), empêchant le traçage long terme sur un relais MESH.
pub fn derive_hourly_blind_tag(recipient_ed25519_pk: &[u8; 32], epoch_hour: u64) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS-BLIND-DEADDROP-TAG-v1"), recipient_ed25519_pk);
    let mut info = [0u8; 12];
    info[..4].copy_from_slice(b"TAG:");
    info[4..12].copy_from_slice(&epoch_hour.to_be_bytes());

    let mut tag = [0u8; 16];
    let _ = hk.expand(&info, &mut tag);
    tag
}

pub struct BlindEnvelopeSlot {
    pub blind_tag: [u8; 16],
    pub expires_at: Instant,
    pub ciphertext: Vec<u8>,
}

impl Drop for BlindEnvelopeSlot {
    fn drop(&mut self) {
        self.blind_tag.zeroize();
        self.ciphertext.zeroize();
    }
}

pub struct RamDeadDropVault {
    max_slots: usize,
    ttl: Duration,
    slots: VecDeque<BlindEnvelopeSlot>,
}

impl RamDeadDropVault {
    pub fn new(max_slots: usize, ttl_secs: u64) -> Self {
        Self {
            max_slots: max_slots.clamp(16, 4096),
            ttl: Duration::from_secs(ttl_secs.clamp(60, 86_400)),
            slots: VecDeque::with_capacity(128),
        }
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.slots.retain(|s| s.expires_at > now);
    }

    pub fn deposit(&mut self, blind_tag: [u8; 16], ciphertext: Vec<u8>) -> Result<(), &'static str> {
        if ciphertext.is_empty() || ciphertext.len() > 65_536 {
            return Err("AEGIS_DEADDROP_INVALID_LEN");
        }
        self.purge_expired();
        if self.slots.len() >= self.max_slots {
            self.slots.pop_front(); // Éjection FIFO avec zéroïsation automatique via Drop
        }
        self.slots.push_back(BlindEnvelopeSlot {
            blind_tag,
            expires_at: Instant::now() + self.ttl,
            ciphertext,
        });
        Ok(())
    }

    /// Extraction destructive (Read-Once) en temps constant (`ConstantTimeEq`).
    pub fn collect_and_burn(&mut self, target_tag: &[u8; 16]) -> Vec<Vec<u8>> {
        self.purge_expired();
        let mut found = Vec::new();
        let mut kept = VecDeque::with_capacity(self.slots.len());

        while let Some(mut slot) = self.slots.pop_front() {
            if bool::from(slot.blind_tag.ct_eq(target_tag)) {
                found.push(std::mem::take(&mut slot.ciphertext));
            } else {
                kept.push_back(slot);
            }
        }
        self.slots = kept;
        found
    }

    pub fn wipe_all(&mut self) {
        self.slots.clear();
    }

    pub fn active_count(&mut self) -> usize {
        self.purge_expired();
        self.slots.len()
    }
}

/// En-tête binaire compact (16 octets) entre le Smartphone (BLE GATT) et le Boîtier AEGIS LoRa :
/// [Magic 2B (0xAE,0x36) | HopsTTL 1B | Flags 1B | MsgID 8B | FragIdx 1B | FragTotal 1B | PayloadLen 2B]
pub fn fragment_for_lora_relay(
    msg_id: [u8; 8],
    hops_ttl: u8,
    is_dead_drop: bool,
    envelope: &[u8],
) -> Result<Vec<Vec<u8>>, &'static str> {
    if envelope.is_empty() {
        return Err("AEGIS_EMPTY_LORA_PAYLOAD");
    }
    let total_chunks = (envelope.len() + LORA_MESH_CHUNK_PAYLOAD_MAX - 1) / LORA_MESH_CHUNK_PAYLOAD_MAX;
    if total_chunks > 255 {
        return Err("AEGIS_LORA_MESSAGE_TOO_LARGE");
    }

    let safe_ttl = hops_ttl.clamp(1, 7);
    let flags: u8 = if is_dead_drop { 0x01 } else { 0x00 };
    let mut packets = Vec::with_capacity(total_chunks);

    for (idx, chunk) in envelope.chunks(LORA_MESH_CHUNK_PAYLOAD_MAX).enumerate() {
        let mut pkt = Vec::with_capacity(LORA_MESH_HEADER_LEN + chunk.len());
        pkt.extend_from_slice(&LORA_MESH_MAGIC);
        pkt.push(safe_ttl);
        pkt.push(flags);
        pkt.extend_from_slice(&msg_id);
        pkt.push(idx as u8);
        pkt.push(total_chunks as u8);
        pkt.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        pkt.extend_from_slice(chunk);
        packets.push(pkt);
    }
    Ok(packets)
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_RAM_DEADDROP: Mutex<RamDeadDropVault> =
        Mutex::new(RamDeadDropVault::new(512, 12 * 3600));
}

pub fn wipe_global_deaddrop() {
    if let Ok(mut store) = GLOBAL_RAM_DEADDROP.lock() {
        store.wipe_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_tag_rotates_hourly() {
        let pk = [0x77u8; 32];
        let t1 = derive_hourly_blind_tag(&pk, 500_000);
        let t2 = derive_hourly_blind_tag(&pk, 500_001);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_deaddrop_read_once_and_burn() {
        let mut vault = RamDeadDropVault::new(32, 3600);
        let tag = derive_hourly_blind_tag(&[0x11u8; 32], 42);
        vault.deposit(tag, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(vault.active_count(), 1);

        let msgs = vault.collect_and_burn(&tag);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], vec![1, 2, 3, 4]);
        assert_eq!(vault.active_count(), 0);
    }

    #[test]
    fn test_lora_fragmentation_512b_cell() {
        let cell = [0xABu8; 512];
        let frags = fragment_for_lora_relay([1, 2, 3, 4, 5, 6, 7, 8], 5, true, &cell).unwrap();
        assert_eq!(frags.len(), 3); // 204 + 204 + 104 = 512 octets
        assert_eq!(&frags[0][0..2], &LORA_MESH_MAGIC);
        assert_eq!(frags[0][2], 5); // TTL
        assert_eq!(frags[0][13], 3); // Total fragments
    }
}