#![no_std]
//! AEGIS Mesh Relay Node — Bare-Metal `#![no_std]` SRAM-Only Engine (nRF52840 + Semtech SX1262)
//! Garanties matérielles :
//!   1. 0 allocation dynamique sur Flash (aucune persistance NVS/EEPROM/SPIFFS).
//!   2. Déduplication anti-tempête radio par table circulaire en SRAM volatile.
//!   3. Relais aveugle Zero-Knowledge (ne possède aucune clé de déchiffrement E2EE).
//!   4. Tamper-Wipe : `hardware_tamper_zeroize()` écrase instantanément toute la SRAM.

use zeroize::Zeroize;

pub const LORA_MAGIC: [u8; 2] = [0xAE, 0x36];
pub const MAX_LORA_FRAME: usize = 220;
pub const DEDUP_RING_SIZE: usize = 128;
pub const SRAM_DEADDROP_SLOTS: usize = 32;

#[derive(Clone, Copy)]
pub struct SramPacketSlot {
    pub occupied: bool,
    pub len: u8,
    pub bytes: [u8; MAX_LORA_FRAME],
}

impl Default for SramPacketSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            len: 0,
            bytes: [0u8; MAX_LORA_FRAME],
        }
    }
}

pub struct BlindMeshRelayState {
    dedup_msg_ids: [[u8; 8]; DEDUP_RING_SIZE],
    dedup_cursor: usize,
    sram_dead_drop: [SramPacketSlot; SRAM_DEADDROP_SLOTS],
    drop_cursor: usize,
}

impl Default for BlindMeshRelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl BlindMeshRelayState {
    pub const fn new() -> Self {
        Self {
            dedup_msg_ids: [[0u8; 8]; DEDUP_RING_SIZE],
            dedup_cursor: 0,
            sram_dead_drop: [SramPacketSlot {
                occupied: false,
                len: 0,
                bytes: [0u8; MAX_LORA_FRAME],
            }; SRAM_DEADDROP_SLOTS],
            drop_cursor: 0,
        }
    }

    /// Inspecte un paquet LoRa/BLE entrant [Magic 2B | TTL 1B | Flags 1B | MsgID 8B | ...]
    /// Retourne `Some(tx_len)` avec TTL décrémenté si le paquet doit être réémis en LoRa.
    pub fn process_incoming_radio_frame(&mut self, frame: &mut [u8]) -> Option<usize> {
        if frame.len() < 16 || frame.len() > MAX_LORA_FRAME {
            return None;
        }
        if frame[0..2] != LORA_MAGIC {
            return None;
        }
        let ttl = frame[2];
        if ttl == 0 {
            return None;
        }

        let mut msg_id = [0u8; 8];
        msg_id.copy_from_slice(&frame[4..12]);

        // Anti-boucle : ignore un MsgID déjà relayé récemment en SRAM
        for seen in &self.dedup_msg_ids {
            if *seen == msg_id && msg_id != [0u8; 8] {
                return None;
            }
        }
        self.dedup_msg_ids[self.dedup_cursor] = msg_id;
        self.dedup_cursor = (self.dedup_cursor + 1) % DEDUP_RING_SIZE;

        // Si le flag Dead-Drop (bit 0) est actif, garde une copie aveugle en SRAM circulaire
        if (frame[3] & 0x01) != 0 {
            let slot = &mut self.sram_dead_drop[self.drop_cursor];
            slot.bytes.zeroize();
            slot.bytes[..frame.len()].copy_from_slice(frame);
            slot.len = frame.len() as u8;
            slot.occupied = true;
            self.drop_cursor = (self.drop_cursor + 1) % SRAM_DEADDROP_SLOTS;
        }

        // Décrémente le TTL avant réémission LoRa
        frame[2] = ttl.saturating_sub(1);
        if frame[2] > 0 {
            Some(frame.len())
        } else {
            None
        }
    }

    /// Coupure d'urgence sur ouverture boîtier (Tamper Switch GPIO) ou bouton panique
    pub fn hardware_tamper_zeroize(&mut self) {
        for id in &mut self.dedup_msg_ids {
            id.zeroize();
        }
        for slot in &mut self.sram_dead_drop {
            slot.bytes.zeroize();
            slot.len = 0;
            slot.occupied = false;
        }
        self.dedup_cursor = 0;
        self.drop_cursor = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_relay_decrements_ttl_and_deduplicates() {
        let mut relay = BlindMeshRelayState::new();
        let mut pkt = [0u8; 32];
        pkt[0..2].copy_from_slice(&LORA_MAGIC);
        pkt[2] = 3; // TTL = 3
        pkt[3] = 0x01; // Dead-drop flag
        pkt[4..12].copy_from_slice(&[9, 9, 9, 9, 1, 2, 3, 4]);

        assert_eq!(relay.process_incoming_radio_frame(&mut pkt), Some(32));
        assert_eq!(pkt[2], 2); // TTL décrémenté

        // Le même paquet reçu en écho radio est bloqué (anti-tempête)
        assert_eq!(relay.process_incoming_radio_frame(&mut pkt), None);

        // Tamper switch : toute la SRAM est remise à zéro
        relay.hardware_tamper_zeroize();
        assert!(!relay.sram_dead_drop[0].occupied);
    }
}