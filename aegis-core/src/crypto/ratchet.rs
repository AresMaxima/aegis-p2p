//! aegis-core/src/crypto/ratchet.rs
//! Symmetric Ratchet + Skipped Message Keys (out-of-order support).
//!
//! Audit 2026-09-27 (Vague 2) — Refonte complète :
//!   • L'ancien code supposait l'ordre des messages (session cassée au 1er perdu).
//!   • Ajout header minimal (seq_num u32) → wire format v2.
//!   • Ajout store borné (MAX_SKIP = 1000) des clés de messages skipés.
//!   • Replay protection via fenêtre glissante.
//!
//! Limite : PAS de Post-Compromise Security (PCS). Le DH ratchet step
//! périodique nécessite un vrai handshake Signal avec transmission
//! de prev_chain_len. À implémenter en v3.1 si nécessaire.
//!
//! Compat : pad_payload / unpad_payload conservés (utilisés par blindspots_test).

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// Nombre maximum de clés de messages skipés avant rejet (anti-DoS).
const MAX_SKIP: u32 = 1000;

/// Taille du header en bytes : seq_num u32 (4 octets).
const HEADER_SIZE: usize = 4;

// =============================================================================
// PADDING ANTI-ANALYSE DE TRAFIC (conservé — utilisé par blindspots_test)
// =============================================================================

/// Pad un payload à un multiple exact de `block_size` octets avec du padding aléatoire.
pub fn pad_payload(data: &[u8], block_size: usize) -> Result<Vec<u8>, &'static str> {
    if block_size == 0 {
        return Err("Le block_size doit être supérieur à 0");
    }

    let payload_len = data.len();
    if payload_len > u16::MAX as usize {
        return Err("Payload trop grand (maximum 65535 octets)");
    }

    let total_unpadded = 2 + payload_len;
    let padding_needed = (block_size - (total_unpadded % block_size)) % block_size;

    let mut padded = Vec::with_capacity(total_unpadded + padding_needed);

    padded.extend_from_slice(&(payload_len as u16).to_be_bytes());
    padded.extend_from_slice(data);

    if padding_needed > 0 {
        let mut random_padding = vec![0u8; padding_needed];
        getrandom::getrandom(&mut random_padding)
            .map_err(|_| "Échec de génération du padding aléatoire")?;
        padded.extend_from_slice(&random_padding);
    }

    Ok(padded)
}

/// Extrait le payload d'origine et retire le padding aléatoire.
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if padded.len() < 2 {
        return Err("Payload trop court");
    }

    let payload_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if 2 + payload_len > padded.len() {
        return Err("Taille de payload invalide");
    }

    Ok(padded[2..2 + payload_len].to_vec())
}

// =============================================================================
// SESSION DE CLIQUET (SYMMETRIC RATCHET + SKIPPED KEYS)
// =============================================================================

/// État d'une session de cliquet P2P.
///
/// Contient :
///   • 1 root key (partagé avec l'autre partie au handshake).
///   • 2 chaînes symétriques (envoi / réception), ratchetées par message.
///   • 1 store de clés skipées (pour messages hors-ordre).
///
/// Wire format (chaque message) :
///   `[header (4 octets)] [ciphertext (N octets)]`
///   header = seq_num (u32 LE)
///   ciphertext = ChaCha20-Poly1305 sur `pad_payload(plaintext, 512)`
pub struct RatchetSession {
    // --- Root key (pour dérivation d'extension future) ---
    #[allow(dead_code)]
    root_key: [u8; 32],

    // --- Chaîne d'envoi ---
    send_chain_key: [u8; 32],
    send_seq: u32,

    // --- Chaîne de réception ---
    recv_chain_key: [u8; 32],
    recv_seq: u32,

    // --- Clés skipées : seq_num → message_key ---
    skipped_keys: HashMap<u32, [u8; 32]>,
}

impl Drop for RatchetSession {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.send_chain_key.zeroize();
        self.recv_chain_key.zeroize();
        for (_, v) in self.skipped_keys.iter_mut() {
            v.zeroize();
        }
    }
}

impl RatchetSession {
    /// Initiator : dérive root + chaînes symétriques.
    ///
    /// root = HKDF-SHA256(
    ///     DH(static_A, static_B) || DH(ephemeral_A, static_B),
    ///     salt = AEGIS_RATCHET_ROOT_SALT
    /// )
    pub fn new_initiator(
        local_static: &X25519StaticSecret,
        local_ephemeral: &X25519StaticSecret,
        remote_static: &X25519PublicKey,
    ) -> Self {
        let dh1 = local_static.diffie_hellman(remote_static);
        let dh2 = local_ephemeral.diffie_hellman(remote_static);

        let mut master_secret = Vec::with_capacity(64);
        master_secret.extend_from_slice(dh1.as_bytes());
        master_secret.extend_from_slice(dh2.as_bytes());

        let root_key = derive_root(&master_secret);
        master_secret.zeroize();

        // Initiator : envoie sur SEND, reçoit sur RECV.
        let send_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_SEND");
        let recv_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_RECV");

        Self {
            root_key,
            send_chain_key,
            send_seq: 0,
            recv_chain_key,
            recv_seq: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Responder : dérive root + chaînes symétriques (inversées).
    ///
    /// root = HKDF-SHA256(
    ///     DH(static_B, static_A) || DH(static_B, ephemeral_A),
    ///     salt = AEGIS_RATCHET_ROOT_SALT
    /// )
    /// Note : DH est symétrique, donc le root est identique à celui de l'initiator.
    pub fn new_responder(
        local_static: &X25519StaticSecret,
        remote_static: &X25519PublicKey,
        remote_ephemeral: &X25519PublicKey,
    ) -> Self {
        let dh1 = local_static.diffie_hellman(remote_static);
        let dh2 = local_static.diffie_hellman(remote_ephemeral);

        let mut master_secret = Vec::with_capacity(64);
        master_secret.extend_from_slice(dh1.as_bytes());
        master_secret.extend_from_slice(dh2.as_bytes());

        let root_key = derive_root(&master_secret);
        master_secret.zeroize();

        // Responder : envoie sur RECV, reçoit sur SEND (inversé).
        let send_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_RECV");
        let recv_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_SEND");

        Self {
            root_key,
            send_chain_key,
            send_seq: 0,
            recv_chain_key,
            recv_seq: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Chiffre un message : pad → header → ChaCha20-Poly1305.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let padded_plaintext = pad_payload(plaintext, 512).map_err(|e| e.to_string())?;

        // Dériver message_key || next_chain_key depuis la chaîne d'envoi
        let (message_key, next_chain_key) = kdf_chain(&self.send_chain_key, self.send_seq);

        let cipher = ChaCha20Poly1305::new_from_slice(&message_key)
            .map_err(|e| format!("Erreur d'initialisation du cipher: {}", e))?;

        // Nonce déterministe : seq_num (u32 LE) || 0u64 → unique par (chain_key, seq)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.send_seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, padded_plaintext.as_slice())
            .map_err(|_| "Échec du chiffrement du message".to_string())?;

        // Header minimal : seq_num (4 octets LE)
        let header = self.send_seq.to_le_bytes();

        // Avancer la chaîne
        self.send_chain_key.zeroize();
        self.send_chain_key = next_chain_key;
        self.send_seq += 1;

        // Assembler header + ciphertext
        let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    /// Déchiffre un message : parse header → skip → unpad.
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        if message.len() < HEADER_SIZE {
            return Err("Message trop court".to_string());
        }

        let seq_num = u32::from_le_bytes([
            message[0], message[1], message[2], message[3],
        ]);
        let ciphertext = &message[HEADER_SIZE..];

        // --- 1. Skip les clés jusqu'à seq_num (stocke les intermédiaires) ---
        self.skip_message_keys_until(seq_num)
            .map_err(|e| format!("Erreur skip chain: {}", e))?;

        // --- 2. Récupérer la message key (skipped ou chain courante) ---
        let key_to_use = if let Some(k) = self.skipped_keys.remove(&seq_num) {
            k
        } else if seq_num == self.recv_seq {
            // Cas normal : c'est la prochaine clé de la chaîne
            let (mk, next_ck) = kdf_chain(&self.recv_chain_key, seq_num);
            self.recv_chain_key.zeroize();
            self.recv_chain_key = next_ck;
            self.recv_seq = seq_num + 1;
            mk
        } else {
            return Err(format!(
                "Clé de message introuvable (seq={})",
                seq_num
            ));
        };

        // --- 3. Déchiffrer ---
        let cipher = ChaCha20Poly1305::new_from_slice(&key_to_use)
            .map_err(|e| format!("Erreur d'initialisation du cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&seq_num.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let padded_plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Échec de déchiffrement / MAC invalide".to_string())?;

        unpad_payload(&padded_plaintext).map_err(|e| e.to_string())
    }

    /// Skip les clés de la chaîne jusqu'à atteindre le numéro `until` (exclusif).
    /// Stocke les clés intermédiaires dans `skipped_keys` pour usage ultérieur.
    fn skip_message_keys_until(&mut self, until: u32) -> Result<(), String> {
        if until <= self.recv_seq {
            return Ok(()); // rien à skip
        }

        let to_skip = until - self.recv_seq;
        if to_skip > MAX_SKIP {
            return Err(format!(
                "Trop de messages skipés ({} > MAX_SKIP={})",
                to_skip, MAX_SKIP
            ));
        }

        let mut ck = self.recv_chain_key;
        for seq in self.recv_seq..until {
            let (mk, next_ck) = kdf_chain(&ck, seq);
            self.skipped_keys.insert(seq, mk);
            ck.zeroize();
            ck = next_ck;
        }
        // Avancer l'état de la chaîne
        self.recv_chain_key.zeroize();
        self.recv_chain_key = ck;
        self.recv_seq = until;

        Ok(())
    }
}

// =============================================================================
// HELPERS KDF
// =============================================================================

/// Dérive le root initial depuis master_secret.
fn derive_root(master_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_RATCHET_ROOT_SALT"), master_secret);
    let mut out = [0u8; 32];
    hk.expand(b"AEGIS_ROOT_V2", &mut out).expect("HKDF root");
    out
}

/// Dérive une chaîne d'envoi/réception initiale depuis le root.
fn derive_chain(root: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_CHAIN_SALT"), root);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("HKDF chain");
    out
}

/// KDF symétrique par message : (message_key, next_chain_key).
fn kdf_chain(chain_key: &[u8; 32], seq: u32) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_MSG_KEY_SALT"), chain_key);
    let mut msg_key = [0u8; 32];
    let mut next_ck = [0u8; 32];

    let mut info_msg = [0u8; 8];
    info_msg[..4].copy_from_slice(b"MSG_");
    info_msg[4..].copy_from_slice(&seq.to_le_bytes());
    hk.expand(&info_msg, &mut msg_key).expect("HKDF msg_key");

    let mut info_next = [0u8; 9];
    info_next[..5].copy_from_slice(b"NEXT_");
    info_next[5..].copy_from_slice(&seq.to_le_bytes());
    hk.expand(&info_next, &mut next_ck).expect("HKDF next_chain");

    (msg_key, next_ck)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn handshake() -> (RatchetSession, RatchetSession) {
        let mut rng = OsRng;

        let alice_static = X25519StaticSecret::random_from_rng(&mut rng);
        let alice_static_pub = X25519PublicKey::from(&alice_static);

        let bob_static = X25519StaticSecret::random_from_rng(&mut rng);
        let bob_static_pub = X25519PublicKey::from(&bob_static);

        let alice_ephemeral = X25519StaticSecret::random_from_rng(&mut rng);
        let alice_ephemeral_pub = X25519PublicKey::from(&alice_ephemeral);

        let alice = RatchetSession::new_initiator(&alice_static, &alice_ephemeral, &bob_static_pub);
        let bob = RatchetSession::new_responder(&bob_static, &alice_static_pub, &alice_ephemeral_pub);

        (alice, bob)
    }

    #[test]
    fn test_ratchet_handshake_and_in_order_exchange() {
        let (mut alice, mut bob) = handshake();

        let msg1 = b"Message un";
        let enc1 = alice.encrypt(msg1).unwrap();
        assert!(enc1.len() >= HEADER_SIZE + 512 + 16);
        let dec1 = bob.decrypt(&enc1).unwrap();
        assert_eq!(dec1, msg1);

        let msg2 = b"Message deux";
        let enc2 = alice.encrypt(msg2).unwrap();
        let dec2 = bob.decrypt(&enc2).unwrap();
        assert_eq!(dec2, msg2);
    }

    #[test]
    fn test_ratchet_out_of_order_messages() {
        let (mut alice, mut bob) = handshake();

        let m1 = b"premier";
        let m2 = b"deuxieme";
        let m3 = b"troisieme";
        let e1 = alice.encrypt(m1).unwrap();
        let e2 = alice.encrypt(m2).unwrap();
        let e3 = alice.encrypt(m3).unwrap();

        // Réception dans le désordre : 3, 1, 2
        assert_eq!(bob.decrypt(&e3).unwrap(), m3);
        assert_eq!(bob.decrypt(&e1).unwrap(), m1);
        assert_eq!(bob.decrypt(&e2).unwrap(), m2);
    }

    #[test]
    fn test_ratchet_replay_rejected() {
        let (mut alice, mut bob) = handshake();

        let msg = b"unique";
        let enc = alice.encrypt(msg).unwrap();

        assert_eq!(bob.decrypt(&enc).unwrap(), msg);

        // Replay : doit échouer (clé déjà consommée)
        let result = bob.decrypt(&enc);
        assert!(result.is_err(), "Replay aurait dû être rejeté");
    }

    #[test]
    fn test_ratchet_many_messages() {
        let (mut alice, mut bob) = handshake();

        // 100 messages in-order
        for i in 0..100u32 {
            let msg = format!("msg {}", i);
            let enc = alice.encrypt(msg.as_bytes()).unwrap();
            let dec = bob.decrypt(&enc).unwrap();
            assert_eq!(dec, msg.as_bytes());
        }
    }

    #[test]
    fn test_ratchet_max_skip_protection() {
        let (mut _alice, mut bob) = handshake();

        // Tenter un skip > MAX_SKIP directement
        let result = bob.skip_message_keys_until(MAX_SKIP + 100);
        assert!(result.is_err(), "Skip > MAX_SKIP doit être rejeté");
    }

    #[test]
    fn test_ratchet_bidirectional() {
        let (mut alice, mut bob) = handshake();

        // A → B
        let m_ab = b"Alice vers Bob";
        let e_ab = alice.encrypt(m_ab).unwrap();
        assert_eq!(bob.decrypt(&e_ab).unwrap(), m_ab);

        // B → A
        let m_ba = b"Bob vers Alice";
        let e_ba = bob.encrypt(m_ba).unwrap();
        assert_eq!(alice.decrypt(&e_ba).unwrap(), m_ba);

        // A → B (2e message)
        let m_ab2 = b"Encore un";
        let e_ab2 = alice.encrypt(m_ab2).unwrap();
        assert_eq!(bob.decrypt(&e_ab2).unwrap(), m_ab2);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"courte donnee";
        let padded = pad_payload(data, 512).unwrap();
        assert_eq!(padded.len(), 512);
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(unpadded, data);
    }
}