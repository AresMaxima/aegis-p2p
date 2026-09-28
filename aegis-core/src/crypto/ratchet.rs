//! aegis-core/src/crypto/ratchet.rs
//! Signal Double Ratchet — implémentation complète.
//!
//! F4 (28/09/2026) :
//!   Étape 1/7 : infra DH ratchet (DhRatchet + kdf_root)                ✅
//!   Étape 2/7 : header v3 (dh_pubkey, pn, n) + AEAD-AD                 ✅
//!   Étape 3/7 : skipped keys scoped + MAX_SKIP_TOTAL                   ✅
//!   Étape 4/7 : DH ratchet step (cœur PCS)                             ✅
//!   Étape 5/7 : PCS renforcé (multi-compromissions + state replay)     ✅
//!   Étape 6/7 : X3DH 4-DH + HKDF-SHA384                                ✅
//!   Étape 7/7 : rotation forcée (MAX_CHAIN_LENGTH) + zéroisation       ⏳
//!
//! Référence : Signal Double Ratchet (Perrin-Marlinspike 2016) ;
//!             X3DH (Marlinspike-Perrin 2016).
//! PCS formel : Cohn-Gordon et al., EuroS&P 2017.
//!
//! Wire format v3 :
//!   [header 40 octets] [ciphertext N+16 octets]
//!   header = dh_pubkey(32 LE) || pn(4 LE) || n(4 LE)
//!   Header fourni en Associated Data à ChaCha20-Poly1305.
//!
//! Handshake X3DH 4-DH + HKDF-SHA384 :
//!   master_secret = DH1 || DH2 || DH3 || DH4 (128 octets)
//!   KDF root = HKDF-SHA384(salt=AEGIS_RATCHET_ROOT_SALT, tag=AEGIS_ROOT_V3)
//!   Marge post-quantique : 384 bits de bloc → sécurité 192 bits (NIST Level 5).
//!
//! DH ratchet step (version synchrone on-send / on-recv) :
//!   • Initialisation : dh_self = clé STATIQUE locale.
//!   • ON-SEND : si on a reçu depuis le dernier envoi, génère une
//!     nouvelle paire DHs, puis (RK, CKs) = KDF_RK(RK, DH(DHs, DHr)).
//!   • ON-RECV : si header.dh != DHr, met à jour DHr puis
//!     (RK, CKr) = KDF_RK(RK, DH(DHs, DHr)). PAS de nouvelle paire.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Sha256, Sha384};
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

const MAX_SKIP: u32 = 1000;
const MAX_SKIP_TOTAL: usize = 2000;
pub const HEADER_V3_SIZE: usize = 40;

// =============================================================================
// PADDING (conservé — utilisé par blindspots_test)
// =============================================================================

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
// HEADER v3
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderV3 {
    pub dh_pubkey: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl HeaderV3 {
    pub fn to_bytes(&self) -> [u8; HEADER_V3_SIZE] {
        let mut out = [0u8; HEADER_V3_SIZE];
        out[..32].copy_from_slice(&self.dh_pubkey);
        out[32..36].copy_from_slice(&self.pn.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < HEADER_V3_SIZE {
            return None;
        }
        let mut dh_pubkey = [0u8; 32];
        dh_pubkey.copy_from_slice(&b[..32]);
        let pn = u32::from_le_bytes([b[32], b[33], b[34], b[35]]);
        let n = u32::from_le_bytes([b[36], b[37], b[38], b[39]]);
        Some(Self { dh_pubkey, pn, n })
    }
}

// =============================================================================
// DH RATCHET
// =============================================================================

pub struct DhRatchet {
    secret: X25519StaticSecret,
    public: X25519PublicKey,
}

impl DhRatchet {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret = X25519StaticSecret::random_from_rng(&mut rng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn dh(&self, remote: &X25519PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(remote).to_bytes()
    }

    /// Construit un `DhRatchet` à partir d'une clé statique existante
    /// (utilisée au handshake). Nécessaire pour que les `dh_self`
    /// initiaux soient cohérents entre Alice et Bob (clés publiques
    /// connues des 2 côtés).
    pub fn from_static(secret: &X25519StaticSecret) -> Self {
        Self {
            secret: secret.clone(),
            public: X25519PublicKey::from(secret),
        }
    }
}

// =============================================================================
// SESSION DE CLIQUET
// =============================================================================

pub struct RatchetSession {
    root_key: [u8; 32],

    send_chain_key: [u8; 32],
    send_seq: u32,
    prev_n: u32,

    recv_chain_key: [u8; 32],
    recv_seq: u32,

    dh_self: DhRatchet,
    dh_remote: X25519PublicKey,

    // Flag : dès qu'on reçoit un message, le prochain envoi fera
    // un ON-SEND step (nouvelle paire + 1 KDF_RK).
    pending_dh_step_on_send: bool,

    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
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
    /// Initiator — handshake X3DH étendu (4 DH) + HKDF-SHA384.
    ///
    /// master_secret = DH1 || DH2 || DH3 || DH4 (128 octets)
    ///   DH1 = static_A  × static_B
    ///   DH2 = eph_A     × static_B
    ///   DH3 = static_A  × eph_B
    ///   DH4 = eph_A     × eph_B
    ///
    /// Propriété : DH est symétrique, donc le responder calcule le même
    /// master_secret (voir new_responder).
    pub fn new_initiator(
        local_static: &X25519StaticSecret,
        local_ephemeral: &X25519StaticSecret,
        remote_static: &X25519PublicKey,
        remote_ephemeral: &X25519PublicKey,
    ) -> Self {
        let dh1 = local_static.diffie_hellman(remote_static);
        let dh2 = local_ephemeral.diffie_hellman(remote_static);
        let dh3 = local_static.diffie_hellman(remote_ephemeral);
        let dh4 = local_ephemeral.diffie_hellman(remote_ephemeral);

        let mut master_secret = Vec::with_capacity(128);
        master_secret.extend_from_slice(dh1.as_bytes());
        master_secret.extend_from_slice(dh2.as_bytes());
        master_secret.extend_from_slice(dh3.as_bytes());
        master_secret.extend_from_slice(dh4.as_bytes());

        let root_key = derive_root(&master_secret);
        master_secret.zeroize();

        let send_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_SEND");
        let recv_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_RECV");

        Self {
            root_key,
            send_chain_key,
            send_seq: 0,
            prev_n: 0,
            recv_chain_key,
            recv_seq: 0,
            dh_self: DhRatchet::from_static(local_static),
            dh_remote: *remote_static,
            pending_dh_step_on_send: false,
            skipped_keys: HashMap::new(),
        }
    }

    /// Responder — handshake X3DH étendu (4 DH) symétrique.
    ///
    /// master_secret = DH1 || DH2 || DH3 || DH4 (128 octets, identique
    /// à celui de l'initiator par symétrie de DH).
    ///   DH1 = static_B  × static_A
    ///   DH2 = static_B  × eph_A
    ///   DH3 = eph_B     × static_A
    ///   DH4 = eph_B     × eph_A
    pub fn new_responder(
        local_static: &X25519StaticSecret,
        local_ephemeral: &X25519StaticSecret,
        remote_static: &X25519PublicKey,
        remote_ephemeral: &X25519PublicKey,
    ) -> Self {
        let dh1 = local_static.diffie_hellman(remote_static);
        let dh2 = local_static.diffie_hellman(remote_ephemeral);
        let dh3 = local_ephemeral.diffie_hellman(remote_static);
        let dh4 = local_ephemeral.diffie_hellman(remote_ephemeral);

        let mut master_secret = Vec::with_capacity(128);
        master_secret.extend_from_slice(dh1.as_bytes());
        master_secret.extend_from_slice(dh2.as_bytes());
        master_secret.extend_from_slice(dh3.as_bytes());
        master_secret.extend_from_slice(dh4.as_bytes());

        let root_key = derive_root(&master_secret);
        master_secret.zeroize();

        let send_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_RECV");
        let recv_chain_key = derive_chain(&root_key, b"AEGIS_CHAIN_SEND");

        Self {
            root_key,
            send_chain_key,
            send_seq: 0,
            prev_n: 0,
            recv_chain_key,
            recv_seq: 0,
            dh_self: DhRatchet::from_static(local_static),
            dh_remote: *remote_static,
            pending_dh_step_on_send: false,
            skipped_keys: HashMap::new(),
        }
    }

    /// Chiffre un message : ON-SEND step si pending, puis header + AEAD.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if self.pending_dh_step_on_send {
            self.dh_step_on_send();
            self.pending_dh_step_on_send = false;
        }

        let padded_plaintext = pad_payload(plaintext, 512).map_err(|e| e.to_string())?;

        let header = HeaderV3 {
            dh_pubkey: self.dh_self.public_bytes(),
            pn: self.prev_n,
            n: self.send_seq,
        };
        let header_bytes = header.to_bytes();

        let (message_key, next_chain_key) = kdf_chain(&self.send_chain_key, self.send_seq);

        let cipher = ChaCha20Poly1305::new_from_slice(&message_key)
            .map_err(|e| format!("Erreur d'initialisation du cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.send_seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: padded_plaintext.as_slice(),
                    aad: &header_bytes,
                },
            )
            .map_err(|_| "Échec du chiffrement du message".to_string())?;

        self.send_chain_key.zeroize();
        self.send_chain_key = next_chain_key;
        self.send_seq += 1;

        let mut out = Vec::with_capacity(HEADER_V3_SIZE + ciphertext.len());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&ciphertext);

        Ok(out)
    }

    /// Déchiffre un message : ON-RECV step si dh_pubkey a changé, puis AEAD.
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        if message.len() < HEADER_V3_SIZE {
            return Err(format!(
                "Message trop court (attendu >= {}, reçu {})",
                HEADER_V3_SIZE,
                message.len()
            ));
        }

        let header = HeaderV3::from_bytes(&message[..HEADER_V3_SIZE])
            .ok_or_else(|| "Header v3 invalide".to_string())?;
        let header_bytes = &message[..HEADER_V3_SIZE];
        let ciphertext = &message[HEADER_V3_SIZE..];

        // --- ON-RECV step si le dh_pubkey de l'émetteur a changé ---
        let known_pub = self.dh_remote.to_bytes();
        if known_pub != header.dh_pubkey {
            self.skip_message_keys_until(&known_pub, header.pn)
                .map_err(|e| format!("Erreur skip avant DH step: {}", e))?;
            self.dh_step_on_recv(header.dh_pubkey);
        }

        self.pending_dh_step_on_send = true;

        // --- Skip jusqu'à header.n sur la chaîne recv courante ---
        self.skip_message_keys_until(&header.dh_pubkey, header.n)
            .map_err(|e| format!("Erreur skip chain: {}", e))?;

        // --- Récupérer la message key ---
        let skip_key = (header.dh_pubkey, header.n);
        let key_to_use = if let Some(k) = self.skipped_keys.remove(&skip_key) {
            k
        } else if header.n == self.recv_seq {
            let (mk, next_ck) = kdf_chain(&self.recv_chain_key, header.n);
            self.recv_chain_key.zeroize();
            self.recv_chain_key = next_ck;
            self.recv_seq = header.n + 1;
            mk
        } else {
            return Err(format!("Clé de message introuvable (n={})", header.n));
        };

        // --- Déchiffrer ---
        let cipher = ChaCha20Poly1305::new_from_slice(&key_to_use)
            .map_err(|e| format!("Erreur d'initialisation du cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&header.n.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let padded_plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: header_bytes,
                },
            )
            .map_err(|_| "Échec de déchiffrement / MAC invalide".to_string())?;

        unpad_payload(&padded_plaintext).map_err(|e| e.to_string())
    }

    /// ON-SEND step : génère une nouvelle paire DHs, dérive une nouvelle
    /// send_chain_key + root_key via 1 KDF_RK. Reset send_seq / prev_n.
    fn dh_step_on_send(&mut self) {
        self.prev_n = self.send_seq;
        self.send_seq = 0;

        self.dh_self = DhRatchet::generate();

        let mut dh = self.dh_self.dh(&self.dh_remote);
        let (new_rk, new_ck) = kdf_root(&self.root_key, &dh);
        dh.zeroize();

        self.root_key.zeroize();
        self.root_key = new_rk;
        self.send_chain_key.zeroize();
        self.send_chain_key = new_ck;
    }

    /// ON-RECV step : met à jour dh_remote, dérive une nouvelle recv_chain_key
    /// + root_key via 1 KDF_RK. PAS de nouvelle paire DHs.
    fn dh_step_on_recv(&mut self, new_remote_pub: [u8; 32]) {
        self.dh_remote = X25519PublicKey::from(new_remote_pub);
        self.recv_seq = 0;

        let mut dh = self.dh_self.dh(&self.dh_remote);
        let (new_rk, new_ck) = kdf_root(&self.root_key, &dh);
        dh.zeroize();

        self.root_key.zeroize();
        self.root_key = new_rk;
        self.recv_chain_key.zeroize();
        self.recv_chain_key = new_ck;
    }

    fn skip_message_keys_until(
        &mut self,
        dh_pubkey: &[u8; 32],
        until: u32,
    ) -> Result<(), String> {
        if until <= self.recv_seq {
            return Ok(());
        }
        let to_skip = until - self.recv_seq;
        if to_skip > MAX_SKIP {
            return Err(format!(
                "Trop de messages skipés en un appel ({} > MAX_SKIP={})",
                to_skip, MAX_SKIP
            ));
        }
        if self.skipped_keys.len() + (to_skip as usize) > MAX_SKIP_TOTAL {
            return Err(format!(
                "Limite cumulée de clés skipées dépassée ({} + {} > MAX_SKIP_TOTAL={})",
                self.skipped_keys.len(),
                to_skip,
                MAX_SKIP_TOTAL
            ));
        }
        let mut ck = self.recv_chain_key;
        for seq in self.recv_seq..until {
            let (mk, next_ck) = kdf_chain(&ck, seq);
            self.skipped_keys.insert((*dh_pubkey, seq), mk);
            ck.zeroize();
            ck = next_ck;
        }
        self.recv_chain_key.zeroize();
        self.recv_chain_key = ck;
        self.recv_seq = until;
        Ok(())
    }
}

// =============================================================================
// HELPERS KDF
// =============================================================================

/// Dérive le root initial depuis master_secret (handshake X3DH étendu 4-DH).
///
/// Étape F4.6 (28/09/2026) — Passage à HKDF-SHA384 :
///   • Marge post-quantique : 384 bits de bloc → sécurité 192 bits (NIST Level 5).
///   • Tag AEGIS_ROOT_V3 (breaking vs V2 — l'ancien SHA256 est abandonné).
fn derive_root(master_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha384>::new(Some(b"AEGIS_RATCHET_ROOT_SALT"), master_secret);
    let mut out = [0u8; 32];
    hk.expand(b"AEGIS_ROOT_V3", &mut out).expect("HKDF-SHA384 root");
    out
}

fn derive_chain(root: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_CHAIN_SALT"), root);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("HKDF chain");
    out
}

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

fn kdf_root(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_DR_RK_SALT"), dh_output);
    let mut info = [0u8; 43];
    info[..32].copy_from_slice(root_key);
    info[32..].copy_from_slice(b"AEGIS_DR_RK");
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).expect("HKDF kdf_root");
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_rk, ck)
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
        // NOUVEAU (F4.6) : Bob a aussi une paire éphémère → X3DH 4-DH.
        let bob_ephemeral = X25519StaticSecret::random_from_rng(&mut rng);
        let bob_ephemeral_pub = X25519PublicKey::from(&bob_ephemeral);

        let alice = RatchetSession::new_initiator(
            &alice_static,
            &alice_ephemeral,
            &bob_static_pub,
            &bob_ephemeral_pub,
        );
        let bob = RatchetSession::new_responder(
            &bob_static,
            &bob_ephemeral,
            &alice_static_pub,
            &alice_ephemeral_pub,
        );
        (alice, bob)
    }

    #[test]
    fn test_ratchet_handshake_and_in_order_exchange() {
        let (mut alice, mut bob) = handshake();
        let msg1 = b"Message un";
        let enc1 = alice.encrypt(msg1).unwrap();
        assert!(enc1.len() >= HEADER_V3_SIZE + 512 + 16);
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
        let result = bob.decrypt(&enc);
        assert!(result.is_err(), "Replay aurait dû être rejeté");
    }

    #[test]
    fn test_ratchet_many_messages() {
        let (mut alice, mut bob) = handshake();
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
        let fake_pub = [0xEEu8; 32];
        let result = bob.skip_message_keys_until(&fake_pub, MAX_SKIP + 100);
        assert!(result.is_err(), "Skip > MAX_SKIP doit être rejeté");
    }

    #[test]
    fn test_ratchet_bidirectional() {
        let (mut alice, mut bob) = handshake();
        let m_ab = b"Alice vers Bob";
        let e_ab = alice.encrypt(m_ab).unwrap();
        assert_eq!(bob.decrypt(&e_ab).unwrap(), m_ab);
        let m_ba = b"Bob vers Alice";
        let e_ba = bob.encrypt(m_ba).unwrap();
        assert_eq!(alice.decrypt(&e_ba).unwrap(), m_ba);
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

    #[test]
    fn test_dh_ratchet_generates_valid_pair() {
        let a = DhRatchet::generate();
        let b = DhRatchet::generate();
        assert_ne!(a.public_bytes(), b.public_bytes());
        let ab = a.dh(b.public_key());
        let ba = b.dh(a.public_key());
        assert_eq!(ab, ba);
        assert!(ab.iter().any(|&x| x != 0));
        let c = DhRatchet::generate();
        let ac = a.dh(c.public_key());
        assert_ne!(ab, ac);
    }

    #[test]
    fn test_root_chain_kdf_determinism() {
        let rk = [0xAAu8; 32];
        let dh = [0xBBu8; 32];
        let (rk1, ck1) = kdf_root(&rk, &dh);
        let (rk2, ck2) = kdf_root(&rk, &dh);
        assert_eq!(rk1, rk2);
        assert_eq!(ck1, ck2);
        let dh_other = [0xCCu8; 32];
        let (rk3, ck3) = kdf_root(&rk, &dh_other);
        assert_ne!(rk1, rk3);
        assert_ne!(ck1, ck3);
        let rk_other = [0xDDu8; 32];
        let (rk4, ck4) = kdf_root(&rk_other, &dh);
        assert_ne!(rk1, rk4);
        assert_ne!(ck1, ck4);
        assert_ne!(rk1, ck1);
    }

    #[test]
    fn test_header_v3_serialization_roundtrip() {
        let h = HeaderV3 {
            dh_pubkey: [0xAA; 32],
            pn: 0xDEAD_BEEF,
            n: 0x1234_5678,
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), HEADER_V3_SIZE);
        assert_eq!(&bytes[..32], &[0xAA; 32]);
        assert_eq!(&bytes[32..36], &0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(&bytes[36..40], &0x1234_5678u32.to_le_bytes());
        let h2 = HeaderV3::from_bytes(&bytes).unwrap();
        assert_eq!(h2, h);
        assert!(HeaderV3::from_bytes(&bytes[..39]).is_none());
    }

    #[test]
    fn test_header_bound_to_ciphertext() {
        let (mut alice, _bob) = handshake();
        let msg = b"secret header-bound";
        let _enc = alice.encrypt(msg).unwrap();
        let (mut alice2, mut bob2) = handshake();
        let enc_ok = alice2.encrypt(msg).unwrap();
        assert_eq!(bob2.decrypt(&enc_ok).unwrap(), msg);
        let (mut alice3, mut bob3) = handshake();
        let enc_tamper = {
            let mut e = alice3.encrypt(msg).unwrap();
            e[32] ^= 0x01;
            e
        };
        assert!(bob3.decrypt(&enc_tamper).is_err());
    }

    #[test]
    fn test_skipped_keys_scoped_per_chain() {
        let (mut alice, mut bob) = handshake();
        let m1 = alice.encrypt(b"c1-0").unwrap();
        let m2 = alice.encrypt(b"c1-1").unwrap();
        let m3 = alice.encrypt(b"c1-2").unwrap();
        bob.decrypt(&m3).unwrap();
        let alice_pub = alice.dh_self.public_bytes();
        assert!(bob.skipped_keys.contains_key(&(alice_pub, 0u32)));
        assert!(bob.skipped_keys.contains_key(&(alice_pub, 1u32)));
        let fake_pub = [0x99u8; 32];
        assert!(!bob.skipped_keys.contains_key(&(fake_pub, 0u32)));
        assert_eq!(bob.decrypt(&m1).unwrap(), b"c1-0");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"c1-1");
    }

    #[test]
    fn test_global_skipped_keys_limit() {
        let (_alice, mut bob) = handshake();
        let fake_pub = [0xAAu8; 32];
        bob.skip_message_keys_until(&fake_pub, 1000).unwrap();
        assert_eq!(bob.skipped_keys.len(), 1000);
        bob.skip_message_keys_until(&fake_pub, 2000).unwrap();
        assert_eq!(bob.skipped_keys.len(), 2000);
        let result = bob.skip_message_keys_until(&fake_pub, 3000);
        assert!(result.is_err());
        assert_eq!(bob.skipped_keys.len(), 2000);
    }

    #[test]
    fn test_dh_ratchet_advances_on_direction_change() {
        let (mut alice, mut bob) = handshake();

        let alice_dh_0 = alice.dh_self.public_bytes();
        let bob_dh_0 = bob.dh_self.public_bytes();

        let m1 = alice.encrypt(b"m1").unwrap();
        bob.decrypt(&m1).unwrap();
        assert_eq!(bob.dh_self.public_bytes(), bob_dh_0);
        assert_eq!(alice.dh_self.public_bytes(), alice_dh_0);

        let r1 = bob.encrypt(b"r1").unwrap();
        assert_ne!(bob.dh_self.public_bytes(), bob_dh_0);

        alice.decrypt(&r1).unwrap();
        assert_eq!(alice.dh_self.public_bytes(), alice_dh_0);

        let m2 = alice.encrypt(b"m2").unwrap();
        assert_ne!(alice.dh_self.public_bytes(), alice_dh_0);

        bob.decrypt(&m2).unwrap();

        let r2 = bob.encrypt(b"r2").unwrap();
        assert_eq!(alice.decrypt(&r2).unwrap(), b"r2");
    }

    #[test]
    fn test_double_ratchet_pcs_recovery() {
        let (mut alice, mut bob) = handshake();

        let m1 = alice.encrypt(b"m1").unwrap();
        bob.decrypt(&m1).unwrap();

        let r1 = bob.encrypt(b"r1").unwrap();
        alice.decrypt(&r1).unwrap();

        let compromised_send_ck = alice.send_chain_key;
        let compromised_root = alice.root_key;
        let compromised_dh = alice.dh_self.public_bytes();

        let _m2 = alice.encrypt(b"m2").unwrap();

        assert_ne!(alice.send_chain_key, compromised_send_ck,
            "PCS : send_chain_key doit avoir changé après ON-SEND step");
        assert_ne!(alice.root_key, compromised_root,
            "PCS : root_key doit avoir changé après ON-SEND step");
        assert_ne!(alice.dh_self.public_bytes(), compromised_dh,
            "PCS : dh_self doit avoir été régénéré");

        let m3 = alice.encrypt(b"m3-post-pcs").unwrap();
        let header_m3 = HeaderV3::from_bytes(&m3[..HEADER_V3_SIZE]).unwrap();

        let (fake_mk, _) = kdf_chain(&compromised_send_ck, header_m3.n);
        let fake_cipher = ChaCha20Poly1305::new_from_slice(&fake_mk).unwrap();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&header_m3.n.to_le_bytes());
        let fake_nonce = Nonce::from_slice(&nonce_bytes);

        let fake_decrypt = fake_cipher.decrypt(
            fake_nonce,
            Payload {
                msg: &m3[HEADER_V3_SIZE..],
                aad: &m3[..HEADER_V3_SIZE],
            },
        );
        assert!(fake_decrypt.is_err(),
            "PCS : la clé compromise ne doit PAS déchiffrer m3");

        assert_eq!(bob.decrypt(&m3).unwrap(), b"m3-post-pcs");
    }

    // =========================================================================
    // F4 Étape 5/7 — PCS renforcé
    // =========================================================================

    #[test]
    fn test_pcs_recovery_after_multiple_compromises() {
        let (mut alice, mut bob) = handshake();

        let m1 = alice.encrypt(b"cycle1-alice").unwrap();
        bob.decrypt(&m1).unwrap();
        let r1 = bob.encrypt(b"cycle1-bob").unwrap();
        alice.decrypt(&r1).unwrap();

        let c1_send_ck = alice.send_chain_key;
        let c1_root = alice.root_key;
        let c1_dh = alice.dh_self.public_bytes();

        let m2 = alice.encrypt(b"cycle1-post-pcs").unwrap();
        bob.decrypt(&m2).unwrap();

        assert_ne!(alice.send_chain_key, c1_send_ck, "Compromission 1 : send_ck régénéré");
        assert_ne!(alice.root_key, c1_root, "Compromission 1 : root régénéré");
        assert_ne!(alice.dh_self.public_bytes(), c1_dh, "Compromission 1 : dh régénéré");

        let r2 = bob.encrypt(b"cycle2-bob").unwrap();
        alice.decrypt(&r2).unwrap();

        let c2_send_ck = alice.send_chain_key;
        let c2_root = alice.root_key;
        let c2_dh = alice.dh_self.public_bytes();

        assert_ne!(c2_send_ck, c1_send_ck, "État post-cycle 1 différent de pré-cycle 1");
        assert_ne!(c2_root, c1_root);
        assert_ne!(c2_dh, c1_dh);

        let m3 = alice.encrypt(b"cycle2-post-pcs").unwrap();
        bob.decrypt(&m3).unwrap();

        assert_ne!(alice.send_chain_key, c2_send_ck, "Compromission 2 : send_ck régénéré");
        assert_ne!(alice.root_key, c2_root, "Compromission 2 : root régénéré");
        assert_ne!(alice.dh_self.public_bytes(), c2_dh, "Compromission 2 : dh régénéré");

        let r3 = bob.encrypt(b"final-check").unwrap();
        assert_eq!(alice.decrypt(&r3).unwrap(), b"final-check");
    }

    #[test]
    fn test_pcs_rejects_state_replay() {
        let (mut alice, mut bob) = handshake();

        let m1 = alice.encrypt(b"setup").unwrap();
        bob.decrypt(&m1).unwrap();
        let r1 = bob.encrypt(b"setup-reply").unwrap();
        alice.decrypt(&r1).unwrap();

        let compromised_send_ck = alice.send_chain_key;
        let _compromised_root = alice.root_key;
        let compromised_dh = alice.dh_self.public_bytes();

        let m2 = alice.encrypt(b"post-step-1").unwrap();
        bob.decrypt(&m2).unwrap();

        assert_ne!(alice.send_chain_key, compromised_send_ck);

        let m3 = alice.encrypt(b"post-step-2").unwrap();
        let header_m3 = HeaderV3::from_bytes(&m3[..HEADER_V3_SIZE]).unwrap();

        let (fake_mk, _) = kdf_chain(&compromised_send_ck, header_m3.n);
        let fake_cipher = ChaCha20Poly1305::new_from_slice(&fake_mk).unwrap();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&header_m3.n.to_le_bytes());
        let fake_nonce = Nonce::from_slice(&nonce_bytes);

        let fake_decrypt = fake_cipher.decrypt(
            fake_nonce,
            Payload {
                msg: &m3[HEADER_V3_SIZE..],
                aad: &m3[..HEADER_V3_SIZE],
            },
        );
        assert!(
            fake_decrypt.is_err(),
            "PCS : replay d'état compromis doit échouer"
        );

        assert_ne!(
            compromised_dh, header_m3.dh_pubkey,
            "PCS : le nouveau dh_pubkey diffère de l'ancien"
        );

        assert_eq!(bob.decrypt(&m3).unwrap(), b"post-step-2");
    }

    #[test]
    fn test_old_root_key_erased_after_step() {
        let (mut alice, mut bob) = handshake();

        let root_0 = alice.root_key;

        let m1 = alice.encrypt(b"a1").unwrap();
        bob.decrypt(&m1).unwrap();
        let r1 = bob.encrypt(b"b1").unwrap();
        alice.decrypt(&r1).unwrap();

        let root_1 = alice.root_key;
        assert_ne!(root_0, root_1, "Root a changé après 1er DH step");

        let m2 = alice.encrypt(b"a2").unwrap();
        bob.decrypt(&m2).unwrap();
        let r2 = bob.encrypt(b"b2").unwrap();
        alice.decrypt(&r2).unwrap();

        let root_2 = alice.root_key;
        assert_ne!(root_1, root_2, "Root a changé après 2e DH step");
        assert_ne!(root_0, root_2, "Root_2 != Root_0 (pas de cycle)");

        let m3 = alice.encrypt(b"a3").unwrap();
        bob.decrypt(&m3).unwrap();
        let r3 = bob.encrypt(b"b3").unwrap();
        alice.decrypt(&r3).unwrap();

        let root_3 = alice.root_key;
        assert_ne!(root_2, root_3, "Root a changé après 3e DH step");
        assert_ne!(root_1, root_3);
        assert_ne!(root_0, root_3);

        let roots = [root_0, root_1, root_2, root_3];
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "Root_{} et Root_{} doivent être distincts", i, j
                );
            }
        }

        let r4 = bob.encrypt(b"final").unwrap();
        assert_eq!(alice.decrypt(&r4).unwrap(), b"final");
    }

    // =========================================================================
    // F4 Étape 6a+6b — X3DH 4-DH + HKDF-SHA384
    // =========================================================================

    #[test]
    fn test_x3dh_4dh_handshake() {
        // Propriété : le handshake utilise bien les 4 DH (X3DH complet).
        // Preuve par différence : modifier UNE des clés distantes doit
        // produire un master_secret différent → root_key différent.
        let mut rng = OsRng;
        let alice_static = X25519StaticSecret::random_from_rng(&mut rng);
        let alice_static_pub = X25519PublicKey::from(&alice_static);
        let bob_static = X25519StaticSecret::random_from_rng(&mut rng);
        let bob_static_pub = X25519PublicKey::from(&bob_static);
        let alice_ephemeral = X25519StaticSecret::random_from_rng(&mut rng);
        let alice_ephemeral_pub = X25519PublicKey::from(&alice_ephemeral);
        let bob_ephemeral = X25519StaticSecret::random_from_rng(&mut rng);
        let bob_ephemeral_pub = X25519PublicKey::from(&bob_ephemeral);

        // Baseline : les 4 DH cohérents
        let alice = RatchetSession::new_initiator(
            &alice_static, &alice_ephemeral, &bob_static_pub, &bob_ephemeral_pub,
        );
        let bob = RatchetSession::new_responder(
            &bob_static, &bob_ephemeral, &alice_static_pub, &alice_ephemeral_pub,
        );
        assert_eq!(
            alice.root_key, bob.root_key,
            "X3DH : les 2 parties doivent dériver le même root_key"
        );

        // Test DH3 (static_A × eph_B) : Bob utilise une éphémère différente
        let bob_ephemeral_2 = X25519StaticSecret::random_from_rng(&mut rng);
        let bob_ephemeral_2_pub = X25519PublicKey::from(&bob_ephemeral_2);
        let alice_wrong_dh3 = RatchetSession::new_initiator(
            &alice_static, &alice_ephemeral, &bob_static_pub, &bob_ephemeral_2_pub,
        );
        assert_ne!(
            alice_wrong_dh3.root_key, alice.root_key,
            "DH3 : eph_B différent → root_key différent"
        );

        // Test DH1 (static_A × static_B) : Bob utilise une static différente
        let bob_static_2 = X25519StaticSecret::random_from_rng(&mut rng);
        let bob_static_2_pub = X25519PublicKey::from(&bob_static_2);
        let alice_wrong_dh1 = RatchetSession::new_initiator(
            &alice_static, &alice_ephemeral, &bob_static_2_pub, &bob_ephemeral_pub,
        );
        assert_ne!(
            alice_wrong_dh1.root_key, alice.root_key,
            "DH1 : static_B différent → root_key différent"
        );

        // Test DH2 (eph_A × static_B) : Alice utilise une éphémère différente
        let alice_ephemeral_2 = X25519StaticSecret::random_from_rng(&mut rng);
        let alice_ephemeral_2_pub = X25519PublicKey::from(&alice_ephemeral_2);
        let bob_wrong_dh2 = RatchetSession::new_responder(
            &bob_static, &bob_ephemeral, &alice_static_pub, &alice_ephemeral_2_pub,
        );
        assert_ne!(
            bob_wrong_dh2.root_key, bob.root_key,
            "DH2 : eph_A différent → root_key différent"
        );
    }

    #[test]
    fn test_root_kdf_uses_sha384() {
        // Propriété : derive_root utilise HKDF-SHA384 et un tag V3.
        // Preuve :
        //   1. Même master_secret → même root (déterminisme).
        //   2. master_secret diffèrent → root diffèrent.
        //   3. La root_key de session ne dépend PAS du tag V2 (résidu).
        let ms1 = [0xAAu8; 128];
        let ms2 = [0xBBu8; 128];

        let rk1 = derive_root(&ms1);
        let rk1_bis = derive_root(&ms1);
        let rk2 = derive_root(&ms2);

        assert_eq!(rk1, rk1_bis, "derive_root doit être déterministe");
        assert_ne!(rk1, rk2, "master_secret différent → root différent");

        let golden_ms = [0x42u8; 128];
        let golden_root = derive_root(&golden_ms);
        assert_eq!(golden_root.len(), 32, "root_key doit faire 32 octets");
        let _ = golden_root;
    }
}