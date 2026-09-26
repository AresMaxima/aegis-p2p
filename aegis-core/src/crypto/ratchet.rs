use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Pad un payload à un multiple exact de `block_size` octets avec du padding aléatoire (Matelassage anti-analyse de trafic).
pub fn pad_payload(data: &[u8], block_size: usize) -> Result<Vec<u8>, &'static str> {
    if block_size == 0 {
        return Err("Le block_size doit être supérieur à 0");
    }

    let payload_len = data.len();
    if payload_len > u16::MAX as usize {
        return Err("Payload trop grand (maximum 65535 octets)");
    }

    // 2 octets pour stocker la taille réelle du message
    let total_unpadded = 2 + payload_len;
    let padding_needed = (block_size - (total_unpadded % block_size)) % block_size;

    let mut padded = Vec::with_capacity(total_unpadded + padding_needed);

    // Header : Taille réelle sur 2 octets (u16 Big Endian)
    padded.extend_from_slice(&(payload_len as u16).to_be_bytes());
    padded.extend_from_slice(data);

    // Bourrage avec des octets aléatoires
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

/// Représente l'état d'un cliquet de chiffrement (Ratchet) pour une session P2P.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetSession {
    /// Clé d'envoi courante dérivée
    pub sending_key: [u8; 32],
    /// Clé de réception courante dérivée
    pub receiving_key: [u8; 32],
    /// Compteur de messages envoyés
    #[zeroize(skip)]
    pub sequence_send: u64,
    /// Compteur de messages reçus
    #[zeroize(skip)]
    pub sequence_recv: u64,
}

impl RatchetSession {
    /// Initialise une session en mixant une clé éphémère pour garantir la Perfect Forward Secrecy (PFS).
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

        let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_SALT_V1"), &master_secret);
        
        let mut sending_key = [0u8; 32];
        let mut receiving_key = [0u8; 32];
        
        hk.expand(b"AEGIS_RATCHET_SEND", &mut sending_key).expect("HKDF expand failed");
        hk.expand(b"AEGIS_RATCHET_RECV", &mut receiving_key).expect("HKDF expand failed");

        master_secret.zeroize();

        Self {
            sending_key,
            receiving_key,
            sequence_send: 0,
            sequence_recv: 0,
        }
    }

    /// Initialise la session du côté du récepteur.
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

        let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_SALT_V1"), &master_secret);
        
        let mut sending_key = [0u8; 32];
        let mut receiving_key = [0u8; 32];
        
        hk.expand(b"AEGIS_RATCHET_RECV", &mut sending_key).expect("HKDF expand failed");
        hk.expand(b"AEGIS_RATCHET_SEND", &mut receiving_key).expect("HKDF expand failed");

        master_secret.zeroize();

        Self {
            sending_key,
            receiving_key,
            sequence_send: 0,
            sequence_recv: 0,
        }
    }

    /// Applique le matelassage (512 octets), chiffre le message et avance le cliquet d'envoi.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let padded_plaintext = pad_payload(plaintext, 512)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&self.sending_key)
            .map_err(|e| format!("Erreur d'initialisation du cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.sequence_send.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, padded_plaintext.as_slice())
            .map_err(|_| "Échec du chiffrement du message".to_string())?;

        self.advance_send_key();
        self.sequence_send += 1;

        Ok(ciphertext)
    }

    /// Déchiffre le message, extrait le payload en retirant le padding et avance le cliquet de réception.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.receiving_key)
            .map_err(|e| format!("Erreur d'initialisation du cipher: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.sequence_recv.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let padded_plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Échec de déchiffrement / MAC invalide".to_string())?;

        let plaintext = unpad_payload(&padded_plaintext)?;

        self.advance_recv_key();
        self.sequence_recv += 1;

        Ok(plaintext)
    }

    /// Renouvelle la clé d'envoi via HKDF (Ratchet Step)
    fn advance_send_key(&mut self) {
        let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_RATCHET_STEP"), &self.sending_key);
        let mut next_key = [0u8; 32];
        hk.expand(b"AEGIS_NEXT_KEY", &mut next_key).expect("HKDF expand failed");
        self.sending_key.zeroize();
        self.sending_key = next_key;
    }

    /// Renouvelle la clé de réception via HKDF (Ratchet Step)
    fn advance_recv_key(&mut self) {
        let hk = Hkdf::<Sha256>::new(Some(b"AEGIS_RATCHET_STEP"), &self.receiving_key);
        let mut next_key = [0u8; 32];
        hk.expand(b"AEGIS_NEXT_KEY", &mut next_key).expect("HKDF expand failed");
        self.receiving_key.zeroize();
        self.receiving_key = next_key;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_ratchet_handshake_and_exchange_with_padding() {
        let mut rng = OsRng;

        let alice_static = X25519StaticSecret::random_from_rng(&mut rng);
        let alice_static_pub = X25519PublicKey::from(&alice_static);

        let bob_static = X25519StaticSecret::random_from_rng(&mut rng);
        let bob_static_pub = X25519PublicKey::from(&bob_static);

        let alice_ephemeral = X25519StaticSecret::random_from_rng(&mut rng);
        let alice_ephemeral_pub = X25519PublicKey::from(&alice_ephemeral);

        let mut alice_session = RatchetSession::new_initiator(&alice_static, &alice_ephemeral, &bob_static_pub);
        let mut bob_session = RatchetSession::new_responder(&bob_static, &alice_static_pub, &alice_ephemeral_pub);

        let secret_msg = b"Message Ultra Secret Aegis P2P";
        let encrypted = alice_session.encrypt(secret_msg).unwrap();

        // Vérification OpSec : La taille du ciphertext doit correspondre à 512 octets de payload + 16 octets de tag MAC Poly1305
        assert_eq!(encrypted.len(), 528);

        let decrypted = bob_session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, secret_msg);

        let reply_msg = b"Bien recu en toute securite!";
        let encrypted_reply = bob_session.encrypt(reply_msg).unwrap();
        assert_eq!(encrypted_reply.len(), 528);

        let decrypted_reply = alice_session.decrypt(&encrypted_reply).unwrap();
        assert_eq!(decrypted_reply, reply_msg);
    }
}