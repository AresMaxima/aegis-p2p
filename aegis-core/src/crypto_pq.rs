//! aegis-core/src/crypto_pq.rs
//! Encapsulation Hybride Post-Quantique ML-KEM-768 + X25519 (Constant-Time)
//! et Chiffrement VectorisÃ© ARM NEON / Hardware Extensions (CdCM v2.2-RC1).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768::{
    decapsulate as kyber_decapsulate, encapsulate as kyber_encapsulate, keypair as kyber_keypair,
    Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroize;

use crate::secure_buffer::SecureBuffer;

pub const AES_256_GCM_KEY_LEN: usize = 32;
pub const AES_256_GCM_NONCE_LEN: usize = 12;

/// ClÃ© publique hybride contenant les composantes ML-KEM-768 et X25519
#[derive(Clone)]
pub struct HybridPublicKey {
    pub kyber_pk: KyberPublicKey,
    pub x25519_pk: X25519PublicKey,
}

/// ClÃ© privÃ©e hybride
pub struct HybridSecretKey {
    pub kyber_sk: KyberSecretKey,
    pub x25519_sk: X25519SecretKey,
}

/// Paquet d'encapsulation Ã  transmettre au pair
#[derive(Clone)]
pub struct HybridEncapsulationPayload {
    pub kyber_ct: KyberCiphertext,
    pub x25519_eph_pk: X25519PublicKey,
}

pub struct HybridKeyExchange;

impl HybridKeyExchange {
    pub fn generate_keypair() -> (HybridPublicKey, HybridSecretKey) {
        generate_hybrid_keypair()
    }

    pub fn encapsulate(peer_pk: &HybridPublicKey) -> (HybridEncapsulationPayload, SecureBuffer) {
        encapsulate_hybrid(peer_pk)
    }

    pub fn decapsulate(sk: &HybridSecretKey, payload: &HybridEncapsulationPayload) -> SecureBuffer {
        decapsulate_hybrid(sk, payload)
    }

    /// Encapsulation directe pour vault et sessions P2P : autonome et sans boucle d'appel
    pub fn encapsulate_and_derive(
        peer_x25519_pk: &X25519PublicKey,
        peer_kyber_pk: &KyberPublicKey,
    ) -> (SecureBuffer, X25519PublicKey, KyberCiphertext) {
        let (kyber_ss, kyber_ct) = kyber_encapsulate(peer_kyber_pk);

        let eph_x25519_sk = EphemeralSecret::random_from_rng(rand::thread_rng());
        let eph_x25519_pk = X25519PublicKey::from(&eph_x25519_sk);
        let x25519_ss = eph_x25519_sk.diffie_hellman(peer_x25519_pk);

        let mut combined_ss = Vec::with_capacity(kyber_ss.as_bytes().len() + x25519_ss.as_bytes().len());
        combined_ss.extend_from_slice(kyber_ss.as_bytes());
        combined_ss.extend_from_slice(x25519_ss.as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(b"AEGIS-v2.2-HYBRID-HKDF-SALT"), &combined_ss);
        let mut session_key = SecureBuffer::new(AES_256_GCM_KEY_LEN);
        hk.expand(b"AEGIS-v2.2-SESSION-KEY-EXPANSION", session_key.as_slice_mut())
            .expect("Ã‰chec d'expansion HKDF-SHA256");

        combined_ss.zeroize();

        (session_key, eph_x25519_pk, kyber_ct)
    }

    /// DÃ©capsulation directe pour vault et sessions P2P avec EphemeralSecret
    pub fn decapsulate_and_derive(
        x25519_sk: EphemeralSecret,
        kyber_sk: &KyberSecretKey,
        peer_x25519_pk: &X25519PublicKey,
        kyber_ct: &KyberCiphertext,
    ) -> SecureBuffer {
        let kyber_ss = kyber_decapsulate(kyber_ct, kyber_sk);
        let x25519_ss = x25519_sk.diffie_hellman(peer_x25519_pk);

        let mut combined_ss = Vec::with_capacity(kyber_ss.as_bytes().len() + x25519_ss.as_bytes().len());
        combined_ss.extend_from_slice(kyber_ss.as_bytes());
        combined_ss.extend_from_slice(x25519_ss.as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(b"AEGIS-v2.2-HYBRID-HKDF-SALT"), &combined_ss);
        let mut session_key = SecureBuffer::new(AES_256_GCM_KEY_LEN);
        hk.expand(b"AEGIS-v2.2-SESSION-KEY-EXPANSION", session_key.as_slice_mut())
            .expect("Ã‰chec d'expansion HKDF-SHA256");

        combined_ss.zeroize();

        session_key
    }
}

pub fn generate_hybrid_keypair() -> (HybridPublicKey, HybridSecretKey) {
    let (kyber_pk, kyber_sk) = kyber_keypair();
    let x25519_sk = X25519SecretKey::random_from_rng(rand::thread_rng());
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    (
        HybridPublicKey { kyber_pk, x25519_pk },
        HybridSecretKey { kyber_sk, x25519_sk },
    )
}

pub fn encapsulate_hybrid(
    peer_pk: &HybridPublicKey,
) -> (HybridEncapsulationPayload, SecureBuffer) {
    let (session_key, eph_x25519_pk, kyber_ct) =
        HybridKeyExchange::encapsulate_and_derive(&peer_pk.x25519_pk, &peer_pk.kyber_pk);

    (
        HybridEncapsulationPayload {
            kyber_ct,
            x25519_eph_pk: eph_x25519_pk,
        },
        session_key,
    )
}

pub fn decapsulate_hybrid(
    sk: &HybridSecretKey,
    payload: &HybridEncapsulationPayload,
) -> SecureBuffer {
    let kyber_ss = kyber_decapsulate(&payload.kyber_ct, &sk.kyber_sk);
    let x25519_ss = sk.x25519_sk.diffie_hellman(&payload.x25519_eph_pk);

    let mut combined_ss = Vec::with_capacity(kyber_ss.as_bytes().len() + x25519_ss.as_bytes().len());
    combined_ss.extend_from_slice(kyber_ss.as_bytes());
    combined_ss.extend_from_slice(x25519_ss.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS-v2.2-HYBRID-HKDF-SALT"), &combined_ss);
    let mut session_key = SecureBuffer::new(AES_256_GCM_KEY_LEN);
    hk.expand(b"AEGIS-v2.2-SESSION-KEY-EXPANSION", session_key.as_slice_mut())
        .expect("Ã‰chec d'expansion HKDF-SHA256");

    combined_ss.zeroize();

    session_key
}

pub struct Aes256GcmEngine;

impl Aes256GcmEngine {
    pub fn encrypt(
        key: &SecureBuffer,
        nonce: &[u8; AES_256_GCM_NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| aes_gcm::Error)?;
        cipher.encrypt(Nonce::from_slice(nonce), plaintext)
    }

    pub fn decrypt(
        key: &SecureBuffer,
        nonce: &[u8; AES_256_GCM_NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<SecureBuffer, aes_gcm::Error> {
        let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| aes_gcm::Error)?;
        let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?;
        let mut buf = SecureBuffer::new(plaintext.len());
        buf.as_slice_mut().copy_from_slice(&plaintext);
        Ok(buf)
    }
}

pub fn encrypt_aes_256_gcm_neon(
    key: &SecureBuffer,
    nonce_bytes: &[u8; AES_256_GCM_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if key.len() != AES_256_GCM_KEY_LEN {
        return Err("Taille de clÃ© AES-256 invalide");
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| "Ã‰chec d'initialisation de la primitive AES-256-GCM")?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Ã‰chec lors du chiffrement AES-256-GCM")
}

pub fn decrypt_aes_256_gcm_neon(
    key: &SecureBuffer,
    nonce_bytes: &[u8; AES_256_GCM_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<SecureBuffer, &'static str> {
    if key.len() != AES_256_GCM_KEY_LEN {
        return Err("Taille de clÃ© AES-256 invalide");
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| "Ã‰chec d'initialisation de la primitive AES-256-GCM")?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted_vec = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "Ã‰chec lors du dÃ©chiffrement (intÃ©gritÃ© GCM compromise)")?;

    let mut out_buf = SecureBuffer::new(decrypted_vec.len());
    out_buf.as_slice_mut().copy_from_slice(&decrypted_vec);

    let mut decrypted_vec_clean = decrypted_vec;
    decrypted_vec_clean.zeroize();

    Ok(out_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_hybrid_key_exchange_roundtrip() {
        let (alice_pk, alice_sk) = HybridKeyExchange::generate_keypair();
        let (payload, bob_session_key) = HybridKeyExchange::encapsulate(&alice_pk);
        let alice_session_key = HybridKeyExchange::decapsulate(&alice_sk, &payload);

        assert_eq!(alice_session_key.as_slice(), bob_session_key.as_slice());
    }

    #[test]
    fn test_encapsulate_and_derive_direct_roundtrip() {
        let bob_x_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let bob_x_public = X25519PublicKey::from(&bob_x_secret);
        let (kyber_pk, kyber_sk) = pqcrypto_mlkem::mlkem768::keypair();

        let (alice_derived, alice_x_pub, kyber_ct) =
            HybridKeyExchange::encapsulate_and_derive(&bob_x_public, &kyber_pk);

        let bob_derived = HybridKeyExchange::decapsulate_and_derive(
            bob_x_secret,
            &kyber_sk,
            &alice_x_pub,
            &kyber_ct,
        );

        assert_eq!(alice_derived.as_slice(), bob_derived.as_slice());
    }

    #[test]
    fn test_aes_256_gcm_neon_roundtrip() {
        let mut key = SecureBuffer::new(32);
        key.as_slice_mut().fill(0x42);
        let nonce = [0x07u8; 12];
        let plaintext = b"AEGIS v2.2 ZERO-DISK TEST PAYLOAD";
        let aad = b"HEADER_AAD";

        let ciphertext = encrypt_aes_256_gcm_neon(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_256_gcm_neon(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_benchmark_crypto_throughput() {
        let mut key = SecureBuffer::new(32);
        key.as_slice_mut().fill(0x13);
        let nonce = [0x01u8; 12];

        let size = 10 * 1024 * 1024;
        let mut plaintext = vec![0xABu8; size];

        let start = Instant::now();
        let ciphertext = encrypt_aes_256_gcm_neon(&key, &nonce, &plaintext, b"").unwrap();
        let duration = start.elapsed();

        plaintext.zeroize();

        let throughput_mb_s = (size as f64 / (1024.0 * 1024.0)) / duration.as_secs_f64();
        println!("DÃ©bit Chiffrement AES-256-GCM : {:.2} Mo/s", throughput_mb_s);

        assert!(ciphertext.len() > size);

        #[cfg(debug_assertions)]
        assert!(throughput_mb_s > 0.5, "DÃ©bit anormalement bas en profil Debug");

        #[cfg(not(debug_assertions))]
        assert!(throughput_mb_s > 50.0, "DÃ©bit insuffisant en profil Release");
    }
}
/// Ephemeral 512B frame processing on-the-fly
pub fn process_512b_frame_ephemeral(
    master_key: &[u8],
    frame_index: u64,
    payload: &mut [u8; 512],
) -> Result<(), ()> {
    use zeroize::Zeroize;
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut ephemeral_key = [0u8; 32];
    let info = frame_index.to_le_bytes();
    
    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS-EPHEMERAL-FRAME-SALT"), master_key);
    hk.expand(&info, &mut ephemeral_key).map_err(|_| ())?;

    // Chiffrement / Déchiffrement In-Place du bloc de 512 octets
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= ephemeral_key[i % 32];
    }

    // Destruction sub-milliseconde de la clé dérivée
    ephemeral_key.zeroize();
    Ok(())
}

#[cfg(kani)]
#[kani::proof]
fn verify_process_512b_frame_bounds() {
    let master_key: [u8; 32] = kani::any();
    let frame_index: u64 = kani::any();
    let mut payload: [u8; 512] = kani::any();
    let res = process_512b_frame_ephemeral(&master_key, frame_index, &mut payload);
    kani::assert(res.is_ok(), "Process frame must never panic or fail on valid bounds");
}