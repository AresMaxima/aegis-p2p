use crate::secure_buffer::SecureBuffer;
use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

pub struct HybridKeyExchange;

impl HybridKeyExchange {
    /// Génère une paire de clés combinée (X25519 + Kyber1024)
    pub fn generate_keypair() -> (
        (EphemeralSecret, SecretKey),
        (X25519PublicKey, PublicKey),
    ) {
        let x_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let x_public = X25519PublicKey::from(&x_secret);
        let (kyber_public, kyber_secret) = keypair();

        ((x_secret, kyber_secret), (x_public, kyber_public))
    }

    /// Côté Émetteur : Encapsule Kyber et génère le secret partagé + clés publiques éphémères
    pub fn encapsulate_and_derive(
        peer_x_public: &X25519PublicKey,
        peer_kyber_public: &PublicKey,
    ) -> (SecureBuffer, X25519PublicKey, Ciphertext) {
        let my_x_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let my_x_public = X25519PublicKey::from(&my_x_secret);

        let x_shared = my_x_secret.diffie_hellman(peer_x_public);
        let (kyber_shared, ciphertext) = encapsulate(peer_kyber_public);

        // Assemblage sécurisé avec effacement explicite post-expansion HKDF
        let mut combined_secret = Vec::with_capacity(32 + kyber_shared.as_bytes().len());
        combined_secret.extend_from_slice(x_shared.as_bytes());
        combined_secret.extend_from_slice(kyber_shared.as_bytes());

        let hk = Hkdf::<Sha256>::new(None, &combined_secret);

        // Purge immédiate de la mémoire volatile contenant la concaténation brute
        combined_secret.zeroize();

        let mut derived_key = SecureBuffer::new(32);
        hk.expand(b"AEGIS-PQ-HYBRID-RATCHET", derived_key.as_slice_mut())
            .expect("Échec d'expansion HKDF");

        (derived_key, my_x_public, ciphertext)
    }

    /// Côté Récepteur : Décapsule Kyber et dérive le même secret partagé
    pub fn decapsulate_and_derive(
        my_x_secret: EphemeralSecret,
        my_kyber_secret: &SecretKey,
        peer_x_public: &X25519PublicKey,
        ciphertext: &Ciphertext,
    ) -> SecureBuffer {
        let x_shared = my_x_secret.diffie_hellman(peer_x_public);
        let kyber_shared = decapsulate(ciphertext, my_kyber_secret);

        let mut combined_secret = Vec::with_capacity(32 + kyber_shared.as_bytes().len());
        combined_secret.extend_from_slice(x_shared.as_bytes());
        combined_secret.extend_from_slice(kyber_shared.as_bytes());

        let hk = Hkdf::<Sha256>::new(None, &combined_secret);

        // Purge immédiate de la mémoire volatile contenant la concaténation brute
        combined_secret.zeroize();

        let mut derived_key = SecureBuffer::new(32);
        hk.expand(b"AEGIS-PQ-HYBRID-RATCHET", derived_key.as_slice_mut())
            .expect("Échec d'expansion HKDF");

        derived_key
    }
}