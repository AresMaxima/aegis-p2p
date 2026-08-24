//! aegis-core/src/storage/vault.rs
//! Format de Conteneur Chiffré `.aegis` PQ-Hybride, Scellement TPM 2.0 & PanicPurge

use crate::crypto_pq::HybridKeyExchange;
use crate::secure_buffer::SecureBuffer;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_kyber::kyber1024::{
    ciphertext_bytes, Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
};
use pqcrypto_traits::kem::Ciphertext as _;
use rand::{RngCore, thread_rng};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Échec de l'attestation matérielle (TPM) ou compteur Anti-Rollback invalide")]
    HardwareAttestationFailed,
    #[error("Conteneur .aegis invalide, corrompu ou taille insuffisante")]
    InvalidContainer,
    #[error("Échec de vérification de la signature Ed25519 éphémère")]
    InvalidSignature,
    #[error("Échec du chiffrement ou déchiffrement AEAD")]
    CryptoError,
    #[error("Erreur de dérivation de clé (Argon2id)")]
    KdfError,
    #[error("Erreur I/O lors de la purge physique du fichier")]
    IoError(#[from] std::io::Error),
}

pub struct AegisVault;

impl AegisVault {
    /// Masque d'entropie polymorphe (32 octets)
    pub const POLYMORPHIC_MASK_SIZE: usize = 32;
    /// Salt Argon2id (16 octets)
    pub const SALT_SIZE: usize = 16;
    /// Nonce ChaCha20Poly1305 (12 octets)
    pub const NONCE_SIZE: usize = 12;
    /// Clé publique X25519 éphémère (32 octets)
    pub const X25519_PK_SIZE: usize = 32;
    /// Signature Ed25519 éphémère (64 octets)
    pub const SIGNATURE_SIZE: usize = 64;
    /// Tag Poly1305 (16 octets)
    pub const POLY1305_TAG_SIZE: usize = 16;

    /// Dérive une Master Vault Key via Argon2id (m=64MB, t=3, p=4)
    pub fn derive_master_key(
        passphrase: &[u8],
        salt: &[u8; Self::SALT_SIZE],
    ) -> Result<SecureBuffer, VaultError> {
        let params = Params::new(65536, 3, 4, Some(32)).map_err(|_| VaultError::KdfError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_buf = SecureBuffer::new(32);
        argon2
            .hash_password_into(passphrase, salt, key_buf.as_slice_mut())
            .map_err(|_| VaultError::KdfError)?;

        Ok(key_buf)
    }

    /// Empaquette un SecureBuffer selon la structure binaire complète .aegis (Cahier des Charges 1.2)
    /// Structure : [MASK (32B)] [SALT (16B)] [NONCE (12B)] [X25519_PK (32B)] [KYBER_CT] [SIGNATURE (64B)] [PAYLOAD]
    pub fn pack_to_aegis(
        payload: &SecureBuffer,
        peer_x_public: &X25519PublicKey,
        peer_kyber_public: &KyberPublicKey,
        signing_key: &SigningKey,
    ) -> Result<Vec<u8>, VaultError> {
        let mut rng = thread_rng();

        // 1. Masque polymorphe (32B)
        let mut header_mask = [0u8; Self::POLYMORPHIC_MASK_SIZE];
        rng.fill_bytes(&mut header_mask);

        // 2. Salt Argon2id (16B)
        let mut salt = [0u8; Self::SALT_SIZE];
        rng.fill_bytes(&mut salt);

        // 3. Nonce ChaCha20Poly1305 (12B)
        let mut nonce_bytes = [0u8; Self::NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 4. Encapsulation PQ-Hybride (X25519 + Kyber1024)
        let (derived_key_buf, my_x_public, kyber_ciphertext) =
            HybridKeyExchange::encapsulate_and_derive(peer_x_public, peer_kyber_public);

        // 5. Chiffrement AEAD du payload
        let cipher = ChaCha20Poly1305::new_from_slice(derived_key_buf.as_slice())
            .map_err(|_| VaultError::CryptoError)?;
        let ciphertext = cipher
            .encrypt(nonce, payload.as_slice())
            .map_err(|_| VaultError::CryptoError)?;

        // 6. Signature Ed25519 sur l'assemblage [NONCE + X25519_PK + KYBER_CT + CIPHERTEXT]
        let mut signed_data = Vec::with_capacity(
            Self::NONCE_SIZE + Self::X25519_PK_SIZE + ciphertext_bytes() + ciphertext.len(),
        );
        signed_data.extend_from_slice(&nonce_bytes);
        signed_data.extend_from_slice(my_x_public.as_bytes());
        signed_data.extend_from_slice(kyber_ciphertext.as_bytes());
        signed_data.extend_from_slice(&ciphertext);

        let signature: Signature = signing_key.sign(&signed_data);

        // 7. Assemblage binaire final
        let total_size = Self::POLYMORPHIC_MASK_SIZE
            + Self::SALT_SIZE
            + Self::NONCE_SIZE
            + Self::X25519_PK_SIZE
            + ciphertext_bytes()
            + Self::SIGNATURE_SIZE
            + ciphertext.len();

        let mut container = Vec::with_capacity(total_size);
        container.extend_from_slice(&header_mask);
        container.extend_from_slice(&salt);
        container.extend_from_slice(&nonce_bytes);
        container.extend_from_slice(my_x_public.as_bytes());
        container.extend_from_slice(kyber_ciphertext.as_bytes());
        container.extend_from_slice(&signature.to_bytes());
        container.extend_from_slice(&ciphertext);

        Ok(container)
    }

    /// Déverrouille un conteneur .aegis avec vérifications TPM & Anti-Rollback
    pub fn unpack_aegis(
        container: &[u8],
        my_x_secret: EphemeralSecret,
        my_kyber_secret: &KyberSecretKey,
        verifying_key: &VerifyingKey,
        tpm_nv_counter: u32,
        expected_counter: u32,
    ) -> Result<SecureBuffer, VaultError> {
        // 1. Contrôle intégrité TPM & Compteur Anti-Rollback
        if crate::crypto::tpm::AegisTpmManager::verify_kernel_integrity().is_err()
            || tpm_nv_counter < expected_counter
        {
            return Err(VaultError::HardwareAttestationFailed);
        }

        // 2. Bornes minimales
        let kyber_len = ciphertext_bytes();
        let min_required_size = Self::POLYMORPHIC_MASK_SIZE
            + Self::SALT_SIZE
            + Self::NONCE_SIZE
            + Self::X25519_PK_SIZE
            + kyber_len
            + Self::SIGNATURE_SIZE
            + Self::POLY1305_TAG_SIZE;

        if container.len() < min_required_size {
            return Err(VaultError::InvalidContainer);
        }

        let mut offset = Self::POLYMORPHIC_MASK_SIZE;

        // Salt
        let _salt = &container[offset..offset + Self::SALT_SIZE];
        offset += Self::SALT_SIZE;

        // Nonce
        let nonce_bytes = &container[offset..offset + Self::NONCE_SIZE];
        let nonce = Nonce::from_slice(nonce_bytes);
        offset += Self::NONCE_SIZE;

        // X25519 PK
        let mut peer_x_bytes = [0u8; Self::X25519_PK_SIZE];
        peer_x_bytes.copy_from_slice(&container[offset..offset + Self::X25519_PK_SIZE]);
        let peer_x_public = X25519PublicKey::from(peer_x_bytes);
        offset += Self::X25519_PK_SIZE;

        // Kyber CT
        let kyber_bytes = &container[offset..offset + kyber_len];
        let kyber_ciphertext = KyberCiphertext::from_bytes(kyber_bytes)
            .map_err(|_| VaultError::InvalidContainer)?;
        offset += kyber_len;

        // Signature Ed25519
        let mut sig_bytes = [0u8; Self::SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(&container[offset..offset + Self::SIGNATURE_SIZE]);
        let signature = Signature::from_bytes(&sig_bytes);
        offset += Self::SIGNATURE_SIZE;

        let ciphertext = &container[offset..];

        // 3. Vérification de la signature
        let mut signed_data = Vec::with_capacity(
            Self::NONCE_SIZE + Self::X25519_PK_SIZE + kyber_len + ciphertext.len(),
        );
        signed_data.extend_from_slice(nonce_bytes);
        signed_data.extend_from_slice(peer_x_public.as_bytes());
        signed_data.extend_from_slice(kyber_bytes);
        signed_data.extend_from_slice(ciphertext);

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| VaultError::InvalidSignature)?;

        // 4. Décapsulation PQ-Hybride & Dérivation
        let derived_key_buf = HybridKeyExchange::decapsulate_and_derive(
            my_x_secret,
            my_kyber_secret,
            &peer_x_public,
            &kyber_ciphertext,
        );

        // 5. Déchiffrement ChaCha20Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(derived_key_buf.as_slice())
            .map_err(|_| VaultError::CryptoError)?;

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| VaultError::CryptoError)?,
        );

        if plaintext.is_empty() {
            return Err(VaultError::InvalidContainer);
        }

        let mut secure_buf = SecureBuffer::new(plaintext.len());
        secure_buf.as_slice_mut().copy_from_slice(&plaintext);

        Ok(secure_buf)
    }

    /// Overwrite physique sur disque par du bruit CSPRNG (/dev/urandom) avant suppression (PanicPurge 0000 / 9999)
    pub fn panic_purge(vault_path: &Path) -> Result<(), VaultError> {
        if vault_path.exists() {
            let mut file = OpenOptions::new().write(true).open(vault_path)?;
            let file_len = file.metadata()?.len();
            let mut rng = thread_rng();

            let mut buffer = [0u8; 4096];
            let mut written = 0u64;

            while written < file_len {
                rng.fill_bytes(&mut buffer);
                let chunk_size = std::cmp::min(buffer.len() as u64, file_len - written) as usize;
                file.write_all(&buffer[..chunk_size])?;
                written += chunk_size as u64;
            }
            file.flush()?;

            std::fs::remove_file(vault_path)?;
        }
        Ok(())
    }
}