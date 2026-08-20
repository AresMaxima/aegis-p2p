use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Représente l'identité maître d'un utilisateur chargée temporairement en RAM.
/// Implémente `ZeroizeOnDrop` pour garantir l'effacement de la mémoire vive à la destruction.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeys {
    /// Clé privée d'édition Ed25519 (Signature)
    #[zeroize(skip)]
    pub ed25519_signing: Ed25519SigningKey,
    /// Clé privée statique X25519 (Chiffrement / Diffie-Hellman)
    pub x25519_secret: X25519StaticSecret,
}

impl IdentityKeys {
    /// Clé publique Ed25519 correspondante
    pub fn ed25519_verifying(&self) -> Ed25519VerifyingKey {
        self.ed25519_signing.verifying_key()
    }

    /// Clé publique X25519 correspondante
    pub fn x25519_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.x25519_secret)
    }

    /// Calcule le Hash de l'Empreinte Publique (ID unique à partager avec le correspondant)
    pub fn public_identity_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.ed25519_verifying().as_bytes());
        hasher.update(self.x25519_public().as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..16]) // Empreinte de 32 caractères hexadécimaux
    }
}

/// Génère une nouvelle phrase mnémonique BIP-39 (12 mots par défaut, 128 bits d'entropie).
pub fn generate_mnemonic(word_count: usize) -> Result<String, String> {
    let entropy_bytes = match word_count {
        12 => 16,
        24 => 32,
        _ => return Err("Le nombre de mots doit être 12 ou 24".to_string()),
    };

    let mut entropy = vec![0u8; entropy_bytes];
    getrandom::getrandom(&mut entropy)
        .map_err(|e| format!("Erreur du générateur d'entropie matérielle: {}", e))?;

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| format!("Erreur lors de la création du mnémonique: {}", e))?;

    let phrase = mnemonic.to_string();
    entropy.zeroize();

    Ok(phrase)
}

/// Dérive l'ensemble des clés cryptographiques (Ed25519 & X25519) à partir d'une phrase mnémonique.
pub fn derive_keys_from_mnemonic(mnemonic_phrase: &str) -> Result<IdentityKeys, String> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)
        .map_err(|e| format!("Phrase mnémonique invalide: {}", e))?;

    // CORRECTION OPSEC : La Seed maître doit être mutable pour pouvoir la zéroïser
    let mut seed = mnemonic.to_seed("");

    // Dérivation des 32 premiers octets pour Ed25519
    let mut ed_bytes = [0u8; 32];
    ed_bytes.copy_from_slice(&seed[0..32]);
    let ed25519_signing = Ed25519SigningKey::from_bytes(&ed_bytes);

    // Dérivation des 32 octets suivants pour X25519
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&seed[32..64]);
    let x25519_secret = X25519StaticSecret::from(x_bytes);

    // CORRECTION OPSEC : Nettoyage STRICT ET OBLIGATOIRE de la Seed maître et des sous-tampons
    ed_bytes.zeroize();
    x_bytes.zeroize();
    seed.zeroize();

    Ok(IdentityKeys {
        ed25519_signing,
        x25519_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation_and_derivation() {
        let phrase = generate_mnemonic(12).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);

        let keys = derive_keys_from_mnemonic(&phrase).unwrap();
        let hash = keys.public_identity_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_deterministic_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys_1 = derive_keys_from_mnemonic(phrase).unwrap();
        let keys_2 = derive_keys_from_mnemonic(phrase).unwrap();

        assert_eq!(keys_1.public_identity_hash(), keys_2.public_identity_hash());
    }
}