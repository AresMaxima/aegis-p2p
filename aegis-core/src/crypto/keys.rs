use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// =========================================================================
// C12 Clarification (audit 2026-09-21) : dérivation BIP-39 non-SLIP-0010
// =========================================================================
//
// La fonction `derive_keys_from_mnemonic` effectue un **split naïf** du seed
// BIP-39 (64 octets) :
//
//   • seed[0..32]  → clé privée Ed25519 (signature)
//   • seed[32..64] → clé privée X25519  (chiffrement / ECDH)
//
// # Ce que cela implique
//
// ✅ **Cryptographiquement sûr** : le seed BIP-39 est un PRK de 512 bits issu
//    de PBKDF2-HMAC-SHA512 sur (mnemonic, passphrase). Sa première moitié
//    est indiscernable d'aléatoire. Utiliser seed[0..32] comme clé Ed25519
//    est équivalent en sécurité à un tirage uniforme.
//
// ❌ **Non-interopérable** avec les standards de dérivation de wallets :
//    • BIP-32  (Bitcoin, Ethereum, HD wallets)
//    • SLIP-0010 (dérivation Ed25519 standard, utilisé par Ledger, Trezor)
//    • Toute implémentation cherchant à restaurer une identité AEGIS depuis
//      une phrase mnémonique sur un autre logiciel échouera silencieusement.
//
// # Décision de design (actée le 21/09/2026)
//
// AEGIS **n'annonce PAS** l'interop avec les wallets matériels. La phrase
// mnémonique AEGIS est un format d'export/import **propre à AEGIS**, pas
// un format universel. C'est un choix explicite : la simplicité et la
// sécurité priment sur l'interopérabilité.
//
// Cas pratique : un utilisateur peut parfaitement avoir une identité AEGIS
// ET une identité Ledger sur le même téléphone, avec deux phrases mnémoniques
// distinctes. Les deux apps cohabitent sans interférence.
//
// # Si une migration vers SLIP-0010 devient nécessaire (non planifié)
//
// Remplacer le split naïf par :
//
//   use slip10::derive_key_from_path;
//   let ed_seed = derive_key_from_path(&seed, Curve::Ed25519, &[0])?;
//   let x_seed  = derive_key_from_path(&seed, Curve::Ed25519, &[1])?;
//
// Cela casserait la compatibilité avec les identités AEGIS existantes →
// nécessite une migration utilisateur (re-scan du QR ou re-import mnémonique).
//
// # Documentation utilisateur associée
//
// Le manuel AEGIS (toutes langues) doit préciser :
//
//   « La phrase mnémonique AEGIS est le SEUL moyen de restaurer votre
//     identité AEGIS. Elle utilise le format BIP-39 mais une dérivation
//     propre à AEGIS — elle ne peut PAS être utilisée pour restaurer un
//     wallet Ledger ou Trezor, et inversement. Conservez précieusement
//     cette phrase. Sa perte = perte définitive de l'identité AEGIS. »
// =========================================================================

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
///
/// **ATTENTION** : dérivation **non-SLIP-0010** — voir le bloc de commentaires
/// en haut de ce fichier pour les implications d'interopérabilité.
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