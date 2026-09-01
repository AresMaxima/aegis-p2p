//! aegis-core/src/qr_pairing.rs
//! Encodage et décodage de la charge utile d'appariement Out-of-Band (QR Code Version 40)

use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use pqcrypto_mlkem::mlkem768::PublicKey as KyberPublicKey;
use pqcrypto_traits::kem::PublicKey;
use zeroize::Zeroize;

pub const QR_VERSION_40_MAX_PAYLOAD: usize = 2710;
pub const TOR_V3_ONION_ADDR_LEN: usize = 56;
pub const ED25519_PK_LEN: usize = 32;
pub const KYBER768_PK_LEN: usize = 1184;

pub const PAIRING_HEADER_MAGIC: &[u8; 4] = b"AGP1";

pub struct OutOfBandPairingPayload {
    pub kyber_pk_bytes: [u8; KYBER768_PK_LEN],
    pub ed25519_pk_bytes: [u8; ED25519_PK_LEN],
    pub tor_onion_address: [u8; TOR_V3_ONION_ADDR_LEN],
}

impl OutOfBandPairingPayload {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PAIRING_HEADER_MAGIC.len()
                + KYBER768_PK_LEN
                + ED25519_PK_LEN
                + TOR_V3_ONION_ADDR_LEN,
        );

        out.extend_from_slice(PAIRING_HEADER_MAGIC);
        out.extend_from_slice(&self.kyber_pk_bytes);
        out.extend_from_slice(&self.ed25519_pk_bytes);
        out.extend_from_slice(&self.tor_onion_address);

        assert!(out.len() <= QR_VERSION_40_MAX_PAYLOAD);
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        let expected_len = PAIRING_HEADER_MAGIC.len()
            + KYBER768_PK_LEN
            + ED25519_PK_LEN
            + TOR_V3_ONION_ADDR_LEN;

        if bytes.len() != expected_len {
            return Err("Taille du QR code d'appariement invalide");
        }

        if &bytes[..4] != PAIRING_HEADER_MAGIC {
            return Err("Magic bytes de l'en-tête d'appariement invalides");
        }

        let mut offset = 4;

        let mut kyber_pk_bytes = [0u8; KYBER768_PK_LEN];
        kyber_pk_bytes.copy_from_slice(&bytes[offset..offset + KYBER768_PK_LEN]);
        offset += KYBER768_PK_LEN;

        let mut ed25519_pk_bytes = [0u8; ED25519_PK_LEN];
        ed25519_pk_bytes.copy_from_slice(&bytes[offset..offset + ED25519_PK_LEN]);
        offset += ED25519_PK_LEN;

        let mut tor_onion_address = [0u8; TOR_V3_ONION_ADDR_LEN];
        tor_onion_address.copy_from_slice(&bytes[offset..offset + TOR_V3_ONION_ADDR_LEN]);

        if KyberPublicKey::from_bytes(&kyber_pk_bytes).is_err() {
            return Err("Clé publique ML-KEM-768 corrompue dans le QR Code");
        }

        if Ed25519PublicKey::from_bytes(&ed25519_pk_bytes).is_err() {
            return Err("Clé d'identité Ed25519 corrompue dans le QR Code");
        }

        Ok(Self {
            kyber_pk_bytes,
            ed25519_pk_bytes,
            tor_onion_address,
        })
    }
}

impl Drop for OutOfBandPairingPayload {
    fn drop(&mut self) {
        self.kyber_pk_bytes.zeroize();
        self.ed25519_pk_bytes.zeroize();
        self.tor_onion_address.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_payload_serialize_deserialize() {
        let dummy_payload = OutOfBandPairingPayload {
            kyber_pk_bytes: [0x55u8; KYBER768_PK_LEN],
            ed25519_pk_bytes: [0xAAu8; ED25519_PK_LEN],
            tor_onion_address: *b"v3onionaddress56byteslongexample1234567890abcdefgh.onion",
        };

        let (kyber_pk, _) = pqcrypto_mlkem::mlkem768::keypair();
        let mut valid_payload = dummy_payload;
        valid_payload.kyber_pk_bytes.copy_from_slice(kyber_pk.as_bytes());

        let ed_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let ed_pk = ed_sk.verifying_key();
        valid_payload.ed25519_pk_bytes.copy_from_slice(ed_pk.as_bytes());

        let binary_qr = valid_payload.serialize();
        assert_eq!(binary_qr.len(), 4 + 1184 + 32 + 56);

        let parsed = OutOfBandPairingPayload::deserialize(&binary_qr).unwrap();
        assert_eq!(parsed.kyber_pk_bytes, valid_payload.kyber_pk_bytes);
        assert_eq!(parsed.ed25519_pk_bytes, valid_payload.ed25519_pk_bytes);
        assert_eq!(parsed.tor_onion_address, valid_payload.tor_onion_address);
    }
}