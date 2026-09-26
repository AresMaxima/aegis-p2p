//! aegis-core/src/attestation.rs
//! Android Key Attestation — Niveau 3 (CdCM v2.2-RC3).

use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, RSA_PKCS1_2048_8192_SHA256,
};
use x509_parser::prelude::*;

const KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AttestationStatus {
    Ok,
    ChainEmpty,
    ChainTooLong,
    ParseError,
    ChainSignatureInvalid,
    AttestationExtensionMissing,
    AttestationExtensionParseError,
    ChallengeMismatch,
    BootloaderUnlocked,
    BootStateNotVerified,
    BootHashMissing,
    SecurityLevelSoftware,
}

impl AttestationStatus {
    pub fn to_code(&self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::ChainEmpty => -1,
            Self::ChainTooLong => -2,
            Self::ParseError => -3,
            Self::ChainSignatureInvalid => -4,
            Self::AttestationExtensionMissing => -5,
            Self::AttestationExtensionParseError => -6,
            Self::ChallengeMismatch => -7,
            Self::BootloaderUnlocked => -8,
            Self::BootStateNotVerified => -9,
            Self::BootHashMissing => -10,
            Self::SecurityLevelSoftware => -11,
        }
    }

    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::ChainTooLong
                | Self::ChainSignatureInvalid
                | Self::ChallengeMismatch
                | Self::BootloaderUnlocked
                | Self::BootStateNotVerified
                | Self::BootHashMissing
                | Self::SecurityLevelSoftware
                | Self::AttestationExtensionParseError
        )
    }
}

// =========================================================================
// Parsing X.509
// =========================================================================

fn parse_concatenated_certs(
    chain: &[u8],
) -> Result<Vec<X509Certificate<'_>>, AttestationStatus> {
    const MAX_CERTS: usize = 10;
    let mut certs = Vec::new();
    let mut remaining = chain;

    while !remaining.is_empty() && certs.len() < MAX_CERTS {
        match X509Certificate::from_der(remaining) {
            Ok((rest, cert)) => {
                certs.push(cert);
                remaining = rest;
            }
            Err(_) => {
                if certs.is_empty() {
                    return Err(AttestationStatus::ParseError);
                }
                break;
            }
        }
    }

    if certs.is_empty() {
        return Err(AttestationStatus::ChainEmpty);
    }
    if certs.len() == MAX_CERTS {
        return Err(AttestationStatus::ChainTooLong);
    }

    Ok(certs)
}

// =========================================================================
// Vérification des signatures de chaîne
// =========================================================================

fn verify_cert_signature(child: &X509Certificate, parent: &X509Certificate) -> bool {
    let tbs = child.tbs_certificate.as_ref();
    // FIX 3 : Cow<[u8]> → &[u8] via deref coercion, sans clone.
    let sig: &[u8] = &child.signature_value.data;
    let alg_oid = child.signature_algorithm.algorithm.to_id_string();
    let parent_pk = parent.public_key().raw;

    if alg_oid == "1.2.840.10045.4.3.2" {
        let vk = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, parent_pk);
        return vk.verify(tbs, sig).is_ok();
    }

    if alg_oid == "1.2.840.113549.1.1.11" {
        let vk = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, parent_pk);
        return vk.verify(tbs, sig).is_ok();
    }

    false
}

// =========================================================================
// Extraction de l'extension d'attestation
// =========================================================================

fn get_attestation_extension<'a>(cert: &'a X509Certificate) -> Option<&'a [u8]> {
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == KEY_ATTESTATION_OID {
            return Some(ext.value);
        }
    }
    None
}

// =========================================================================
// Mini-parser DER ciblé
// =========================================================================

fn der_read_tag<'a>(data: &'a [u8], expected: u8) -> Result<(&'a [u8], &'a [u8]), AttestationStatus> {
    if data.is_empty() || data[0] != expected {
        return Err(AttestationStatus::AttestationExtensionParseError);
    }
    if data.len() < 2 {
        return Err(AttestationStatus::AttestationExtensionParseError);
    }
    let len_byte = data[1];
    let (len, hdr) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2usize)
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err(AttestationStatus::AttestationExtensionParseError);
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | (data[2 + i] as usize);
        }
        (l, 2 + n)
    };
    if data.len() < hdr + len {
        return Err(AttestationStatus::AttestationExtensionParseError);
    }
    Ok((&data[hdr..hdr + len], &data[hdr + len..]))
}

/// FIX 1 : Encodage base-128 correct (bit de continuation sur tous les octets
/// SAUF le dernier). Pour 704 → `[0x85, 0x40]`.
fn der_read_ctx_tag<'a>(
    data: &'a [u8],
    tag_value: u32,
) -> Option<(&'a [u8], &'a [u8])> {
    if data.len() < 2 {
        return None;
    }

    // Encodage base-128 : LSB d'abord, puis reverse, puis continuation bit.
    let mut tag_bytes = Vec::new();
    let mut v = tag_value;
    loop {
        tag_bytes.push((v & 0x7F) as u8);
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    tag_bytes.reverse();
    let n = tag_bytes.len();
    for i in 0..n.saturating_sub(1) {
        tag_bytes[i] |= 0x80;
    }

    if data[0] != 0xBF {
        return None;
    }
    if data.len() < 1 + tag_bytes.len() {
        return None;
    }
    for (i, &b) in tag_bytes.iter().enumerate() {
        if data[1 + i] != b {
            return None;
        }
    }

    let len_pos = 1 + tag_bytes.len();
    if data.len() <= len_pos {
        return None;
    }
    let len_byte = data[len_pos];
    let (len, hdr) = if len_byte & 0x80 == 0 {
        (len_byte as usize, len_pos + 1)
    } else {
        let nb = (len_byte & 0x7F) as usize;
        if nb == 0 || nb > 4 || data.len() < len_pos + 1 + nb {
            return None;
        }
        let mut l = 0usize;
        for i in 0..nb {
            l = (l << 8) | (data[len_pos + 1 + i] as usize);
        }
        (l, len_pos + 1 + nb)
    };

    if data.len() < hdr + len {
        return None;
    }
    Some((&data[hdr..hdr + len], &data[hdr + len..]))
}

/// FIX 2 : calcul de `consumed` corrigé (ne pas ajouter 1).
fn der_find_ctx_tag<'a>(data: &'a [u8], tag_value: u32) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < data.len() {
        let slice = &data[i..];
        if slice.len() < 2 {
            return None;
        }
        // Tag context-specific 1 octet (0xA0..=0xBF sauf 0xBF multi-octets)
        if slice[0] & 0xE0 == 0xA0 && slice[0] != 0xBF {
            let n = (slice[0] & 0x1F) as u32;
            let (content, rest) = read_der_len(&slice[1..]).ok()?;
            if n == tag_value {
                return Some(content);
            }
            // FIX 2 : `slice.len() - rest.len()` inclut déjà l'octet de tag.
            let consumed = slice.len() - rest.len();
            i += consumed;
            continue;
        }
        // Tag context-specific multi-octets
        if slice[0] == 0xBF {
            if let Some((content, _)) = der_read_ctx_tag(slice, tag_value) {
                return Some(content);
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    None
}

fn read_der_len(data: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    if data.is_empty() {
        return Err(());
    }
    let len_byte = data[0];
    let (len, hdr) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 1usize)
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 1 + n {
            return Err(());
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | (data[1 + i] as usize);
        }
        (l, 1 + n)
    };
    if data.len() < hdr + len {
        return Err(());
    }
    Ok((&data[hdr..hdr + len], &data[hdr + len..]))
}

// =========================================================================
// KeyDescription
// =========================================================================

struct KeyDescription<'a> {
    attestation_version: i64,
    attestation_security_level: i64,
    attestation_challenge: &'a [u8],
    tee_enforced: &'a [u8],
}

fn parse_key_description(ext_bytes: &[u8]) -> Result<KeyDescription, AttestationStatus> {
    let (seq, _) = der_read_tag(ext_bytes, 0x30)?;
    let mut cursor = seq;

    let (v_bytes, rest) = der_read_tag(cursor, 0x02)?;
    let attestation_version = read_int(v_bytes);
    cursor = rest;

    let (sl_bytes, rest) = der_read_tag(cursor, 0x0A)?;
    let attestation_security_level = read_int(sl_bytes);
    cursor = rest;

    let (_, rest) = der_read_tag(cursor, 0x02)?;
    cursor = rest;

    let (_, rest) = der_read_tag(cursor, 0x0A)?;
    cursor = rest;

    let (challenge, rest) = der_read_tag(cursor, 0x04)?;
    cursor = rest;

    let (_, rest) = der_read_tag(cursor, 0x04)?;
    cursor = rest;

    let (_, rest) = der_read_tag(cursor, 0x30)?;
    cursor = rest;

    let (tee_enforced, _) = der_read_tag(cursor, 0x30)?;

    Ok(KeyDescription {
        attestation_version,
        attestation_security_level,
        attestation_challenge: challenge,
        tee_enforced,
    })
}

fn read_int(bytes: &[u8]) -> i64 {
    let mut v: i64 = 0;
    for &b in bytes {
        v = (v << 8) | (b as i64);
    }
    v
}

// =========================================================================
// RootOfTrust
// =========================================================================

struct RootOfTrust<'a> {
    device_locked: bool,
    verified_boot_state: i64,
    verified_boot_hash: &'a [u8],
}

fn parse_root_of_trust(data: &[u8]) -> Result<RootOfTrust, AttestationStatus> {
    let (seq, _) = der_read_tag(data, 0x30)?;
    let mut cursor = seq;

    let (_, rest) = der_read_tag(cursor, 0x04)?;
    cursor = rest;

    let (dl, rest) = der_read_tag(cursor, 0x01)?;
    let device_locked = !dl.is_empty() && dl[0] != 0x00;
    cursor = rest;

    let (vbs, rest) = der_read_tag(cursor, 0x0A)?;
    let verified_boot_state = read_int(vbs);
    cursor = rest;

    let (vbh, _) = der_read_tag(cursor, 0x04)?;

    Ok(RootOfTrust {
        device_locked,
        verified_boot_state,
        verified_boot_hash: vbh,
    })
}

// =========================================================================
// Vérification complète
// =========================================================================

pub fn verify_attestation_chain(chain: &[u8], expected_challenge: &[u8]) -> AttestationStatus {
    let certs = match parse_concatenated_certs(chain) {
        Ok(c) => c,
        Err(e) => return e,
    };

    for i in 0..certs.len().saturating_sub(1) {
        if !verify_cert_signature(&certs[i], &certs[i + 1]) {
            return AttestationStatus::ChainSignatureInvalid;
        }
    }

    let leaf = &certs[0];
    let ext_bytes = match get_attestation_extension(leaf) {
        Some(b) => b,
        None => return AttestationStatus::AttestationExtensionMissing,
    };

    let kd = match parse_key_description(ext_bytes) {
        Ok(k) => k,
        Err(e) => return e,
    };

    if kd.attestation_version < 3 {
        return AttestationStatus::AttestationExtensionParseError;
    }

    if kd.attestation_security_level < 1 {
        return AttestationStatus::SecurityLevelSoftware;
    }

    if kd.attestation_challenge != expected_challenge {
        return AttestationStatus::ChallengeMismatch;
    }

    let rot_bytes = match der_find_ctx_tag(kd.tee_enforced, 704) {
        Some(b) => b,
        None => return AttestationStatus::AttestationExtensionMissing,
    };

    let rot = match parse_root_of_trust(rot_bytes) {
        Ok(r) => r,
        Err(e) => return e,
    };

    if !rot.device_locked {
        return AttestationStatus::BootloaderUnlocked;
    }

    if rot.verified_boot_state != 0 {
        return AttestationStatus::BootStateNotVerified;
    }

    if rot.verified_boot_hash.is_empty() {
        return AttestationStatus::BootHashMissing;
    }

    AttestationStatus::Ok
}

// =========================================================================
// TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_returns_chain_empty() {
        let status = verify_attestation_chain(&[], &[0u8; 32]);
        assert_eq!(status, AttestationStatus::ChainEmpty);
    }

    #[test]
    fn test_garbage_chain_returns_parse_error() {
        let status = verify_attestation_chain(&[0x00, 0x01, 0x02, 0x03], &[0u8; 32]);
        assert_eq!(status, AttestationStatus::ParseError);
    }

    #[test]
    fn test_code_mapping() {
        assert_eq!(AttestationStatus::Ok.to_code(), 0);
        assert_eq!(AttestationStatus::ChainEmpty.to_code(), -1);
        assert_eq!(AttestationStatus::ChallengeMismatch.to_code(), -7);
        assert_eq!(AttestationStatus::BootloaderUnlocked.to_code(), -8);
    }

    #[test]
    fn test_is_critical() {
        assert!(AttestationStatus::ChallengeMismatch.is_critical());
        assert!(AttestationStatus::BootloaderUnlocked.is_critical());
        assert!(AttestationStatus::BootStateNotVerified.is_critical());
        assert!(!AttestationStatus::Ok.is_critical());
        assert!(!AttestationStatus::ChainEmpty.is_critical());
        assert!(!AttestationStatus::AttestationExtensionMissing.is_critical());
    }

    #[test]
    fn test_der_read_tag_basic() {
        let data = [0x30u8, 0x03, 0x01, 0x02, 0x03];
        let (content, rest) = der_read_tag(&data, 0x30).unwrap();
        assert_eq!(content, &[0x01, 0x02, 0x03]);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_der_read_tag_wrong_tag() {
        let data = [0x30u8, 0x03, 0x01, 0x02, 0x03];
        assert!(der_read_tag(&data, 0x02).is_err());
    }

    #[test]
    fn test_der_read_tag_long_form() {
        let mut data = vec![0x30u8, 0x81, 0xC8];
        data.extend(std::iter::repeat(0xAA).take(200));
        let (content, _) = der_read_tag(&data, 0x30).unwrap();
        assert_eq!(content.len(), 200);
    }

    #[test]
    fn test_der_read_ctx_tag_704() {
        let mut data = vec![0xBF, 0x85, 0x40, 0x03];
        data.extend_from_slice(b"ABC");
        let (content, _) = der_read_ctx_tag(&data, 704).unwrap();
        assert_eq!(content, b"ABC");
    }

    /// FIX 2 regression test : tag 1-byte puis tag [704], on doit trouver [704].
    #[test]
    fn test_find_ctx_tag_skips_other_tags() {
        // teeEnforced factice :
        //   [600] { NULL }  →  0xBF 0x84 0x58 0x02 0x05 0x00
        //   [704] { "XY" }  →  0xBF 0x85 0x40 0x02 'X' 'Y'
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&[0xBF, 0x84, 0x58, 0x02, 0x05, 0x00]);
        data.extend_from_slice(&[0xBF, 0x85, 0x40, 0x02, b'X', b'Y']);
        let content = der_find_ctx_tag(&data, 704).unwrap();
        assert_eq!(content, b"XY");
    }

    #[test]
    fn test_parse_root_of_trust() {
        let vbk = [0x04u8, 0x02, 0xDE, 0xAD];
        let dl = [0x01u8, 0x01, 0xFF];
        let vbs = [0x0A_u8, 0x01, 0x00];
        let mut vbh = vec![0x04u8, 0x20];
        vbh.extend(std::iter::repeat(0x00).take(32));

        let mut inner = Vec::new();
        inner.extend_from_slice(&vbk);
        inner.extend_from_slice(&dl);
        inner.extend_from_slice(&vbs);
        inner.extend_from_slice(&vbh);

        let mut full = vec![0x30u8, inner.len() as u8];
        full.extend_from_slice(&inner);

        let rot = parse_root_of_trust(&full).unwrap();
        assert!(rot.device_locked);
        assert_eq!(rot.verified_boot_state, 0);
        assert_eq!(rot.verified_boot_hash.len(), 32);
    }
}