//! aegis-core/src/network/stealth_transport.rs
//! C96 — Anti-DPI Stealth Transport (WebTunnel / HTTP/3 MASQUE RFC 9297 + TLS ECH)
//!
//! Rend le flux de cellules fixes de 512 octets d'AEGIS indiscernable d'une
//! session HTTPS / HTTP/3 (QUIC) ordinaire face aux boitiers DPI etatiques
//! bloquant Tor et Snowflake.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

pub const AEGIS_CELL_LEN: usize = 512;
/// Type de capsule HTTP/3 DATAGRAM (RFC 9297 Section 3.5)
pub const H3_CAPSULE_DATAGRAM: u8 = 0x00;
/// Type de capsule HTTP/3 PADDING / GREASE (RFC 9297 Section 5.4 : 41 * N + 23 -> 0x4040 varint)
pub const H3_CAPSULE_GREASE_PAD: u8 = 0x40;
/// Code d'extension TLS 1.3 Encrypted Client Hello (IETF ECH 0xFE0D)
pub const TLS_EXT_ECH: u16 = 0xFE0D;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StealthError {
    MalformedCapsule,
    TruncatedFrame,
    AuthFailed,
    InvalidHost,
}

/// Encode un entier en QUIC Variable-Length Integer (RFC 9000 Section 16, 2 octets pour 64..16383).
#[inline]
pub fn encode_quic_varint_2b(val: usize) -> Result<[u8; 2], StealthError> {
    if val > 0x3FFF {
        return Err(StealthError::MalformedCapsule);
    }
    let v = (val as u16) | 0x4000;
    Ok(v.to_be_bytes())
}

#[inline]
pub fn decode_quic_varint(buf: &[u8]) -> Result<(usize, usize), StealthError> {
    if buf.is_empty() {
        return Err(StealthError::TruncatedFrame);
    }
    let prefix = buf[0] >> 6;
    match prefix {
        0 => Ok(((buf[0] & 0x3F) as usize, 1)),
        1 => {
            if buf.len() < 2 {
                return Err(StealthError::TruncatedFrame);
            }
            let v = u16::from_be_bytes([buf[0] & 0x3F, buf[1]]) as usize;
            Ok((v, 2))
        }
        _ => Err(StealthError::MalformedCapsule),
    }
}

/// Construit une requete HTTP/1.1 / HTTP/3 Extended CONNECT compatible Tor WebTunnel
/// imitant un navigateur standard vers un domaine de couverture banal.
pub fn build_webtunnel_upgrade_headers(cover_host: &str, secret_path: &str) -> Result<String, StealthError> {
    if cover_host.is_empty()
        || cover_host.contains('\r')
        || cover_host.contains('\n')
        || secret_path.contains('\r')
        || secret_path.contains('\n')
    {
        return Err(StealthError::InvalidHost);
    }
    let mut nonce_raw = [0u8; 16];
    let _ = getrandom::getrandom(&mut nonce_raw);
    use base64::Engine;
    let ws_key = base64::engine::general_purpose::STANDARD.encode(nonce_raw);
    nonce_raw.zeroize();

    let path = if secret_path.starts_with('/') {
        secret_path.to_owned()
    } else {
        format!("/{}", secret_path)
    };

    Ok(format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {cover_host}\r\n\
         User-Agent: Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-Fetch-Dest: empty\r\n\
         Sec-Fetch-Mode: websocket\r\n\
         Sec-Fetch-Site: same-origin\r\n\r\n"
    ))
}

/// Genere une extension binaire TLS 1.3 Encrypted Client Hello (0xFE0D) valide en structure
/// (HPKE X25519 + HKDF-SHA256 + ChaCha20-Poly1305) pour masquer le ClientHello interne aux sondes DPI.
pub fn build_tls_ech_extension(
    config_id: u8,
    ech_public_key_32: &[u8; 32],
    inner_sni: &[u8],
) -> Result<Vec<u8>, StealthError> {
    if inner_sni.is_empty() || inner_sni.len() > 128 {
        return Err(StealthError::InvalidHost);
    }
    let mut eph_seed = [0u8; 32];
    let _ = getrandom::getrandom(&mut eph_seed);
    let eph_sk = X25519StaticSecret::from(eph_seed);
    eph_seed.zeroize();
    let eph_pk = X25519PublicKey::from(&eph_sk);
    let peer_pk = X25519PublicKey::from(*ech_public_key_32);
    let mut shared = eph_sk.diffie_hellman(&peer_pk).to_bytes();

    let hk = Hkdf::<Sha256>::new(Some(b"AEGIS-TLS13-ECH-HPKE"), &shared);
    shared.zeroize();
    let mut key_nonce = [0u8; 44];
    hk.expand(b"ECH-KEY+NONCE", &mut key_nonce)
        .map_err(|_| StealthError::AuthFailed)?;

    let cipher = ChaCha20Poly1305::new(key_nonce[0..32].into());
    let nonce = Nonce::from_slice(&key_nonce[32..44]);

    // Pad inner ClientHello a un palier standard RFC 9849 (160 octets)
    let mut padded_ch = [0u8; 160];
    padded_ch[0] = inner_sni.len() as u8;
    padded_ch[1..1 + inner_sni.len()].copy_from_slice(inner_sni);

    // En-tete ECH ClientHelloOuter : type(0x00=outer) || kdf_id(0x0001 HKDF-SHA256) || aead_id(0x0003 ChaCha20Poly1305) || config_id || enc_len(0x0020) || enc(32B)
    let mut header = Vec::with_capacity(42);
    header.push(0x00); // ECHClientHelloType::outer
    header.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
    header.extend_from_slice(&0x0003u16.to_be_bytes()); // ChaCha20Poly1305
    header.push(config_id);
    header.extend_from_slice(&32u16.to_be_bytes());
    header.extend_from_slice(eph_pk.as_bytes());

    let encrypted_ch = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &padded_ch,
                aad: &header,
            },
        )
        .map_err(|_| StealthError::AuthFailed)?;
    key_nonce.zeroize();
    padded_ch.zeroize();

    let body_len = header.len() + 2 + encrypted_ch.len();
    let mut ext = Vec::with_capacity(4 + body_len);
    ext.extend_from_slice(&TLS_EXT_ECH.to_be_bytes());
    ext.extend_from_slice(&(body_len as u16).to_be_bytes());
    ext.extend_from_slice(&header);
    ext.extend_from_slice(&(encrypted_ch.len() as u16).to_be_bytes());
    ext.extend_from_slice(&encrypted_ch);
    Ok(ext)
}

/// Encapsule une cellule AEGIS de 512 octets dans un flux HTTP/3 MASQUE (RFC 9297) :
/// [CAPSULE_DATAGRAM (0x00)] [VarInt Len (541)] [ContextID=0x00] [Nonce 12B] [AEAD(512B)+Tag(16B)]
/// suivi d'une capsule GREASE stochastique (16..143 octets) pour casser la signature de taille fixe sur le lien WAN !
pub fn wrap_cell_masque_h3(
    obf_key_32: &[u8; 32],
    cell_512: &[u8; AEGIS_CELL_LEN],
) -> Result<Vec<u8>, StealthError> {
    let mut nonce_bytes = [0u8; 12];
    let mut jitter_seed = [0u8; 1];
    let _ = getrandom::getrandom(&mut nonce_bytes);
    let _ = getrandom::getrandom(&mut jitter_seed);

    let cipher = ChaCha20Poly1305::new(obf_key_32.into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: cell_512,
                aad: b"H3-MASQUE-v3.7",
            },
        )
        .map_err(|_| StealthError::AuthFailed)?;

    // Payload = ContextID(1B = 0x00) + Nonce(12B) + Ciphertext(528B) = 541 octets
    let dgram_len = 1 + 12 + ct.len();
    let len_varint = encode_quic_varint_2b(dgram_len)?;

    let grease_len = 16usize + ((jitter_seed[0] as usize) & 0x7F); // 16..143 octets variables
    let mut grease_noise = vec![0u8; grease_len];
    let _ = getrandom::getrandom(&mut grease_noise);
    let grease_varint = encode_quic_varint_2b(grease_len)?;

    let mut out = Vec::with_capacity(1 + 2 + dgram_len + 2 + 2 + grease_len);
    // 1. Capsule DATAGRAM utile
    out.push(H3_CAPSULE_DATAGRAM);
    out.extend_from_slice(&len_varint);
    out.push(0x00); // HTTP Datagram Context ID = 0
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);

    // 2. Capsule GREASE d'obscurcissement de profil statistique (ignoree a la reception RFC 9297)
    out.push(H3_CAPSULE_GREASE_PAD);
    out.push(0x29); // QUIC VarInt 2B = 0x0029 (Grease Capsule Type = 41)
    out.extend_from_slice(&grease_varint);
    out.extend_from_slice(&grease_noise);
    grease_noise.zeroize();

    Ok(out)
}

/// Desencapsule un flux HTTP/3 MASQUE, ignore toute capsule GREASE/inconnue, et restitue la cellule pure de 512 octets.
pub fn unwrap_cell_masque_h3(
    obf_key_32: &[u8; 32],
    wire_frame: &[u8],
) -> Result<[u8; AEGIS_CELL_LEN], StealthError> {
    let mut pos = 0usize;
    while pos < wire_frame.len() {
        let (cap_type, t_used) = decode_quic_varint(&wire_frame[pos..])?;
        pos += t_used;
        let (cap_len, l_used) = decode_quic_varint(&wire_frame[pos..])?;
        pos += l_used;

        if wire_frame.len().saturating_sub(pos) < cap_len {
            return Err(StealthError::TruncatedFrame);
        }
        let payload = &wire_frame[pos..pos + cap_len];
        pos += cap_len;

        if cap_type == (H3_CAPSULE_DATAGRAM as usize) {
            // Attendu : ContextID(0x00) + Nonce(12B) + Ciphertext(528B) = 541 octets
            if payload.len() != 1 + 12 + AEGIS_CELL_LEN + 16 || payload[0] != 0x00 {
                return Err(StealthError::MalformedCapsule);
            }
            let nonce = Nonce::from_slice(&payload[1..13]);
            let cipher = ChaCha20Poly1305::new(obf_key_32.into());
            let mut pt = cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &payload[13..],
                        aad: b"H3-MASQUE-v3.7",
                    },
                )
                .map_err(|_| StealthError::AuthFailed)?;
            let mut cell = [0u8; AEGIS_CELL_LEN];
            cell.copy_from_slice(&pt);
            pt.zeroize();
            return Ok(cell);
        }
    }
    Err(StealthError::MalformedCapsule)
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_masque_unwrap_never_panics_on_hostile_dpi_probe() {
        let mut wire = [0u8; 24];
        for i in 0..8 {
            wire[i] = kani::any();
        }
        let key = [0x11u8; 32];
        let _ = unwrap_cell_masque_h3(&key, &wire);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masque_h3_wrap_unwrap_and_variable_wire_size() {
        let key = [0x77u8; 32];
        let mut cell = [0u8; AEGIS_CELL_LEN];
        cell[0] = 0x53;
        cell[511] = 0xFE;

        let f1 = wrap_cell_masque_h3(&key, &cell).unwrap();
        let f2 = wrap_cell_masque_h3(&key, &cell).unwrap();
        assert!(f1.len() > AEGIS_CELL_LEN + 30);
        // Verification que la capsule est integralement dechiffree malgre le padding GREASE
        let r1 = unwrap_cell_masque_h3(&key, &f1).unwrap();
        let r2 = unwrap_cell_masque_h3(&key, &f2).unwrap();
        assert_eq!(r1, cell);
        assert_eq!(r2, cell);
    }

    #[test]
    fn test_tls_ech_and_webtunnel_headers_generation() {
        let pk = [0x33u8; 32];
        let ech = build_tls_ech_extension(42, &pk, b"cdn.cloudflare-ech.example").unwrap();
        assert_eq!(&ech[0..2], &TLS_EXT_ECH.to_be_bytes());
        assert!(ech.len() > 200);

        let hdr = build_webtunnel_upgrade_headers("assets.example-cdn.net", "/v2/stream-9f8a").unwrap();
        assert!(hdr.starts_with("GET /v2/stream-9f8a HTTP/1.1\r\n"));
        assert!(hdr.contains("Upgrade: websocket\r\n"));
    }
}
