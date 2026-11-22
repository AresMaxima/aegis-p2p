// src/network/ble_handshake.rs
// Handshake ed25519 + ML-KEM-1024 (FIPS 203) + ML-DSA-87 (FIPS 204) Pur Rust.

use std::sync::Mutex;
use std::time::Instant;

use fips203::ml_kem_1024;
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as KemSerDes};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes as DsaSerDes, Signer as _, Verifier as _};

use crate::{ed25519_sign_safe, ed25519_verify_safe};

pub const MSG1_LEN: usize = 8915;
pub const MSG2_LEN: usize = 10483;
pub const MSG3_LEN: usize = 6259;

pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
const HKDF_SALT: &[u8] = b"AEGIS-BLE-HANDSHAKE-v2-SALT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole { Initiator, Responder }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase { Idle, AwaitingMsg2, AwaitingMsg3, Complete, Failed }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    NotStarted, AlreadyStarted, WrongPhase, InvalidLength,
    InvalidSignature, FingerprintMismatch, CryptoUnavailable,
    Timeout, FragmentError,
}

impl HandshakeError {
    pub fn to_code(self) -> i32 {
        match self {
            HandshakeError::NotStarted => -50,
            HandshakeError::AlreadyStarted => -51,
            HandshakeError::WrongPhase => -52,
            HandshakeError::InvalidLength => -53,
            HandshakeError::InvalidSignature => -54,
            HandshakeError::FingerprintMismatch => -55,
            HandshakeError::CryptoUnavailable => -56,
            HandshakeError::Timeout => -57,
            HandshakeError::FragmentError => -58,
        }
    }
}

#[derive(Debug)]
pub struct HandshakeState {
    pub role: HandshakeRole,
    pub phase: HandshakePhase,
    pub peer_fingerprint: [u8; 32],
    pub own_nonce: [u8; 32],
    pub own_ed_pubkey: [u8; 32],
    pub own_mlkem_pk: Vec<u8>,
    pub own_mlkem_sk: Vec<u8>,
    pub own_mldsa_pk: Vec<u8>,
    pub own_mldsa_sk: Vec<u8>,
    pub peer_ed_pubkey: Option<[u8; 32]>,
    pub peer_mlkem_pk: Option<Vec<u8>>,
    pub peer_mldsa_pk: Option<Vec<u8>>,
    pub peer_nonce: Option<[u8; 32]>,
    pub mlkem_ss_i_to_r: Option<[u8; 32]>,
    pub mlkem_ss_r_to_i: Option<[u8; 32]>,
    pub shared_secret: Option<[u8; 32]>,
    pub rx_buffer: Vec<u8>,
    pub started_at: Instant,
}

impl HandshakeState {
    pub fn new(role: HandshakeRole, peer_fingerprint: [u8; 32]) -> Result<Self, HandshakeError> {
        let own_nonce = generate_nonce()?;
        let own_ed_pubkey = own_ed25519_pubkey()?;
        let (mlkem_pk, mlkem_sk) = ml_kem_1024::KG::try_keygen().map_err(|_| HandshakeError::CryptoUnavailable)?;
        let (mldsa_pk, mldsa_sk) = ml_dsa_87::try_keygen().map_err(|_| HandshakeError::CryptoUnavailable)?;

        Ok(Self {
            role, phase: HandshakePhase::Idle, peer_fingerprint,
            own_nonce, own_ed_pubkey,
            own_mlkem_pk: KemSerDes::into_bytes(mlkem_pk).to_vec(),
            own_mlkem_sk: KemSerDes::into_bytes(mlkem_sk).to_vec(),
            own_mldsa_pk: DsaSerDes::into_bytes(mldsa_pk).to_vec(),
            own_mldsa_sk: DsaSerDes::into_bytes(mldsa_sk).to_vec(),
            peer_ed_pubkey: None, peer_mlkem_pk: None, peer_mldsa_pk: None, peer_nonce: None,
            mlkem_ss_i_to_r: None, mlkem_ss_r_to_i: None, shared_secret: None,
            rx_buffer: Vec::new(), started_at: Instant::now(),
        })
    }

    pub fn is_timed_out(&self, now: Instant) -> bool {
        now.duration_since(self.started_at).as_secs() >= HANDSHAKE_TIMEOUT_SECS
    }

    pub fn feed_fragment(&mut self, frag: &[u8]) -> Result<Option<Vec<u8>>, HandshakeError> {
        let expected_len = match (self.role, self.phase) {
            (HandshakeRole::Initiator, HandshakePhase::AwaitingMsg2) => MSG2_LEN,
            (HandshakeRole::Responder, HandshakePhase::Idle) => MSG1_LEN,
            (HandshakeRole::Responder, HandshakePhase::AwaitingMsg3) => MSG3_LEN,
            _ => return Err(HandshakeError::WrongPhase),
        };

        self.rx_buffer.extend_from_slice(frag);
        if self.rx_buffer.len() < expected_len { return Ok(None); }
        if self.rx_buffer.len() > expected_len {
            self.rx_buffer.clear();
            return Err(HandshakeError::FragmentError);
        }

        let msg = std::mem::take(&mut self.rx_buffer);
        let reply = match (self.role, self.phase) {
            (HandshakeRole::Initiator, HandshakePhase::AwaitingMsg2) => self.initiator_process_msg2(&msg)?,
            (HandshakeRole::Responder, HandshakePhase::Idle) => self.responder_process_msg1(&msg)?,
            (HandshakeRole::Responder, HandshakePhase::AwaitingMsg3) => { self.responder_process_msg3(&msg)?; None }
            _ => return Err(HandshakeError::WrongPhase),
        };
        Ok(reply)
    }

    pub fn initiator_start(&mut self) -> Result<Vec<u8>, HandshakeError> {
        if self.role != HandshakeRole::Initiator || self.phase != HandshakePhase::Idle {
            return Err(HandshakeError::WrongPhase);
        }
        let mut msg = Vec::with_capacity(MSG1_LEN);
        msg.extend_from_slice(&self.own_nonce);
        msg.extend_from_slice(&self.own_ed_pubkey);
        msg.extend_from_slice(&self.own_mlkem_pk);
        msg.extend_from_slice(&self.own_mldsa_pk);
        let sig = sign_hybrid(&msg, &self.own_mldsa_sk)?;
        msg.extend_from_slice(&sig);
        self.phase = HandshakePhase::AwaitingMsg2;
        Ok(msg)
    }

    pub fn initiator_process_msg2(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>, HandshakeError> {
        if self.phase != HandshakePhase::AwaitingMsg2 { return Err(HandshakeError::WrongPhase); }
        if msg.len() != MSG2_LEN { return Err(HandshakeError::InvalidLength); }

        let mut offset = 0;
        let mut nonce_r = [0u8; 32]; nonce_r.copy_from_slice(&msg[offset..offset+32]); offset += 32;
        let mut ed_pub_r = [0u8; 32]; ed_pub_r.copy_from_slice(&msg[offset..offset+32]); offset += 32;
        let mlkem_pk_r = &msg[offset..offset+1568]; offset += 1568;
        let mldsa_pk_r = &msg[offset..offset+2592]; offset += 2592;
        let mlkem_ct_r_to_i = &msg[offset..offset+1568]; offset += 1568;
        let sig_hybride_r = &msg[offset..];
        let signed_data = &msg[0..offset];

        if !verify_peer_fingerprint(&ed_pub_r, &self.peer_fingerprint)? {
            self.phase = HandshakePhase::Failed; return Err(HandshakeError::FingerprintMismatch);
        }
        if !verify_hybrid(signed_data, sig_hybride_r, &ed_pub_r, mldsa_pk_r) {
            self.phase = HandshakePhase::Failed; return Err(HandshakeError::InvalidSignature);
        }

        let ct_arr: [u8; ml_kem_1024::CT_LEN] = mlkem_ct_r_to_i.try_into().map_err(|_| HandshakeError::CryptoUnavailable)?;
        let sk_arr: [u8; ml_kem_1024::DK_LEN] = self.own_mlkem_sk.as_slice().try_into().map_err(|_| HandshakeError::CryptoUnavailable)?;
        let ct = ml_kem_1024::CipherText::try_from_bytes(ct_arr).map_err(|_| HandshakeError::CryptoUnavailable)?;
        let sk = ml_kem_1024::DecapsKey::try_from_bytes(sk_arr).map_err(|_| HandshakeError::CryptoUnavailable)?;
        let ss = sk.try_decaps(&ct).map_err(|_| HandshakeError::CryptoUnavailable)?;
        self.mlkem_ss_r_to_i = Some(KemSerDes::into_bytes(ss));

        let pk_r_arr: [u8; ml_kem_1024::EK_LEN] = mlkem_pk_r.try_into().map_err(|_| HandshakeError::CryptoUnavailable)?;
        let pk_r = ml_kem_1024::EncapsKey::try_from_bytes(pk_r_arr).map_err(|_| HandshakeError::CryptoUnavailable)?;
        let (ss_i_to_r, ct_i_to_r) = pk_r.try_encaps().map_err(|_| HandshakeError::CryptoUnavailable)?;
        self.mlkem_ss_i_to_r = Some(KemSerDes::into_bytes(ss_i_to_r));

        let mut msg3 = Vec::with_capacity(MSG3_LEN);
        msg3.extend_from_slice(&KemSerDes::into_bytes(ct_i_to_r));
        let sig3 = sign_hybrid(&msg3, &self.own_mldsa_sk)?;
        msg3.extend_from_slice(&sig3);

        self.peer_nonce = Some(nonce_r);
        self.peer_ed_pubkey = Some(ed_pub_r);
        self.peer_mlkem_pk = Some(mlkem_pk_r.to_vec());
        self.peer_mldsa_pk = Some(mldsa_pk_r.to_vec());

        self.shared_secret = Some(derive_shared_secret(
            &self.mlkem_ss_i_to_r.unwrap(), &self.mlkem_ss_r_to_i.unwrap(),
            &self.own_nonce, &nonce_r, &self.own_ed_pubkey, &ed_pub_r,
        )?);

        self.phase = HandshakePhase::Complete;
        Ok(Some(msg3))
    }

    pub fn responder_process_msg1(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>, HandshakeError> {
        if self.role != HandshakeRole::Responder || self.phase != HandshakePhase::Idle { return Err(HandshakeError::WrongPhase); }
        if msg.len() != MSG1_LEN { return Err(HandshakeError::InvalidLength); }

        let mut offset = 0;
        let mut nonce_i = [0u8; 32]; nonce_i.copy_from_slice(&msg[offset..offset+32]); offset += 32;
        let mut ed_pub_i = [0u8; 32]; ed_pub_i.copy_from_slice(&msg[offset..offset+32]); offset += 32;
        let mlkem_pk_i = &msg[offset..offset+1568]; offset += 1568;
        let mldsa_pk_i = &msg[offset..offset+2592]; offset += 2592;
        let sig_hybride_i = &msg[offset..];
        let signed_data = &msg[0..offset];

        if !verify_peer_fingerprint(&ed_pub_i, &self.peer_fingerprint)? {
            self.phase = HandshakePhase::Failed; return Err(HandshakeError::FingerprintMismatch);
        }
        if !verify_hybrid(signed_data, sig_hybride_i, &ed_pub_i, mldsa_pk_i) {
            self.phase = HandshakePhase::Failed; return Err(HandshakeError::InvalidSignature);
        }

        let pk_i_arr: [u8; ml_kem_1024::EK_LEN] = mlkem_pk_i.try_into().map_err(|_| HandshakeError::CryptoUnavailable)?;
        let pk_i = ml_kem_1024::EncapsKey::try_from_bytes(pk_i_arr).map_err(|_| HandshakeError::CryptoUnavailable)?;
        let (ss_r_to_i, ct_r_to_i) = pk_i.try_encaps().map_err(|_| HandshakeError::CryptoUnavailable)?;
        self.mlkem_ss_r_to_i = Some(KemSerDes::into_bytes(ss_r_to_i));

        let mut msg2 = Vec::with_capacity(MSG2_LEN);
        msg2.extend_from_slice(&self.own_nonce);
        msg2.extend_from_slice(&self.own_ed_pubkey);
        msg2.extend_from_slice(&self.own_mlkem_pk);
        msg2.extend_from_slice(&self.own_mldsa_pk);
        msg2.extend_from_slice(&KemSerDes::into_bytes(ct_r_to_i));
        let sig2 = sign_hybrid(&msg2, &self.own_mldsa_sk)?;
        msg2.extend_from_slice(&sig2);

        self.peer_nonce = Some(nonce_i);
        self.peer_ed_pubkey = Some(ed_pub_i);
        self.peer_mlkem_pk = Some(mlkem_pk_i.to_vec());
        self.peer_mldsa_pk = Some(mldsa_pk_i.to_vec());

        self.phase = HandshakePhase::AwaitingMsg3;
        Ok(Some(msg2))
    }

    pub fn responder_process_msg3(&mut self, msg: &[u8]) -> Result<(), HandshakeError> {
        if self.phase != HandshakePhase::AwaitingMsg3 { return Err(HandshakeError::WrongPhase); }
        if msg.len() != MSG3_LEN { return Err(HandshakeError::InvalidLength); }

        let mlkem_ct_i_to_r = &msg[0..1568];
        let sig_hybride_i = &msg[1568..];

        let ed_pub_i = self.peer_ed_pubkey.ok_or(HandshakeError::WrongPhase)?;
        let mldsa_pk_i = self.peer_mldsa_pk.as_ref().ok_or(HandshakeError::WrongPhase)?;
        let signed_data = &msg[0..1568];
        if !verify_hybrid(signed_data, sig_hybride_i, &ed_pub_i, mldsa_pk_i) {
            self.phase = HandshakePhase::Failed; return Err(HandshakeError::InvalidSignature);
        }

        let ct_arr: [u8; ml_kem_1024::CT_LEN] = mlkem_ct_i_to_r.try_into().map_err(|_| HandshakeError::CryptoUnavailable)?;
        let sk_arr: [u8; ml_kem_1024::DK_LEN] = self.own_mlkem_sk.as_slice().try_into().map_err(|_| HandshakeError::CryptoUnavailable)?;
        let ct = ml_kem_1024::CipherText::try_from_bytes(ct_arr).map_err(|_| HandshakeError::CryptoUnavailable)?;
        let sk = ml_kem_1024::DecapsKey::try_from_bytes(sk_arr).map_err(|_| HandshakeError::CryptoUnavailable)?;
        let ss = sk.try_decaps(&ct).map_err(|_| HandshakeError::CryptoUnavailable)?;
        self.mlkem_ss_i_to_r = Some(KemSerDes::into_bytes(ss));

        let nonce_i = self.peer_nonce.ok_or(HandshakeError::WrongPhase)?;
        self.shared_secret = Some(derive_shared_secret(
            &self.mlkem_ss_i_to_r.unwrap(), &self.mlkem_ss_r_to_i.unwrap(),
            &nonce_i, &self.own_nonce, &ed_pub_i, &self.own_ed_pubkey,
        )?);

        self.phase = HandshakePhase::Complete;
        Ok(())
    }
}

fn generate_nonce() -> Result<[u8; 32], HandshakeError> {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|_| HandshakeError::CryptoUnavailable)?;
    Ok(nonce)
}

fn own_ed25519_pubkey() -> Result<[u8; 32], HandshakeError> {
    let mut pk = [0u8; 32];
    let rc = unsafe { crate::aegis_ed25519_public_key(pk.as_mut_ptr()) };
    if rc != 0 { return Err(HandshakeError::CryptoUnavailable); }
    Ok(pk)
}

fn verify_peer_fingerprint(pubkey: &[u8; 32], expected_fp: &[u8; 32]) -> Result<bool, HandshakeError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let computed = hasher.finalize();
    Ok(computed.as_slice() == expected_fp)
}

fn sign_hybrid(data: &[u8], mldsa_sk: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let ed_sig = match data.len() {
        32 => ed25519_sign_safe(data.try_into().unwrap()).map_err(|_| HandshakeError::CryptoUnavailable)?,
        _ => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new(); h.update(data);
            let hash = h.finalize();
            let mut arr = [0u8; 32]; arr.copy_from_slice(&hash);
            ed25519_sign_safe(&arr).map_err(|_| HandshakeError::CryptoUnavailable)?
        }
    };

    let sk_arr: [u8; ml_dsa_87::SK_LEN] = mldsa_sk.try_into().map_err(|_| HandshakeError::CryptoUnavailable)?;
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_arr).map_err(|_| HandshakeError::CryptoUnavailable)?;
    let mldsa_sig = sk.try_sign(data, &[]).map_err(|_| HandshakeError::CryptoUnavailable)?;

    let mut out = Vec::with_capacity(64 + ml_dsa_87::SIG_LEN);
    out.extend_from_slice(&ed_sig);
    out.extend_from_slice(&mldsa_sig);
    Ok(out)
}

fn verify_hybrid(data: &[u8], sig: &[u8], ed_pk: &[u8; 32], mldsa_pk: &[u8]) -> bool {
    if sig.len() != 64 + ml_dsa_87::SIG_LEN { return false; }
    let ed_sig = &sig[0..64];
    let mldsa_sig = &sig[64..];

    let ed_ok = match data.len() {
        32 => {
            let mut arr = [0u8; 32]; arr.copy_from_slice(data);
            let mut sig_arr = [0u8; 64]; sig_arr.copy_from_slice(ed_sig);
            ed25519_verify_safe(&arr, ed_pk, &sig_arr)
        }
        _ => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new(); h.update(data);
            let hash = h.finalize();
            let mut arr = [0u8; 32]; arr.copy_from_slice(&hash);
            let mut sig_arr = [0u8; 64]; sig_arr.copy_from_slice(ed_sig);
            ed25519_verify_safe(&arr, ed_pk, &sig_arr)
        }
    };
    if !ed_ok { return false; }

    let pk_arr: [u8; ml_dsa_87::PK_LEN] = match mldsa_pk.try_into() { Ok(a) => a, Err(_) => return false };
    let sig_arr: [u8; ml_dsa_87::SIG_LEN] = match mldsa_sig.try_into() { Ok(a) => a, Err(_) => return false };
    let pk = match ml_dsa_87::PublicKey::try_from_bytes(pk_arr) { Ok(k) => k, Err(_) => return false };
    pk.verify(data, &sig_arr, &[])
}

fn derive_shared_secret(mlkem_ss_i_to_r: &[u8; 32], mlkem_ss_r_to_i: &[u8; 32], nonce_i: &[u8; 32], nonce_r: &[u8; 32], ed_pk_i: &[u8; 32], ed_pk_r: &[u8; 32]) -> Result<[u8; 32], HandshakeError> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(mlkem_ss_i_to_r);
    ikm.extend_from_slice(mlkem_ss_r_to_i);
    let mut info = Vec::with_capacity(128);
    info.extend_from_slice(nonce_i); info.extend_from_slice(nonce_r);
    info.extend_from_slice(ed_pk_i); info.extend_from_slice(ed_pk_r);
    let hk = hkdf::Hkdf::<sha2::Sha384>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).map_err(|_| HandshakeError::CryptoUnavailable)?;
    use zeroize::Zeroize; ikm.zeroize();
    Ok(okm)
}

static HANDSHAKE_STATE: Mutex<Option<HandshakeState>> = Mutex::new(None);

pub fn start_initiator(peer_fingerprint: [u8; 32]) -> Result<(), HandshakeError> {
    let mut guard = HANDSHAKE_STATE.lock().map_err(|_| HandshakeError::AlreadyStarted)?;
    if guard.is_some() { return Err(HandshakeError::AlreadyStarted); }
    let mut state = HandshakeState::new(HandshakeRole::Initiator, peer_fingerprint)?;
    let msg1 = state.initiator_start()?;
    crate::network::ble_mesh_reader::write_handshake_msg(&msg1)?;
    *guard = Some(state);
    Ok(())
}

pub fn start_responder(peer_fingerprint: [u8; 32]) -> Result<(), HandshakeError> {
    let mut guard = HANDSHAKE_STATE.lock().map_err(|_| HandshakeError::AlreadyStarted)?;
    if guard.is_some() { return Err(HandshakeError::AlreadyStarted); }
    let state = HandshakeState::new(HandshakeRole::Responder, peer_fingerprint)?;
    *guard = Some(state);
    Ok(())
}

pub fn process_incoming_fragment(frag: &[u8]) -> Result<(), HandshakeError> {
    let mut guard = HANDSHAKE_STATE.lock().map_err(|_| HandshakeError::WrongPhase)?;
    let state = guard.as_mut().ok_or(HandshakeError::NotStarted)?;
    if state.is_timed_out(Instant::now()) { state.phase = HandshakePhase::Failed; return Err(HandshakeError::Timeout); }
    if let Some(reply) = state.feed_fragment(frag)? { crate::network::ble_mesh_reader::write_handshake_msg(&reply)?; }
    Ok(())
}

pub fn is_in_progress() -> bool {
    match HANDSHAKE_STATE.lock() {
        Ok(g) => match g.as_ref() { Some(s) => matches!(s.phase, HandshakePhase::Idle | HandshakePhase::AwaitingMsg2 | HandshakePhase::AwaitingMsg3), None => false },
        Err(_) => false,
    }
}

pub fn is_complete() -> bool {
    match HANDSHAKE_STATE.lock() { Ok(g) => g.as_ref().map(|s| s.phase == HandshakePhase::Complete).unwrap_or(false), Err(_) => false }
}

pub fn reset() {
    if let Ok(mut g) = HANDSHAKE_STATE.lock() { *g = None; }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ble_handshake_start_initiator(fp_ptr: *const u8) -> i32 {
    if fp_ptr.is_null() { return HandshakeError::InvalidLength.to_code(); }
    let mut fp = [0u8; 32]; unsafe { fp.copy_from_slice(std::slice::from_raw_parts(fp_ptr, 32)) };
    match start_initiator(fp) { Ok(()) => 0, Err(e) => e.to_code() }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ble_handshake_start_responder(fp_ptr: *const u8) -> i32 {
    if fp_ptr.is_null() { return HandshakeError::InvalidLength.to_code(); }
    let mut fp = [0u8; 32]; unsafe { fp.copy_from_slice(std::slice::from_raw_parts(fp_ptr, 32)) };
    match start_responder(fp) { Ok(()) => 0, Err(e) => e.to_code() }
}

#[no_mangle]
pub extern "C" fn aegis_ble_handshake_is_complete() -> i32 { if is_complete() { 1 } else { 0 } }

#[no_mangle]
pub extern "C" fn aegis_ble_handshake_reset() -> i32 { reset(); 0 }

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1ble_1handshake_1start_1initiator(env: jni::JNIEnv, _this: jni::objects::JObject, fp: jni::objects::JByteArray) -> jni::sys::jint {
    let fp_vec = match env.convert_byte_array(&fp) { Ok(v) => v, Err(_) => { let _ = env.exception_clear(); return HandshakeError::InvalidLength.to_code(); } };
    if fp_vec.len() != 32 { return HandshakeError::InvalidLength.to_code(); }
    let mut fp_arr = [0u8; 32]; fp_arr.copy_from_slice(&fp_vec);
    match start_initiator(fp_arr) { Ok(()) => 0, Err(e) => e.to_code() }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1ble_1handshake_1start_1responder(env: jni::JNIEnv, _this: jni::objects::JObject, fp: jni::objects::JByteArray) -> jni::sys::jint {
    let fp_vec = match env.convert_byte_array(&fp) { Ok(v) => v, Err(_) => { let _ = env.exception_clear(); return HandshakeError::InvalidLength.to_code(); } };
    if fp_vec.len() != 32 { return HandshakeError::InvalidLength.to_code(); }
    let mut fp_arr = [0u8; 32]; fp_arr.copy_from_slice(&fp_vec);
    match start_responder(fp_arr) { Ok(()) => 0, Err(e) => e.to_code() }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1ble_1handshake_1is_1complete(_env: jni::JNIEnv, _this: jni::objects::JObject) -> jni::sys::jint {
    if is_complete() { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_aresmaxima_aegis_MainActivity_aegis_1ble_1handshake_1reset(_env: jni::JNIEnv, _this: jni::objects::JObject) -> jni::sys::jint {
    reset(); 0
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::keystore::{HardwareKeystore, TEST_LOCK};

    fn setup_master_key() {
        let root_key = [0x42u8; 32];
        HardwareKeystore::set_root_key(&root_key).expect("set_root_key");
        HardwareKeystore::derive_master_key("TestPIN-BleHandshake").expect("derive_master_key");
    }

    fn teardown() {
        let _ = HardwareKeystore::wipe_all();
        reset();
    }

    fn own_fingerprint() -> [u8; 32] {
        let mut fp = [0u8; 32];
        let rc = unsafe { crate::aegis_ed25519_fingerprint(fp.as_mut_ptr()) };
        assert_eq!(rc, 0);
        fp
    }

    fn own_ed_pubkey() -> [u8; 32] {
        let mut pk = [0u8; 32];
        let rc = unsafe { crate::aegis_ed25519_public_key(pk.as_mut_ptr()) };
        assert_eq!(rc, 0);
        pk
    }

    #[test]
    fn test_hybrid_sign_verify_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        setup_master_key();
        let (pk, sk) = ml_dsa_87::try_keygen().unwrap();
        let pk_bytes = DsaSerDes::into_bytes(pk);
        let sk_bytes = DsaSerDes::into_bytes(sk);
        let data = b"test message";
        let sig = sign_hybrid(data, &sk_bytes).unwrap();
        assert!(verify_hybrid(data, &sig, &own_ed_pubkey(), &pk_bytes));
        teardown();
    }

    #[test]
    fn test_hybrid_sign_rejects_wrong_message() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        setup_master_key();
        let (pk, sk) = ml_dsa_87::try_keygen().unwrap();
        let pk_bytes = DsaSerDes::into_bytes(pk);
        let sk_bytes = DsaSerDes::into_bytes(sk);
        let data = b"message A";
        let sig = sign_hybrid(data, &sk_bytes).unwrap();
        assert!(!verify_hybrid(b"message B", &sig, &own_ed_pubkey(), &pk_bytes));
        teardown();
    }

    #[test]
    fn test_end_to_end_v2() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        setup_master_key();
        let own_fp = own_fingerprint();

        let mut init = HandshakeState::new(HandshakeRole::Initiator, own_fp).unwrap();
        let mut resp = HandshakeState::new(HandshakeRole::Responder, own_fp).unwrap();

        let msg1 = init.initiator_start().unwrap();
        assert_eq!(msg1.len(), MSG1_LEN);

        let msg2 = resp.responder_process_msg1(&msg1).unwrap().unwrap();
        assert_eq!(msg2.len(), MSG2_LEN);

        let msg3 = init.initiator_process_msg2(&msg2).unwrap().unwrap();
        assert_eq!(msg3.len(), MSG3_LEN);
        assert_eq!(init.phase, HandshakePhase::Complete);

        resp.responder_process_msg3(&msg3).unwrap();
        assert_eq!(resp.phase, HandshakePhase::Complete);
        assert_eq!(init.shared_secret, resp.shared_secret);
        teardown();
    }

    #[test]
    fn test_shared_secret_differs_on_input_change() {
        let a = [0x01; 32]; let b = [0x02; 32]; let c = [0x03; 32]; let d = [0x04; 32];
        let s1 = derive_shared_secret(&a, &b, &c, &d, &c, &d).unwrap();
        let s2 = derive_shared_secret(&b, &a, &c, &d, &c, &d).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_timeout() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        setup_master_key();
        reset();
        let mut state = HandshakeState::new(HandshakeRole::Initiator, [0x00; 32]).unwrap();
        state.started_at = Instant::now() - std::time::Duration::from_secs(31);
        assert!(state.is_timed_out(Instant::now()));
        teardown();
    }

    #[test]
    fn test_reset_clears_state() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        setup_master_key();
        reset();
        start_responder([0x00; 32]).unwrap();
        assert!(is_in_progress());
        reset();
        assert!(!is_in_progress());
        teardown();
    }
}