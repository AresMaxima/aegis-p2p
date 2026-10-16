// src/network/ble_handshake.rs
//
// P0-A.3e.1 (2026-10-16) — Handshake ed25519 sur BLE.
// P0-A.3e.2b.1 (2026-10-16) — Envoi Msg1 sur out_fd + wrappers JNI.
//
// Réutilise le protocole 3-message symétrique acté en D74 (Wi-Fi Direct).
//
// Format binaire compact (D74) :
//   Msg 1 (I→R) : nonce_i (32) || pubkey_i (32)                     =  64 octets
//   Msg 2 (R→I) : nonce_r (32) || pubkey_r (32) || sig_r(nonce_i)   = 128 octets
//   Msg 3 (I→R) : sig_i(nonce_r)                                     =  64 octets
//
// Vérifications (fail-closed) :
//   • SHA-256(pubkey_X) == peer_fingerprint_X (reçu via QR OOB)
//   • sig_X(nonce_Y) valide pour chaque direction
//
// Décisions actées :
//   D89 (Q18) : GATT direct, rôle client = initiateur
//   D90 (Q19) : routage par état, pas de préfixe type
//   D91 (Q20) : timeout 30 s
//   D92 (Q21) : shared_secret = HKDF-SHA256(nonce_i||nonce_r||pubkey_i||pubkey_r)
//
// Le shared_secret dérivé ici est un placeholder d'amorçage. Il sera
// remplacé par un X3DH complet (DH + ML-KEM-1024) en P0-A.4.

use std::sync::Mutex;
use std::time::Instant;

use crate::{ed25519_fingerprint_safe, ed25519_sign_safe, ed25519_verify_safe};

// ─────────────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────────────

pub const MSG1_LEN: usize = 64;
pub const MSG2_LEN: usize = 128;
pub const MSG3_LEN: usize = 64;

/// D91 : timeout handshake.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Info HKDF pour la dérivation du shared_secret (D92).
const HKDF_INFO: &[u8] = b"AEGIS-BLE-HANDSHAKE-v1";

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Côté client GATT — envoie Msg1, attend Msg2, envoie Msg3.
    Initiator,
    /// Côté serveur GATT — attend Msg1, envoie Msg2, attend Msg3.
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    Idle,
    /// Initiateur : Msg1 envoyé, attend Msg2.
    AwaitingMsg2,
    /// Responder : Msg2 envoyé, attend Msg3.
    AwaitingMsg3,
    /// Handshake terminé — session établie.
    Complete,
    /// Échec (signature, fingerprint, timeout).
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    NotStarted,
    AlreadyStarted,
    WrongPhase,
    InvalidLength,
    InvalidSignature,
    FingerprintMismatch,
    CryptoUnavailable,
    Timeout,
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
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct HandshakeState {
    pub role: HandshakeRole,
    pub phase: HandshakePhase,
    pub peer_fingerprint: [u8; 32],
    pub own_nonce: [u8; 32],
    pub own_pubkey: [u8; 32],
    pub peer_nonce: Option<[u8; 32]>,
    pub peer_pubkey: Option<[u8; 32]>,
    pub shared_secret: Option<[u8; 32]>,
    pub started_at: Instant,
}

impl HandshakeState {
    /// Crée un nouvel état initiateur.
    ///
    /// `peer_fingerprint` : SHA-256 attendu de la pubkey du peer (via QR OOB).
    pub fn new_initiator(peer_fingerprint: [u8; 32]) -> Result<Self, HandshakeError> {
        Self::new(HandshakeRole::Initiator, peer_fingerprint)
    }

    /// Crée un nouvel état responder.
    pub fn new_responder(peer_fingerprint: [u8; 32]) -> Result<Self, HandshakeError> {
        Self::new(HandshakeRole::Responder, peer_fingerprint)
    }

    fn new(role: HandshakeRole, peer_fingerprint: [u8; 32]) -> Result<Self, HandshakeError> {
        // Générer un nonce aléatoire de 32 octets.
        let own_nonce = generate_nonce()?;

        // Récupérer notre pubkey ed25519 (dérivée de master_key).
        let own_pubkey = own_ed25519_pubkey()?;

        Ok(Self {
            role,
            phase: HandshakePhase::Idle,
            peer_fingerprint,
            own_nonce,
            own_pubkey,
            peer_nonce: None,
            peer_pubkey: None,
            shared_secret: None,
            started_at: Instant::now(),
        })
    }

    /// Retourne `true` si le timeout est dépassé.
    pub fn is_timed_out(&self, now: Instant) -> bool {
        now.duration_since(self.started_at).as_secs() >= HANDSHAKE_TIMEOUT_SECS
    }

    // ── Initiator flow ──────────────────────────────────────────────

    /// (Initiateur) Génère Msg1 : `nonce_i || pubkey_i`.
    pub fn initiator_start(&mut self) -> Result<Vec<u8>, HandshakeError> {
        if self.role != HandshakeRole::Initiator {
            return Err(HandshakeError::WrongPhase);
        }
        if self.phase != HandshakePhase::Idle {
            return Err(HandshakeError::AlreadyStarted);
        }

        let mut msg = Vec::with_capacity(MSG1_LEN);
        msg.extend_from_slice(&self.own_nonce);
        msg.extend_from_slice(&self.own_pubkey);

        self.phase = HandshakePhase::AwaitingMsg2;
        Ok(msg)
    }

    /// (Initiateur) Traite Msg2 et produit Msg3.
    ///
    /// Vérifie :
    ///   1. La longueur (128 octets)
    ///   2. SHA-256(pubkey_r) == peer_fingerprint
    ///   3. sig_r(nonce_i) valide
    ///
    /// Retourne Msg3 : `sig_i(nonce_r)`.
    pub fn initiator_process_msg2(&mut self, msg: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.phase != HandshakePhase::AwaitingMsg2 {
            return Err(HandshakeError::WrongPhase);
        }
        if msg.len() != MSG2_LEN {
            return Err(HandshakeError::InvalidLength);
        }

        let mut nonce_r = [0u8; 32];
        nonce_r.copy_from_slice(&msg[0..32]);
        let mut pubkey_r = [0u8; 32];
        pubkey_r.copy_from_slice(&msg[32..64]);
        let mut sig_r = [0u8; 64];
        sig_r.copy_from_slice(&msg[64..128]);

        // Vérifier fingerprint du peer.
        if !verify_peer_fingerprint(&pubkey_r, &self.peer_fingerprint)? {
            self.phase = HandshakePhase::Failed;
            return Err(HandshakeError::FingerprintMismatch);
        }

        // Vérifier signature du nonce_i.
        if !ed25519_verify_safe(&self.own_nonce, &pubkey_r, &sig_r) {
            self.phase = HandshakePhase::Failed;
            return Err(HandshakeError::InvalidSignature);
        }

        // Signer le nonce_r du peer.
        let sig_i = ed25519_sign_safe(&nonce_r)
            .map_err(|_| HandshakeError::CryptoUnavailable)?;

        // Stocker l'état peer.
        self.peer_nonce = Some(nonce_r);
        self.peer_pubkey = Some(pubkey_r);

        // Dériver le shared_secret (D92).
        self.shared_secret = Some(derive_shared_secret(
            &self.own_nonce,
            &nonce_r,
            &self.own_pubkey,
            &pubkey_r,
        )?);

        self.phase = HandshakePhase::Complete;

        Ok(sig_i.to_vec())
    }

    // ── Responder flow ──────────────────────────────────────────────

    /// (Responder) Traite Msg1 et produit Msg2.
    ///
    /// Vérifie :
    ///   1. La longueur (64 octets)
    ///   2. SHA-256(pubkey_i) == peer_fingerprint
    ///
    /// Retourne Msg2 : `nonce_r || pubkey_r || sig_r(nonce_i)`.
    pub fn responder_process_msg1(&mut self, msg: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.role != HandshakeRole::Responder {
            return Err(HandshakeError::WrongPhase);
        }
        if self.phase != HandshakePhase::Idle {
            return Err(HandshakeError::AlreadyStarted);
        }
        if msg.len() != MSG1_LEN {
            return Err(HandshakeError::InvalidLength);
        }

        let mut nonce_i = [0u8; 32];
        nonce_i.copy_from_slice(&msg[0..32]);
        let mut pubkey_i = [0u8; 32];
        pubkey_i.copy_from_slice(&msg[32..64]);

        // Vérifier fingerprint du peer.
        if !verify_peer_fingerprint(&pubkey_i, &self.peer_fingerprint)? {
            self.phase = HandshakePhase::Failed;
            return Err(HandshakeError::FingerprintMismatch);
        }

        // Signer le nonce_i du peer.
        let sig_r = ed25519_sign_safe(&nonce_i)
            .map_err(|_| HandshakeError::CryptoUnavailable)?;

        // Construire Msg2.
        let mut msg2 = Vec::with_capacity(MSG2_LEN);
        msg2.extend_from_slice(&self.own_nonce);
        msg2.extend_from_slice(&self.own_pubkey);
        msg2.extend_from_slice(&sig_r);

        // Stocker l'état peer.
        self.peer_nonce = Some(nonce_i);
        self.peer_pubkey = Some(pubkey_i);
        self.phase = HandshakePhase::AwaitingMsg3;

        Ok(msg2)
    }

    /// (Responder) Traite Msg3 et finalise.
    ///
    /// Vérifie sig_i(nonce_r).
    pub fn responder_process_msg3(&mut self, msg: &[u8]) -> Result<(), HandshakeError> {
        if self.phase != HandshakePhase::AwaitingMsg3 {
            return Err(HandshakeError::WrongPhase);
        }
        if msg.len() != MSG3_LEN {
            return Err(HandshakeError::InvalidLength);
        }

        let peer_pubkey = self.peer_pubkey.ok_or(HandshakeError::WrongPhase)?;

        let mut sig_i = [0u8; 64];
        sig_i.copy_from_slice(msg);

        if !ed25519_verify_safe(&self.own_nonce, &peer_pubkey, &sig_i) {
            self.phase = HandshakePhase::Failed;
            return Err(HandshakeError::InvalidSignature);
        }

        // Dériver le shared_secret (D92).
        let peer_nonce = self.peer_nonce.ok_or(HandshakeError::WrongPhase)?;
        self.shared_secret = Some(derive_shared_secret(
            &peer_nonce,          // nonce_i (initiateur)
            &self.own_nonce,      // nonce_r (nous)
            &peer_pubkey,         // pubkey_i
            &self.own_pubkey,     // pubkey_r
        )?);

        self.phase = HandshakePhase::Complete;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Helpers crypto
// ─────────────────────────────────────────────────────────────────────

/// Génère un nonce aléatoire de 32 octets via OsRng.
fn generate_nonce() -> Result<[u8; 32], HandshakeError> {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| HandshakeError::CryptoUnavailable)?;
    Ok(nonce)
}

/// Récupère notre pubkey ed25519 (via FFI, dérivée de master_key).
fn own_ed25519_pubkey() -> Result<[u8; 32], HandshakeError> {
    let mut pk = [0u8; 32];
    let rc = unsafe { crate::aegis_ed25519_public_key(pk.as_mut_ptr()) };
    if rc != 0 {
        return Err(HandshakeError::CryptoUnavailable);
    }
    Ok(pk)
}

/// Vérifie que SHA-256(pubkey) == fingerprint attendu.
fn verify_peer_fingerprint(
    pubkey: &[u8; 32],
    expected_fp: &[u8; 32],
) -> Result<bool, HandshakeError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let computed = hasher.finalize();
    Ok(computed.as_slice() == expected_fp)
}

/// D92 : shared_secret = HKDF-SHA256(nonce_i||nonce_r||pubkey_i||pubkey_r).
///
/// Note : ce secret est un placeholder d'amorçage. Le X3DH complet avec
/// ML-KEM-1024 sera introduit en P0-A.4.
fn derive_shared_secret(
    nonce_i: &[u8; 32],
    nonce_r: &[u8; 32],
    pubkey_i: &[u8; 32],
    pubkey_r: &[u8; 32],
) -> Result<[u8; 32], HandshakeError> {
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(nonce_i);
    ikm.extend_from_slice(nonce_r);
    ikm.extend_from_slice(pubkey_i);
    ikm.extend_from_slice(pubkey_r);

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| HandshakeError::CryptoUnavailable)?;

    use zeroize::Zeroize;
    ikm.zeroize();

    Ok(okm)
}

// ─────────────────────────────────────────────────────────────────────
// P0-A.3e.2b.1 (2026-10-16) — Envoi Msg1 sur out_fd
// ─────────────────────────────────────────────────────────────────────

/// Écrit un message handshake (Msg1) dans le pipe out_fd avec framing D86 :
/// `[u8 type=REMOTE_FORWARD][u32 BE len][payload]`.
///
/// Récupère out_fd depuis `ble_mesh::current_pipes()` (actif après set_pipes).
/// Le reader thread a mis out_fd en O_NONBLOCK → drop silencieux si plein.
#[cfg(unix)]
fn send_on_out_pipe(payload: &[u8]) -> Result<(), HandshakeError> {
    let (_in_fd, out_fd) = crate::network::ble_mesh::current_pipes()
        .ok_or(HandshakeError::CryptoUnavailable)?;

    let mut wire = Vec::with_capacity(5 + payload.len());
    wire.push(crate::network::ble_mesh_reader::OUT_TYPE_REMOTE_FORWARD);
    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(payload);

    let n = unsafe {
        libc::write(out_fd, wire.as_ptr() as *const libc::c_void, wire.len())
    };
    if n < 0 || (n as usize) != wire.len() {
        return Err(HandshakeError::CryptoUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_on_out_pipe(_payload: &[u8]) -> Result<(), HandshakeError> {
    Err(HandshakeError::CryptoUnavailable)
}

// ─────────────────────────────────────────────────────────────────────
// État global (utilisé par le reader thread)
// ─────────────────────────────────────────────────────────────────────

static HANDSHAKE_STATE: Mutex<Option<HandshakeState>> = Mutex::new(None);

/// Initialise un handshake en tant qu'initiateur.
///
/// P0-A.3e.2b.1 : écrit Msg1 sur out_fd (framing D86) avant de stocker
/// l'état. Si l'envoi échoue (pipe non configuré), le state n'est pas
/// stocké → cohérent fail-closed.
pub fn start_initiator(peer_fingerprint: [u8; 32]) -> Result<(), HandshakeError> {
    let mut guard = HANDSHAKE_STATE.lock().map_err(|_| HandshakeError::AlreadyStarted)?;
    if guard.is_some() {
        return Err(HandshakeError::AlreadyStarted);
    }
    let mut state = HandshakeState::new_initiator(peer_fingerprint)?;
    let msg1 = state.initiator_start()?;

    // P0-A.3e.2b.1 : envoyer Msg1 au peer via out_fd (framing D86).
    // AVANT le stockage du state : si l'envoi échoue, on ne stocke rien.
    send_on_out_pipe(&msg1)?;

    *guard = Some(state);
    Ok(())
}

/// Initialise un handshake en tant que responder (attend Msg1).
pub fn start_responder(peer_fingerprint: [u8; 32]) -> Result<(), HandshakeError> {
    let mut guard = HANDSHAKE_STATE.lock().map_err(|_| HandshakeError::AlreadyStarted)?;
    if guard.is_some() {
        return Err(HandshakeError::AlreadyStarted);
    }
    let state = HandshakeState::new_responder(peer_fingerprint)?;
    *guard = Some(state);
    Ok(())
}

/// Résultat d'un `process_message`.
pub enum HandshakeAction {
    /// Message traité, pas de réponse à envoyer (handshake terminé côté responder,
    /// ou phase intermédiaire côté initiateur).
    Done,
    /// Envoyer ce message au peer.
    Send(Vec<u8>),
}

/// Traite un message handshake reçu.
///
/// Le routage se fait par phase interne (D90).
pub fn process_message(msg: &[u8]) -> Result<HandshakeAction, HandshakeError> {
    let mut guard = HANDSHAKE_STATE.lock().map_err(|_| HandshakeError::WrongPhase)?;
    let state = guard.as_mut().ok_or(HandshakeError::NotStarted)?;

    if state.is_timed_out(Instant::now()) {
        state.phase = HandshakePhase::Failed;
        return Err(HandshakeError::Timeout);
    }

    match (state.role, state.phase) {
        (HandshakeRole::Initiator, HandshakePhase::AwaitingMsg2) => {
            let msg3 = state.initiator_process_msg2(msg)?;
            Ok(HandshakeAction::Send(msg3))
        }
        (HandshakeRole::Responder, HandshakePhase::Idle) => {
            let msg2 = state.responder_process_msg1(msg)?;
            Ok(HandshakeAction::Send(msg2))
        }
        (HandshakeRole::Responder, HandshakePhase::AwaitingMsg3) => {
            state.responder_process_msg3(msg)?;
            Ok(HandshakeAction::Done)
        }
        _ => Err(HandshakeError::WrongPhase),
    }
}

/// Retourne `true` si un handshake est en cours (pas encore terminé/échoué).
pub fn is_in_progress() -> bool {
    match HANDSHAKE_STATE.lock() {
        Ok(g) => match g.as_ref() {
            Some(s) => matches!(
                s.phase,
                HandshakePhase::Idle
                    | HandshakePhase::AwaitingMsg2
                    | HandshakePhase::AwaitingMsg3
            ),
            None => false,
        },
        Err(_) => false,
    }
}

/// Retourne `true` si le handshake est terminé avec succès.
pub fn is_complete() -> bool {
    match HANDSHAKE_STATE.lock() {
        Ok(g) => g
            .as_ref()
            .map(|s| s.phase == HandshakePhase::Complete)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Retourne le shared_secret si le handshake est terminé.
pub fn shared_secret() -> Option<[u8; 32]> {
    HANDSHAKE_STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|s| s.shared_secret))
}

/// Remet à zéro l'état handshake (appelé sur shutdown ou échec).
pub fn reset() {
    if let Ok(mut g) = HANDSHAKE_STATE.lock() {
        *g = None;
    }
}

// ─────────────────────────────────────────────────────────────────────
// FFI exporté (plain-name + wrappers JNI)
// ─────────────────────────────────────────────────────────────────────

/// FFI plain-name (usage interne / Dart).
///
/// # Safety
/// `fp_ptr` doit pointer vers 32 octets valides.
#[no_mangle]
pub unsafe extern "C" fn aegis_ble_handshake_start_initiator(fp_ptr: *const u8) -> i32 {
    if fp_ptr.is_null() {
        return HandshakeError::InvalidLength.to_code();
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(std::slice::from_raw_parts(fp_ptr, 32));
    match start_initiator(fp) {
        // P0-A.3e.2b.1 : Msg1 a été écrit dans out_fd par start_initiator.
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn aegis_ble_handshake_start_responder(fp_ptr: *const u8) -> i32 {
    if fp_ptr.is_null() {
        return HandshakeError::InvalidLength.to_code();
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(std::slice::from_raw_parts(fp_ptr, 32));
    match start_responder(fp) {
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

#[no_mangle]
pub extern "C" fn aegis_ble_handshake_is_complete() -> i32 {
    if is_complete() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn aegis_ble_handshake_reset() -> i32 {
    reset();
    0
}

// ─────────────────────────────────────────────────────────────────────
// P0-A.3e.2b.1 (2026-10-16) — Wrappers JNI pour MainActivity.kt
//
// JNI symbol naming (C64) : Java_<pkg>_<Classe>_<method>
//   . → _, _ → _1
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1handshake_1start_1initiator(
    env: jni::JNIEnv,
    _this: jni::objects::JObject,
    fp: jni::objects::JByteArray,
) -> jni::sys::jint {
    let fp_vec = match env.convert_byte_array(&fp) {
        Ok(v) => v,
        Err(_) => {
            let _ = env.exception_clear();
            return HandshakeError::InvalidLength.to_code();
        }
    };
    if fp_vec.len() != 32 {
        return HandshakeError::InvalidLength.to_code();
    }
    let mut fp_arr = [0u8; 32];
    fp_arr.copy_from_slice(&fp_vec);
    match start_initiator(fp_arr) {
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1handshake_1start_1responder(
    env: jni::JNIEnv,
    _this: jni::objects::JObject,
    fp: jni::objects::JByteArray,
) -> jni::sys::jint {
    let fp_vec = match env.convert_byte_array(&fp) {
        Ok(v) => v,
        Err(_) => {
            let _ = env.exception_clear();
            return HandshakeError::InvalidLength.to_code();
        }
    };
    if fp_vec.len() != 32 {
        return HandshakeError::InvalidLength.to_code();
    }
    let mut fp_arr = [0u8; 32];
    fp_arr.copy_from_slice(&fp_vec);
    match start_responder(fp_arr) {
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1handshake_1is_1complete(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
) -> jni::sys::jint {
    if is_complete() { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1handshake_1reset(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
) -> jni::sys::jint {
    reset();
    0
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{HardwareKeystore, TEST_LOCK};

    fn setup_master_key() {
        let root_key = [0x42u8; 32];
        HardwareKeystore::set_root_key(&root_key).expect("set_root_key");
        HardwareKeystore::derive_master_key("TestPIN-BleHandshake")
            .expect("derive_master_key");
    }

    fn teardown() {
        let _ = HardwareKeystore::wipe_all();
        reset();
    }

    fn own_fingerprint() -> [u8; 32] {
        let mut fp = [0u8; 32];
        let rc = unsafe { crate::aegis_ed25519_fingerprint(fp.as_mut_ptr()) };
        assert_eq!(rc, 0, "aegis_ed25519_fingerprint a échoué");
        fp
    }

    /// `initiator_start` produit Msg1 de 64 octets (nonce_i || pubkey_i).
    #[test]
    fn test_initiator_start_msg1_format() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let mut st = HandshakeState::new_initiator([0xAA; 32]).unwrap();
        let msg1 = st.initiator_start().unwrap();

        assert_eq!(msg1.len(), MSG1_LEN);
        assert_eq!(&msg1[0..32], &st.own_nonce);
        assert_eq!(&msg1[32..64], &st.own_pubkey);
        assert_eq!(st.phase, HandshakePhase::AwaitingMsg2);

        teardown();
    }

    /// `responder_process_msg1` rejette si fingerprint mismatch.
    #[test]
    fn test_responder_rejects_wrong_fingerprint() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        // Le responder s'attend à un fingerprint DIFFÉRENT de celui de l'initiateur.
        let mut resp = HandshakeState::new_responder([0xFF; 32]).unwrap();
        let msg1 = vec![0u8; MSG1_LEN]; // contenu bidon → fingerprint mismatch

        let result = resp.responder_process_msg1(&msg1);
        assert_eq!(result, Err(HandshakeError::FingerprintMismatch));
        assert_eq!(resp.phase, HandshakePhase::Failed);

        teardown();
    }

    /// `responder_process_msg1` rejette une longueur invalide.
    #[test]
    fn test_responder_rejects_wrong_length() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let mut resp = HandshakeState::new_responder([0x00; 32]).unwrap();
        let msg_short = vec![0u8; MSG1_LEN - 1];

        let result = resp.responder_process_msg1(&msg_short);
        assert_eq!(result, Err(HandshakeError::InvalidLength));

        teardown();
    }

    /// `initiator_process_msg2` rejette une longueur invalide.
    #[test]
    fn test_initiator_rejects_wrong_length_msg2() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let mut init = HandshakeState::new_initiator([0x00; 32]).unwrap();
        init.initiator_start().unwrap();

        let msg_short = vec![0u8; MSG2_LEN - 1];
        let result = init.initiator_process_msg2(&msg_short);
        assert_eq!(result, Err(HandshakeError::InvalidLength));

        teardown();
    }

    /// Rejet en phase incorrecte (initiator essayant process_msg1).
    #[test]
    fn test_wrong_phase_rejection() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let mut init = HandshakeState::new_initiator([0x00; 32]).unwrap();
        // En Idle → responder_process_msg1 sur un initiateur = WrongPhase.
        let result = init.responder_process_msg1(&[0u8; MSG1_LEN]);
        assert_eq!(result, Err(HandshakeError::WrongPhase));

        teardown();
    }

    /// `derive_shared_secret` est déterministe (mêmes inputs → même output).
    #[test]
    fn test_shared_secret_deterministic() {
        let ni = [0x01; 32];
        let nr = [0x02; 32];
        let pi = [0x03; 32];
        let pr = [0x04; 32];

        let s1 = derive_shared_secret(&ni, &nr, &pi, &pr).unwrap();
        let s2 = derive_shared_secret(&ni, &nr, &pi, &pr).unwrap();
        assert_eq!(s1, s2);
    }

    /// `derive_shared_secret` diffère si un seul input change.
    #[test]
    fn test_shared_secret_differs_on_input_change() {
        let ni = [0x01; 32];
        let nr = [0x02; 32];
        let pi = [0x03; 32];
        let pr = [0x04; 32];

        let s1 = derive_shared_secret(&ni, &nr, &pi, &pr).unwrap();
        let s2 = derive_shared_secret(&[0xAA; 32], &nr, &pi, &pr).unwrap();
        assert_ne!(s1, s2);
    }

    /// L'initiateur et le responder aboutissent au même shared_secret.
    #[test]
    fn test_end_to_end_shared_secret_match() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        let own_fp = own_fingerprint();

        // 1. Initiateur + Responder (les deux avec le fingerprint du peer).
        let mut init = HandshakeState::new_initiator(own_fp).unwrap();
        let mut resp = HandshakeState::new_responder(own_fp).unwrap();

        // 2. Initiateur → Msg1
        let msg1 = init.initiator_start().unwrap();

        // 3. Responder traite Msg1 → Msg2
        let msg2 = resp.responder_process_msg1(&msg1).unwrap();
        assert_eq!(msg2.len(), MSG2_LEN);

        // 4. Initiateur traite Msg2 → Msg3 + shared_secret
        let msg3 = init.initiator_process_msg2(&msg2).unwrap();
        assert_eq!(msg3.len(), MSG3_LEN);
        assert_eq!(init.phase, HandshakePhase::Complete);

        // 5. Responder traite Msg3 → finalise + shared_secret
        resp.responder_process_msg3(&msg3).unwrap();
        assert_eq!(resp.phase, HandshakePhase::Complete);

        // 6. Vérifier que les deux shared_secret matchent.
        assert_eq!(init.shared_secret, resp.shared_secret);
        assert!(init.shared_secret.is_some());

        teardown();
    }

    /// Reset efface l'état global.
    #[test]
    fn test_reset_clears_state() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();

        start_responder([0x00; 32]).unwrap();
        assert!(is_in_progress());

        reset();
        assert!(!is_in_progress());
        assert!(!is_complete());

        teardown();
    }

    /// `is_complete` retourne false initialement.
    #[test]
    fn test_is_complete_false_initially() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        assert!(!is_complete());
    }

    /// Double `start_initiator` → AlreadyStarted.
    #[test]
    fn test_double_start_rejected() {
        let _g = TEST_LOCK.lock().unwrap();
        setup_master_key();
        reset();

        start_responder([0x00; 32]).unwrap();
        let result = start_initiator([0x00; 32]);
        assert_eq!(result, Err(HandshakeError::AlreadyStarted));

        teardown();
    }

    /// Erreurs → codes négatifs distincts.
    #[test]
    fn test_error_codes_distinct() {
        use std::collections::HashSet;
        let codes = vec![
            HandshakeError::NotStarted.to_code(),
            HandshakeError::AlreadyStarted.to_code(),
            HandshakeError::WrongPhase.to_code(),
            HandshakeError::InvalidLength.to_code(),
            HandshakeError::InvalidSignature.to_code(),
            HandshakeError::FingerprintMismatch.to_code(),
            HandshakeError::CryptoUnavailable.to_code(),
            HandshakeError::Timeout.to_code(),
        ];
        let set: HashSet<i32> = codes.iter().copied().collect();
        assert_eq!(set.len(), 8);
    }
}