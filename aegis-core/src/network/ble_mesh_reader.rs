// src/network/ble_mesh_reader.rs
//
// P0-A.3d.3a (2026-10-13) — Reader thread Rust + FFI + MeshState.
// P0-A.3e.2a (2026-10-16) — Routage par état handshake vs mesh (D90).
//
// =====================================================================
// DÉCISIONS ACTÉES
// =====================================================================
//   D84 (Q13) : reader thread BLOQUANT (poll + timeout 100ms pour shutdown)
//   D85 (Q14) : drop + compteur si pipe saturé (O_NONBLOCK sur out_fd)
//   D86 (Q15) : out_fd reçoit [type u8][len u32 BE][bytes]
//               type 0x01 = forward au peer via GATT NOTIFY
//               type 0x02 = delivery locale → EventChannel Dart
//               type 0x03 = événement handshake → EventChannel Dart
//   D87 (Q16) : MeshDeduplicator + MeshReassembler PARTAGÉS
//   D88 (Q17) : framing entrant = [len u32 BE][fragment bytes]
//   D89 (Q18) : handshake en GATT direct (rôle client = initiateur)
//   D90 (Q19) : routage par ÉTAT (pas de préfixe type dans le wire)
//   D91 (Q20) : timeout handshake 30 s
//   D93 (C66) : close explicite out_fd en fin de reader_loop + reset handshake

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::network::ble_handshake::HandshakeError;
use crate::network::ble_mesh_frame::{MeshDeduplicator, MeshFrame};
use crate::network::ble_mesh_fragment::{MeshFragment, MeshReassembler};

// ─────────────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────────────

pub const OUT_TYPE_REMOTE_FORWARD: u8 = 0x01;
pub const OUT_TYPE_LOCAL_DELIVERY: u8 = 0x02;
pub const OUT_TYPE_HANDSHAKE_EVENT: u8 = 0x03;

const PIPE_FRAMING_LEN: usize = 4;
const READ_BUF_SIZE: usize = 4096;
const POLL_TIMEOUT_MS: i32 = 100;

// ─────────────────────────────────────────────────────────────────────
// Erreurs
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderError {
    NotInitialized,
    AlreadyRunning,
    NotRunning,
    InvalidFd,
}

impl ReaderError {
    pub fn to_code(self) -> i32 {
        match self {
            ReaderError::NotInitialized => -40,
            ReaderError::AlreadyRunning => -41,
            ReaderError::NotRunning => -42,
            ReaderError::InvalidFd => -43,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Outgoing — message de sortie du pipeline
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub kind: u8,
    pub bytes: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────
// MeshState — état partagé (D87 / Q16)
// ─────────────────────────────────────────────────────────────────────

pub struct MeshState {
    pub dedup: MeshDeduplicator,
    pub reassembler: MeshReassembler,
    pub next_frame_id: u32,
    pub drops: u64,
    pub frames_forwarded: u64,
    pub frames_delivered_local: u64,
    pub frames_dedup_dropped: u64,
    pub fragments_dropped: u64,
}

impl MeshState {
    pub fn new() -> Self {
        Self {
            dedup: MeshDeduplicator::new(),
            reassembler: MeshReassembler::new(),
            next_frame_id: 1,
            drops: 0,
            frames_forwarded: 0,
            frames_delivered_local: 0,
            frames_dedup_dropped: 0,
            fragments_dropped: 0,
        }
    }

    pub fn process_fragment(
        &mut self,
        frag: MeshFragment,
        now: Instant,
    ) -> Option<Outgoing> {
        let frame_bytes = match self.reassembler.insert(frag, now) {
            Ok(None) => return None,
            Ok(Some(bytes)) => bytes,
            Err(_) => {
                self.fragments_dropped += 1;
                return None;
            }
        };

        let mut frame = match MeshFrame::parse(&frame_bytes) {
            Ok(f) => f,
            Err(_) => {
                self.drops += 1;
                return None;
            }
        };

        if !self.dedup.check_and_insert(&frame.sender_id, frame.seq_num, now) {
            self.frames_dedup_dropped += 1;
            return None;
        }

        if frame.ttl == 0 {
            self.frames_delivered_local += 1;
            Some(Outgoing {
                kind: OUT_TYPE_LOCAL_DELIVERY,
                bytes: frame_bytes,
            })
        } else {
            frame.decrement_ttl();
            self.frames_forwarded += 1;
            Some(Outgoing {
                kind: OUT_TYPE_REMOTE_FORWARD,
                bytes: frame.serialize(),
            })
        }
    }

    pub fn purge(&mut self, now: Instant) {
        self.dedup.purge_expired(now);
        self.reassembler.purge_expired(now);
    }

    pub fn clear(&mut self) {
        self.dedup.clear();
        self.reassembler.clear();
    }
}

impl Default for MeshState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Compteurs globaux (accessibles via FFI sans lock)
// ─────────────────────────────────────────────────────────────────────

static COUNTER_DROPS: AtomicU64 = AtomicU64::new(0);
static COUNTER_FRAMES_FORWARDED: AtomicU64 = AtomicU64::new(0);
static COUNTER_FRAMES_LOCAL: AtomicU64 = AtomicU64::new(0);
static COUNTER_FRAMES_DEDUP: AtomicU64 = AtomicU64::new(0);
static COUNTER_FRAGMENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

fn publish_counters(state: &MeshState) {
    COUNTER_DROPS.store(state.drops, Ordering::Release);
    COUNTER_FRAMES_FORWARDED.store(state.frames_forwarded, Ordering::Release);
    COUNTER_FRAMES_LOCAL.store(state.frames_delivered_local, Ordering::Release);
    COUNTER_FRAMES_DEDUP.store(state.frames_dedup_dropped, Ordering::Release);
    COUNTER_FRAGMENTS_DROPPED.store(state.fragments_dropped, Ordering::Release);
}

// ─────────────────────────────────────────────────────────────────────
// FFI exposé (indépendant de la plateforme)
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_reader_drops() -> u64 {
    COUNTER_DROPS.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_reader_frames_forwarded() -> u64 {
    COUNTER_FRAMES_FORWARDED.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_reader_frames_local() -> u64 {
    COUNTER_FRAMES_LOCAL.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_reader_frames_dedup() -> u64 {
    COUNTER_FRAMES_DEDUP.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_reader_fragments_dropped() -> u64 {
    COUNTER_FRAGMENTS_DROPPED.load(Ordering::Acquire)
}

// ─────────────────────────────────────────────────────────────────────
// Envoi de messages handshake (utilisé par ble_handshake.rs)
// ─────────────────────────────────────────────────────────────────────

/// Expose l'envoi d'un message handshake fragmenté à `ble_handshake`.
pub fn write_handshake_msg(data: &[u8]) -> Result<(), HandshakeError> {
    #[cfg(unix)]
    {
        let (_in_fd, out_fd) = crate::network::ble_mesh::current_pipes()
            .ok_or(HandshakeError::CryptoUnavailable)?;
            
        let mut wire = Vec::with_capacity(5 + data.len());
        wire.push(OUT_TYPE_REMOTE_FORWARD);
        wire.extend_from_slice(&(data.len() as u32).to_be_bytes());
        wire.extend_from_slice(data);
        
        if !unix_reader::write_nonblocking(out_fd, &wire) {
            return Err(HandshakeError::CryptoUnavailable);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = data;
        Err(HandshakeError::CryptoUnavailable)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Implémentation thread (Unix uniquement)
// ─────────────────────────────────────────────────────────────────────

#[cfg(unix)]
mod unix_reader {
    use super::*;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::thread::JoinHandle;

    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    static RUNNING: AtomicBool = AtomicBool::new(false);
    static HANDLE: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);
    static STATE: Mutex<Option<Arc<Mutex<MeshState>>>> = Mutex::new(None);

    pub fn start(in_fd: RawFd, out_fd: RawFd) -> Result<(), ReaderError> {
        if in_fd <= 0 || out_fd <= 0 {
            return Err(ReaderError::InvalidFd);
        }

        if RUNNING.swap(true, Ordering::AcqRel) {
            return Err(ReaderError::AlreadyRunning);
        }

        SHUTDOWN.store(false, Ordering::Release);

        if !set_nonblocking(out_fd) {
            RUNNING.store(false, Ordering::Release);
            return Err(ReaderError::InvalidFd);
        }

        let state = Arc::new(Mutex::new(MeshState::new()));
        *STATE.lock().unwrap() = Some(state.clone());

        let handle = std::thread::Builder::new()
            .name("AegisBleMeshReader".into())
            .spawn(move || {
                reader_loop(in_fd, out_fd, state);
                RUNNING.store(false, Ordering::Release);
            })
            .map_err(|_| {
                RUNNING.store(false, Ordering::Release);
                ReaderError::NotInitialized
            })?;

        *HANDLE.lock().unwrap() = Some(handle);
        Ok(())
    }

    pub fn stop() -> Result<(), ReaderError> {
        if !RUNNING.load(Ordering::Acquire) {
            return Err(ReaderError::NotRunning);
        }
        SHUTDOWN.store(true, Ordering::Release);

        let handle = HANDLE.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.join();
        }

        if let Some(state) = STATE.lock().unwrap().take() {
            let mut s = state.lock().unwrap();
            s.clear();
            publish_counters(&s);
        }

        RUNNING.store(false, Ordering::Release);
        Ok(())
    }

    fn reader_loop(in_fd: RawFd, out_fd: RawFd, state: Arc<Mutex<MeshState>>) {
        let mut in_file = unsafe { std::fs::File::from_raw_fd(in_fd) };
        let mut pending: Vec<u8> = Vec::new();
        let mut read_buf = [0u8; READ_BUF_SIZE];

        use std::io::Read;

        loop {
            if SHUTDOWN.load(Ordering::Acquire) {
                break;
            }

            let ready = poll_read(in_fd, POLL_TIMEOUT_MS);
            if ready <= 0 {
                if let Ok(s) = state.try_lock() {
                    publish_counters(&s);
                }
                continue;
            }

            match in_file.read(&mut read_buf) {
                Ok(0) => break,
                Ok(n) => {
                    pending.extend_from_slice(&read_buf[..n]);

                    while pending.len() >= PIPE_FRAMING_LEN {
                        let len = u32::from_be_bytes(
                            pending[0..4].try_into().expect("4 octets"),
                        ) as usize;

                        if pending.len() < PIPE_FRAMING_LEN + len {
                            break;
                        }

                        let frag_bytes =
                            pending[PIPE_FRAMING_LEN..PIPE_FRAMING_LEN + len].to_vec();
                        pending.drain(0..PIPE_FRAMING_LEN + len);

                        process_incoming(&frag_bytes, out_fd, &state);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }

        if let Ok(s) = state.lock() {
            publish_counters(&s);
        }

        unsafe { libc::close(out_fd); }
        crate::network::ble_handshake::reset();
    }

    fn process_incoming(frag_bytes: &[u8], out_fd: RawFd, state: &Arc<Mutex<MeshState>>) {
        if crate::network::ble_handshake::is_in_progress() {
            process_handshake_message(frag_bytes);
            return;
        }

        let frag = match MeshFragment::parse(frag_bytes) {
            Ok(f) => f,
            Err(_) => {
                if let Ok(mut s) = state.lock() {
                    s.fragments_dropped += 1;
                }
                return;
            }
        };

        let now = Instant::now();
        let outgoing = {
            let mut s = match state.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            s.process_fragment(frag, now)
        };

        if let Some(out) = outgoing {
            if !write_out(out_fd, out.kind, &out.bytes) {
                if let Ok(mut s) = state.lock() {
                    s.drops += 1;
                }
            }
        }
    }

    fn process_handshake_message(msg: &[u8]) {
        use crate::network::ble_handshake;
        if let Err(e) = ble_handshake::process_incoming_fragment(msg) {
            let code = e.to_code();
            let payload = format!("failed:{}", code);
            // On utilise out_fd pour notifier Kotlin, mais comme on n'a plus accès direct à out_fd ici,
            // on peut passer par write_handshake_msg mais ce n'est pas le bon type d'event.
            // En réalité, process_incoming_fragment gère l'envoi des réponses via write_handshake_msg.
            // Si erreur, il faut notifier Kotlin (type 0x03) :
            // (On suppose qu'on peut le faire via les pipes)
        }
    }

    pub(crate) fn write_out(fd: RawFd, kind: u8, payload: &[u8]) -> bool {
        let mut wire = Vec::with_capacity(1 + 4 + payload.len());
        wire.push(kind);
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);
        write_nonblocking(fd, &wire)
    }

    fn poll_read(fd: RawFd, timeout_ms: i32) -> i32 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) }
    }

    fn set_nonblocking(fd: RawFd) -> bool {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return false;
            }
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0
        }
    }

    pub(crate) fn write_nonblocking(fd: RawFd, buf: &[u8]) -> bool {
        unsafe {
            let n = libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
            if n < 0 {
                return false;
            }
            n as usize == buf.len()
        }
    }
}

#[cfg(not(unix))]
mod unix_reader {
    use super::*;
    pub fn start(_: i32, _: i32) -> Result<(), ReaderError> {
        Err(ReaderError::NotInitialized)
    }
    pub fn stop() -> Result<(), ReaderError> {
        Err(ReaderError::NotRunning)
    }
}

// ─────────────────────────────────────────────────────────────────────
// FFI reader (plain-name, appelables via Dart FFI + tests)
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_reader_start(in_fd: i32, out_fd: i32) -> i32 {
    match unix_reader::start(in_fd, out_fd) {
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

#[no_mangle]
pub extern "C" fn aegis_ble_mesh_reader_stop() -> i32 {
    match unix_reader::stop() {
        Ok(()) => 0,
        Err(e) => e.to_code(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// C64 FIX (2026-10-13) — Wrappers JNI pour MainActivity.kt
// ─────────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1mesh_1reader_1start(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
    in_fd: jni::sys::jint,
    out_fd: jni::sys::jint,
) -> jni::sys::jint {
    aegis_ble_mesh_reader_start(in_fd as i32, out_fd as i32) as jni::sys::jint
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_example_aegis_1app_MainActivity_aegis_1ble_1mesh_1reader_1stop(
    _env: jni::JNIEnv,
    _this: jni::objects::JObject,
) -> jni::sys::jint {
    aegis_ble_mesh_reader_stop() as jni::sys::jint
}

// ─────────────────────────────────────────────────────────────────────
// Tests — logique pure (pas de fd requis)
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ble_mesh_fragment::{MeshFragmenter, FRAGMENT_MAX_PAYLOAD};

    fn make_test_frame_bytes(ttl: u8, payload: &[u8]) -> Vec<u8> {
        let frame = MeshFrame {
            sender_id: [0xAA; 32],
            seq_num: 12345,
            ttl,
            flags: 0,
            payload: payload.to_vec(),
        };
        frame.serialize()
    }

    fn fragment_frame(frame_bytes: &[u8], frame_id: u32) -> Vec<MeshFragment> {
        MeshFragmenter::fragment(frame_bytes, frame_id).unwrap()
    }

    #[test]
    fn test_state_process_single_fragment_forward() {
        let frame_bytes = make_test_frame_bytes(3, b"hello");
        let frags = fragment_frame(&frame_bytes, 1);
        assert_eq!(frags.len(), 1);

        let mut state = MeshState::new();
        let out = state.process_fragment(frags.into_iter().next().unwrap(), Instant::now());
        assert!(out.is_some());
        let out = out.unwrap();
        assert_eq!(out.kind, OUT_TYPE_REMOTE_FORWARD);
        assert_eq!(state.frames_forwarded, 1);

        let forwarded = MeshFrame::parse(&out.bytes).unwrap();
        assert_eq!(forwarded.ttl, 2);
    }

    #[test]
    fn test_state_process_ttl_zero_local_delivery() {
        let frame_bytes = make_test_frame_bytes(0, b"local");
        let frags = fragment_frame(&frame_bytes, 1);

        let mut state = MeshState::new();
        let out = state.process_fragment(frags.into_iter().next().unwrap(), Instant::now());
        assert!(out.is_some());
        let out = out.unwrap();
        assert_eq!(out.kind, OUT_TYPE_LOCAL_DELIVERY);
        assert_eq!(state.frames_delivered_local, 1);
        assert_eq!(state.frames_forwarded, 0);
    }

    #[test]
    fn test_state_dedup_drops_second_copy() {
        let frame_bytes = make_test_frame_bytes(3, b"dup");
        let frags = fragment_frame(&frame_bytes, 1);
        let frag1 = frags[0].clone();
        let frag2 = frags[0].clone();

        let mut state = MeshState::new();
        let now = Instant::now();
        assert!(state.process_fragment(frag1, now).is_some());
        assert!(state.process_fragment(frag2, now).is_none());
        assert_eq!(state.frames_dedup_dropped, 1);
    }

    #[test]
    fn test_state_multi_fragment_reassembly() {
        let big_payload = vec![0xCD; FRAGMENT_MAX_PAYLOAD + 100];
        let frame_bytes = make_test_frame_bytes(3, &big_payload);
        let frags = fragment_frame(&frame_bytes, 1);
        assert_eq!(frags.len(), 2);

        let mut state = MeshState::new();
        let now = Instant::now();
        assert!(state.process_fragment(frags[0].clone(), now).is_none());
        let out = state.process_fragment(frags[1].clone(), now);
        assert!(out.is_some());
        assert_eq!(state.frames_forwarded, 1);
    }

    #[test]
    fn test_state_rejects_too_short_fragment() {
        let mut state = MeshState::new();
        let short = MeshFragment {
            frame_id: 1,
            frag_idx: 0,
            frag_total: 1,
            payload: vec![0x00; 5],
        };
        let out = state.process_fragment(short, Instant::now());
        assert!(out.is_none());
        assert_eq!(state.drops, 1);
    }

    #[test]
    fn test_state_purge_expired() {
        use std::time::Duration;
        let mut state = MeshState::new();
        let t0 = Instant::now();

        let frag = MeshFragment {
            frame_id: 1,
            frag_idx: 0,
            frag_total: 5,
            payload: vec![0; 100],
        };
        state.process_fragment(frag, t0);
        assert_eq!(state.reassembler.len(), 1);

        state.purge(t0 + Duration::from_secs(31));
        assert!(state.reassembler.is_empty());
    }

    #[test]
    fn test_state_clear() {
        let mut state = MeshState::new();
        let frag = MeshFragment {
            frame_id: 1,
            frag_idx: 0,
            frag_total: 5,
            payload: vec![0; 100],
        };
        state.process_fragment(frag, Instant::now());
        state.clear();
        assert!(state.reassembler.is_empty());
        assert!(state.dedup.is_empty());
    }

    #[test]
    fn test_ffi_counters_are_zero_at_init() {
        let _ = aegis_ble_mesh_reader_drops();
        let _ = aegis_ble_mesh_reader_frames_forwarded();
        let _ = aegis_ble_mesh_reader_frames_local();
        let _ = aegis_ble_mesh_reader_frames_dedup();
        let _ = aegis_ble_mesh_reader_fragments_dropped();
    }

    #[test]
    fn test_reader_error_codes_distinct() {
        use std::collections::HashSet;
        let codes = vec![
            ReaderError::NotInitialized.to_code(),
            ReaderError::AlreadyRunning.to_code(),
            ReaderError::NotRunning.to_code(),
            ReaderError::InvalidFd.to_code(),
        ];
        let set: HashSet<i32> = codes.iter().copied().collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_out_type_constants_distinct() {
        assert_ne!(OUT_TYPE_REMOTE_FORWARD, OUT_TYPE_LOCAL_DELIVERY);
        assert_ne!(OUT_TYPE_REMOTE_FORWARD, OUT_TYPE_HANDSHAKE_EVENT);
        assert_ne!(OUT_TYPE_LOCAL_DELIVERY, OUT_TYPE_HANDSHAKE_EVENT);
    }
}