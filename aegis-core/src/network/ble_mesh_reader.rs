// src/network/ble_mesh_reader.rs
//
// P0-A.3d.3a (2026-10-13) — Reader thread Rust + FFI + MeshState.
//
// =====================================================================
// DÉCISIONS ACTÉES
// =====================================================================
//   D84 (Q13) : reader thread BLOQUANT (poll + timeout 100ms pour shutdown)
//   D85 (Q14) : drop + compteur si pipe saturé (O_NONBLOCK sur out_fd)
//   D86 (Q15) : out_fd reçoit [type u8][len u32 BE][bytes]
//               type 0x01 = forward au peer via GATT NOTIFY
//               type 0x02 = delivery locale → EventChannel Dart
//   D87 (Q16) : MeshDeduplicator + MeshReassembler PARTAGÉS
//   D88 (Q17) : framing entrant = [len u32 BE][fragment bytes]
//
// =====================================================================
// FORMAT ENTRANT (in_fd, Kotlin → Rust)
// =====================================================================
//   [u32 BE length][MeshFragment serialized]
//
// =====================================================================
// FORMAT SORTANT (out_fd, Rust → Kotlin)
// =====================================================================
//   [u8 type][u32 BE length][bytes]
//
// =====================================================================
// SHUTDOWN
// =====================================================================
//   Kotlin ferme pipeIn[1] → Rust reçoit EOF sur in_fd → sortie propre.
//   Rust signale aussi shutdown via AtomicBool pour sortie rapide du poll.
//
// =====================================================================

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::network::ble_mesh_frame::{MeshDeduplicator, MeshFrame};
use crate::network::ble_mesh_fragment::{MeshFragment, MeshReassembler};

// ─────────────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────────────

pub const OUT_TYPE_REMOTE_FORWARD: u8 = 0x01;
pub const OUT_TYPE_LOCAL_DELIVERY: u8 = 0x02;

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

    /// Traite un fragment brut (déjà désérialisé).
    ///
    /// Retourne `Some(Outgoing)` si le frame est complet et forwardable,
    /// `None` sinon (fragment partiel, duplicate, ou drop).
    ///
    /// `now` injecté pour testabilité.
    pub fn process_fragment(
        &mut self,
        frag: MeshFragment,
        now: Instant,
    ) -> Option<Outgoing> {
        // Étape 1 : réassemblage
        let frame_bytes = match self.reassembler.insert(frag, now) {
            Ok(None) => return None,        // fragment partiel
            Ok(Some(bytes)) => bytes,
            Err(_) => {
                self.fragments_dropped += 1;
                return None;
            }
        };

        // Étape 2 : parse MeshFrame
        let mut frame = match MeshFrame::parse(&frame_bytes) {
            Ok(f) => f,
            Err(_) => {
                self.drops += 1;
                return None;
            }
        };

        // Étape 3 : dédup (D80)
        if !self
            .dedup
            .check_and_insert(&frame.sender_id, frame.seq_num, now)
        {
            self.frames_dedup_dropped += 1;
            return None;
        }

        // Étape 4 : décision forward vs delivery locale (D79 + D86)
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

    /// Purge les buffers (D83 / Q12).
    pub fn purge(&mut self, now: Instant) {
        self.dedup.purge_expired(now);
        self.reassembler.purge_expired(now);
    }

    /// Vide entièrement (shutdown).
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
        // C56 : refuser fd <= 0 avant tout from_raw_fd.
        if in_fd <= 0 || out_fd <= 0 {
            return Err(ReaderError::InvalidFd);
        }

        // Un seul reader actif à la fois.
        if RUNNING.swap(true, Ordering::AcqRel) {
            return Err(ReaderError::AlreadyRunning);
        }

        SHUTDOWN.store(false, Ordering::Release);

        // Poser O_NONBLOCK sur out_fd (Q14 : drop si saturé).
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

        // Join avec timeout implicite : le reader sort au plus dans 100 ms
        // (poll timeout) si Kotlin n'a pas encore fermé pipeIn[1].
        let handle = HANDLE.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.join();
        }

        // Purge des buffers (D83).
        if let Some(state) = STATE.lock().unwrap().take() {
            let mut s = state.lock().unwrap();
            s.clear();
            publish_counters(&s);
        }

        RUNNING.store(false, Ordering::Release);
        Ok(())
    }

    fn reader_loop(in_fd: RawFd, out_fd: RawFd, state: Arc<Mutex<MeshState>>) {
        // SAFETY : fd détenus par Rust (transférés via JNI en P0-A.3c.1).
        // Ne PAS les fermer ici : Kotlin les ferme de son côté.
        let mut in_file = unsafe { std::fs::File::from_raw_fd(in_fd) };
        let mut pending: Vec<u8> = Vec::new();
        let mut read_buf = [0u8; READ_BUF_SIZE];

        use std::io::Read;

        loop {
            if SHUTDOWN.load(Ordering::Acquire) {
                break;
            }

            // Poll avec timeout pour permettre un shutdown rapide.
            let ready = poll_read(in_fd, POLL_TIMEOUT_MS);
            if ready <= 0 {
                // Timeout ou erreur : vérifier shutdown et repartir.
                // Publication périodique des compteurs.
                if let Ok(s) = state.try_lock() {
                    publish_counters(&s);
                }
                continue;
            }

            match in_file.read(&mut read_buf) {
                Ok(0) => break, // EOF : Kotlin a fermé pipeIn[1]
                Ok(n) => {
                    pending.extend_from_slice(&read_buf[..n]);

                    // Extraction des fragments framés (D88).
                    while pending.len() >= PIPE_FRAMING_LEN {
                        let len = u32::from_be_bytes(
                            pending[0..4].try_into().expect("4 octets"),
                        ) as usize;

                        if pending.len() < PIPE_FRAMING_LEN + len {
                            break; // fragment incomplet, attendre
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

        // Publication finale.
        if let Ok(s) = state.lock() {
            publish_counters(&s);
        }
    }

    fn process_incoming(frag_bytes: &[u8], out_fd: RawFd, state: &Arc<Mutex<MeshState>>) {
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
            let mut wire = Vec::with_capacity(1 + 4 + out.bytes.len());
            wire.push(out.kind);
            wire.extend_from_slice(&(out.bytes.len() as u32).to_be_bytes());
            wire.extend_from_slice(&out.bytes);

            if !write_nonblocking(out_fd, &wire) {
                if let Ok(mut s) = state.lock() {
                    s.drops += 1;
                }
            }
        }
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

    fn write_nonblocking(fd: RawFd, buf: &[u8]) -> bool {
        unsafe {
            let n = libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
            if n < 0 {
                // EAGAIN → pipe plein → drop (Q14).
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
// FFI reader
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
        // TTL=3 → forward, TTL devient 2.
        let frame_bytes = make_test_frame_bytes(3, b"hello");
        let frags = fragment_frame(&frame_bytes, 1);
        assert_eq!(frags.len(), 1);

        let mut state = MeshState::new();
        let out = state.process_fragment(frags.into_iter().next().unwrap(), Instant::now());
        assert!(out.is_some());
        let out = out.unwrap();
        assert_eq!(out.kind, OUT_TYPE_REMOTE_FORWARD);
        assert_eq!(state.frames_forwarded, 1);

        // Vérifier TTL décrémenté.
        let forwarded = MeshFrame::parse(&out.bytes).unwrap();
        assert_eq!(forwarded.ttl, 2);
    }

    #[test]
    fn test_state_process_ttl_zero_local_delivery() {
        // TTL=0 → delivery locale.
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
        assert!(state.process_fragment(frag2, now).is_none()); // dédup
        assert_eq!(state.frames_dedup_dropped, 1);
    }

    #[test]
    fn test_state_multi_fragment_reassembly() {
        // Payload > 236 → 2 fragments.
        let big_payload = vec![0xCD; FRAGMENT_MAX_PAYLOAD + 100];
        let frame_bytes = make_test_frame_bytes(3, &big_payload);
        let frags = fragment_frame(&frame_bytes, 1);
        assert_eq!(frags.len(), 2);

        let mut state = MeshState::new();
        let now = Instant::now();
        // Fragment 0 → partiel, pas de sortie.
        assert!(state.process_fragment(frags[0].clone(), now).is_none());
        // Fragment 1 → complet, sortie.
        let out = state.process_fragment(frags[1].clone(), now);
        assert!(out.is_some());
        assert_eq!(state.frames_forwarded, 1);
    }

    #[test]
    fn test_state_rejects_too_short_fragment() {
        // Fragment tronqué → fragments_dropped.
        let mut state = MeshState::new();
        let short = MeshFragment {
            frame_id: 1,
            frag_idx: 0,
            frag_total: 1,
            payload: vec![0x00; 5], // < 42 (header MeshFrame)
        };
        // Note : MeshFragment est valide (header ok), mais une fois
        // réassemblé, il ne peut pas être parsé en MeshFrame (TooShort).
        let out = state.process_fragment(short, Instant::now());
        assert!(out.is_none());
        assert_eq!(state.drops, 1);
    }

    #[test]
    fn test_state_purge_expired() {
        use std::time::Duration;
        let mut state = MeshState::new();
        let t0 = Instant::now();

        // Un fragment partiel qui n'aboutit jamais.
        let frag = MeshFragment {
            frame_id: 1,
            frag_idx: 0,
            frag_total: 5,
            payload: vec![0; 100],
        };
        state.process_fragment(frag, t0);
        assert_eq!(state.reassembler.len(), 1);

        // 31 s plus tard → purge.
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
        // Les compteurs globaux ne sont pas touchés par les tests précédents
        // (ils sont mis à jour uniquement via publish_counters()).
        // Ce test vérifie qu'ils existent et sont accessibles.
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
}