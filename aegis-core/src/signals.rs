//! aegis-core/src/signals.rs
//! Canaris RAM Leurres, Handlers de Signaux & Protection Anti-Scanners (CdCM v2.2-RC1).

use rand::RngCore;
use zeroize::Zeroize;

pub const CANARY_MAGIC_U64: u64 = 0xDEAD_BEEF_CAFE_BABE;
pub const CANARY_MAGIC: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

pub struct RamCanary {
    pub guard_before: [u8; 8],
    pub canary_data: [u8; 32],
    pub guard_after: [u8; 8],
}

impl RamCanary {
    pub fn new() -> Self {
        let mut canary = Self {
            guard_before: CANARY_MAGIC,
            canary_data: [0x55; 32],
            guard_after: CANARY_MAGIC,
        };
        rand::thread_rng().fill_bytes(&mut canary.canary_data);
        canary
    }

    /// Vérifie si l'intégrité du canari RAM a été altérée par un scanner mémoire
    pub fn verify_integrity(&self) -> bool {
        self.guard_before == CANARY_MAGIC && self.guard_after == CANARY_MAGIC
    }
}

impl Default for RamCanary {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RamCanary {
    fn drop(&mut self) {
        self.guard_before.zeroize();
        self.canary_data.zeroize();
        self.guard_after.zeroize();
    }
}

/// Structure d'injection de canaris leurres en RAM
pub struct MemoryNoiseCanary {
    pub canary: RamCanary,
}

impl MemoryNoiseCanary {
    pub fn new() -> Self {
        Self {
            canary: RamCanary::new(),
        }
    }

    /// Injecte un canari leurre en RAM (utilisé par blindspots_test)
    pub fn inject(_id: usize, _size: usize) -> Self {
        Self::new()
    }

    pub fn verify(&self) -> bool {
        self.canary.verify_integrity()
    }
}

impl Default for MemoryNoiseCanary {
    fn default() -> Self {
        Self::new()
    }
}

/// Enregistre les gestionnaires de signaux POSIX pour l'interception anti-debug
pub fn setup_signal_handler() {
    #[cfg(unix)]
    unsafe {
        use libc::{sigaction, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV};
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = signal_handler_callback as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        sigaction(SIGSEGV, &sa, std::ptr::null_mut());
        sigaction(SIGFPE, &sa, std::ptr::null_mut());
        sigaction(SIGABRT, &sa, std::ptr::null_mut());
        sigaction(SIGBUS, &sa, std::ptr::null_mut());
        sigaction(SIGILL, &sa, std::ptr::null_mut());
    }
}

#[cfg(unix)]
extern "C" fn signal_handler_callback(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _uctx: *mut libc::c_void,
) {
    crate::panic::aegis_panic_purge();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ram_canary_integrity() {
        let canary = RamCanary::new();
        assert!(canary.verify_integrity());
        let noise_canary = MemoryNoiseCanary::inject(1, 32);
        assert!(noise_canary.verify());
    }

    #[test]
    fn test_default_trait_implementations() {
        let default_canary = RamCanary::default();
        assert!(default_canary.verify_integrity());

        let default_noise = MemoryNoiseCanary::default();
        assert!(default_noise.verify());
    }
}