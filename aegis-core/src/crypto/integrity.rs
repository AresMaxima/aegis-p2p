use std::process::abort;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

pub static COMPROMISE_DETECTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
extern "system" {
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(process_handle: isize, is_debugger_present: *mut i32) -> i32;
    fn OpenClipboard(hWndNewOwner: isize) -> i32;
    fn EmptyClipboard() -> i32;
    fn CloseClipboard() -> i32;
}

pub struct AegisIntegrityMonitor;

impl AegisIntegrityMonitor {
    /// Démarrage de la boucle de surveillance continue.
    pub fn start() {
        // 1. Verrouillage Ptrace préventif : Un seul traçeur étant autorisé,
        // cette action bloque tout attachement ultérieur de spyciel/débogueur.
        Self::claim_ptrace_lock();

        // 2. Thread d'inspection continu
        thread::spawn(|| loop {
            if Self::check_debugger_present() || Self::check_code_integrity() {
                COMPROMISE_DETECTED.store(true, Ordering::SeqCst);
                Self::trigger_emergency_countermeasure();
            }
            thread::sleep(Duration::from_millis(250));
        });
    }

    /// Applique un PTRACE_TRACEME sur soi-même pour fermer l'accès ptrace.
    fn claim_ptrace_lock() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            let res = libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
            if res < 0 {
                Self::trigger_emergency_countermeasure();
            }
        }
    }

    /// Détecte la présence de débogueurs (IsDebuggerPresent, CheckRemoteDebuggerPresent, TracerPid).
    pub fn check_debugger_present() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            if IsDebuggerPresent() != 0 {
                return true;
            }
            let mut remote_debugger: i32 = 0;
            if CheckRemoteDebuggerPresent(-1isize, &mut remote_debugger) != 0 && remote_debugger != 0 {
                return true;
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        let pid: i32 = line
                            .split_whitespace()
                            .last()
                            .unwrap_or("0")
                            .parse()
                            .unwrap_or(0);
                        return pid != 0;
                    }
                }
            }
        }

        false
    }

    /// Analyse `/proc/self/maps` pour interdire Frida, Substrate, Xposed et autres frameworks d'injection.
    pub fn check_code_integrity() -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                let blacklisted = [
                    "frida",
                    "gadget",
                    "substrate",
                    "xposed",
                    "memmod",
                    "hook",
                    "lldb",
                    "gdb",
                ];
                let maps_lower = maps.to_lowercase();
                for keyword in &blacklisted {
                    if maps_lower.contains(keyword) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Contre-mesure d'urgence : Purge mémoire, vidage du presse-papier et Hard Crash sans stack trace.
    pub fn trigger_emergency_countermeasure() -> ! {
        // Écrasement immédiat des clés et secrets en RAM
        crate::crypto::memory::purge_all_secrets();

        // Vidage sécurisé du presse-papier sous Windows
        #[cfg(target_os = "windows")]
        unsafe {
            if OpenClipboard(0) != 0 {
                EmptyClipboard();
                CloseClipboard();
            }
        }

        // Arrêt immédiat et définitif du processus
        abort();
    }
}