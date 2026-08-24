//! aegis-core/src/security/hardware_triggers.rs
//! Détection Anti-Ptrace, Inspection Mémoire Processus & Gardien Runtime

use std::process;

#[cfg(windows)]
extern "system" {
    fn IsDebuggerPresent() -> i32;
}

pub struct HardwareGuard;

impl HardwareGuard {
    /// Vérification anti-debugging et anti-ptrace runtime (Linux, Android & Windows)
    pub fn check_anti_debugging() -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // Inspection de TracerPid dans /proc/self/status
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        if let Some(pid_str) = line.split_whitespace().nth(1) {
                            if let Ok(pid) = pid_str.parse::<i32>() {
                                if pid > 0 {
                                    return true; // Debugger / ptrace détecté
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            unsafe {
                if IsDebuggerPresent() != 0 {
                    return true;
                }
            }
        }

        false
    }

    /// Si une tentative d'inspection mémoire est détectée, arrêt immédiat
    pub fn enforce_runtime_security() {
        if Self::check_anti_debugging() {
            eprintln!("[ALERT CRITIQUE] Inspection ptrace / Debugger détectée.");
            process::exit(137);
        }
    }
}