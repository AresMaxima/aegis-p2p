use std::fs;

#[derive(Debug, Default, Clone)]
pub struct AegisIntegrityMonitor;

impl AegisIntegrityMonitor {
    pub fn new() -> Self {
        Self
    }

    pub fn start() {
        let _ = check_zero_trust_kernel();
    }

    pub fn check_debugger_present() -> bool {
        check_zero_trust_kernel().is_err()
    }

    pub fn check_code_integrity() -> bool {
        check_zero_trust_kernel().is_ok()
    }

    pub fn check_integrity(&self) -> bool {
        check_zero_trust_kernel().is_ok()
    }

    pub fn check_memory_integrity(&self) -> bool {
        true
    }

    pub fn verify(&self) -> bool {
        self.check_integrity()
    }
}

pub fn check_zero_trust_kernel() -> Result<(), ()> {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid_str = line.split_whitespace().nth(1).unwrap_or("0");
                if pid_str != "0" {
                    return Err(());
                }
            }
        }
    }

    if let Ok(kallsyms) = fs::read_to_string("/proc/kallsyms") {
        if kallsyms.contains("kprobe_ftrace_handler") || kallsyms.contains("arch_prepare_kprobe") {
            return Err(());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_monitor() {
        let monitor = AegisIntegrityMonitor::new();
        let _ = monitor.check_integrity();
        AegisIntegrityMonitor::start();
        let _ = AegisIntegrityMonitor::check_debugger_present();
        let _ = AegisIntegrityMonitor::check_code_integrity();
    }
}