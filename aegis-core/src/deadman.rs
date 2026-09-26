use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Instant};

pub const MIN_TIMEOUT_SECS: u64 = 900;   // 15 minutes
pub const MAX_TIMEOUT_SECS: u64 = 14400; // 4 heures
const DEFAULT_TIMEOUT: u64 = 3600; // 1 heure
const MAX_DRIFT_SECS: u64 = 300; // 5 minutes

pub struct DeadMansSwitch;
impl DeadMansSwitch {
    pub fn set_max_inactivity(seconds: u64) {
        aegis_deadman_set_timeout(seconds);
    }
    pub fn heartbeat() -> i32 {
        aegis_deadman_heartbeat()
    }
}

pub struct DeadmanSwitch;
impl DeadmanSwitch {
    pub fn init() {
        // Stub d'initialisation
    }
}

static LAST_HEARTBEAT: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_SECS: AtomicU64 = AtomicU64::new(DEFAULT_TIMEOUT);

lazy_static::lazy_static! {
    static ref BOOT_TIME_REF: Instant = Instant::now();
    static ref SYS_TIME_REF: u64 = current_sys_time();
}

fn current_sys_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[no_mangle]
pub extern "C" fn aegis_deadman_set_timeout(seconds: u64) {
    let clamped = seconds.clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS);
    TIMEOUT_SECS.store(clamped, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn aegis_deadman_heartbeat() -> i32 {
    LAST_HEARTBEAT.store(BOOT_TIME_REF.elapsed().as_secs(), Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "C" fn aegis_deadman_check() -> i32 {
    let elapsed_boot = BOOT_TIME_REF.elapsed().as_secs();
    let current_sys = current_sys_time();
    
    let expected_sys = SYS_TIME_REF.saturating_add(elapsed_boot);
    let drift = current_sys.abs_diff(expected_sys);
    
    if drift > MAX_DRIFT_SECS {
        return -1; 
    }

    let last_hb = LAST_HEARTBEAT.load(Ordering::SeqCst);
    let timeout = TIMEOUT_SECS.load(Ordering::SeqCst);

    if elapsed_boot.saturating_sub(last_hb) > timeout {
        return -1; 
    }
    
    0 
}
#[cfg(test)]
mod cov_dead { use super::*; #[test] fn t() { DeadMansSwitch::set_max_inactivity(1); let _ = DeadMansSwitch::heartbeat(); DeadmanSwitch::init(); } }
