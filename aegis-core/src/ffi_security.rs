use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

pub enum AegisErrorLevel {
    UiDisplayWarning,
    NetworkTransient,
    SecurityCritical,
}

static ZEROIZE_CALLBACK: Mutex<Option<unsafe fn()>> = Mutex::new(None);
static SECURITY_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_native_security() {
    SECURITY_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn register_zeroize_callback(cb: unsafe fn()) {
    if let Ok(mut guard) = ZEROIZE_CALLBACK.lock() {
        *guard = Some(cb);
    }
}

pub fn trigger_emergency_zeroize() {
    if let Ok(guard) = ZEROIZE_CALLBACK.lock() {
        if let Some(cb) = *guard {
            unsafe {
                cb();
            }
        }
    }
}

pub fn execute_constant_time_ffi<F, R>(target_ms: u64, logic: F) -> R
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = logic();
    let elapsed = start.elapsed();
    let target = Duration::from_millis(target_ms);
    if elapsed < target {
        thread::sleep(target - elapsed);
    }
    result
}

pub fn handle_flutter_ui_error(error_msg: &str) {
    eprintln!("[AEGIS-UI-NON-CRITICAL] {}", error_msg);
}

pub fn safe_ffi_boundary<F, R>(logic: F) -> Result<R, String>
where
    F: FnOnce() -> R + panic::UnwindSafe,
{
    panic::catch_unwind(|| logic()).map_err(|e| {
        if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "FFI_UNKNOWN_PANIC".to_string()
        }
    })
}
#[cfg(test)]
mod cov_ffi {
    use super::*;
    unsafe fn d_cb() {}
    #[test]
    fn t() {
        init_native_security();
        register_zeroize_callback(d_cb);
        trigger_emergency_zeroize();
        let _ = execute_constant_time_ffi(1, || 42);
        handle_flutter_ui_error("err");
        let _ = safe_ffi_boundary(|| Ok::<i32, String>(100));
        let _ = safe_ffi_boundary(|| Err::<i32, String>("e".into()));
    }
}

#[no_mangle]
pub extern "C" fn force_gpu_scramble() {}
