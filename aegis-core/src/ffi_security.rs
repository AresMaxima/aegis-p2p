use std::time::{Duration, Instant};

/// Force un temps d'exécution fixe à chaque appel FFI pour éliminer l'analyse de timing.
pub fn execute_constant_time_ffi<F, R>(quantum_ms: u64, f: F) -> R
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    let target = Duration::from_millis(quantum_ms);

    if elapsed < target {
        std::thread::sleep(target - elapsed);
    }

    result
}