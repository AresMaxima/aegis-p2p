use std::arch::asm;
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC_RAW, getpid};

/// Lecture du compteur de cycles ARM64 avec barrière de synchronisation ISB
#[inline(always)]
fn read_cntvct_atomic() -> u64 {
    let cnt: u64;
    unsafe {
        // Forme une barrière physique contre la spéculation CPU et le masque EL2
        asm!(
            "isb",
            "mrs {}, cntvct_el0",
            out(reg) cnt,
            options(nomem, nostack)
        );
    }
    cnt
}

/// Lit l'horloge matérielle brute via le sous-système POSIX
fn read_monotonic_raw_ns() -> u64 {
    let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        clock_gettime(CLOCK_MONOTONIC_RAW, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Détection d'interception Ring-0 / EL2 par analyse différentielle multi-horloges
pub fn verify_syscall_latency() {
    let cycle_start = read_cntvct_atomic();
    let time_start = read_monotonic_raw_ns();

    // Syscall de référence (getpid)
    unsafe { getpid() };

    let cycle_end = read_cntvct_atomic();
    let time_end = read_monotonic_raw_ns();

    let cycle_delta = cycle_end.saturating_sub(cycle_start);
    let time_delta_ns = time_end.saturating_sub(time_start);

    // 1. Détection de surcoût absolu de cycles (Hook Ring-0)
    const MAX_ALLOWED_CYCLES: u64 = 800;
    
    // 2. Détection de dérive (Hyperviseur EL2 falsifiant cntvct_el0)
    // Si cntvct_el0 rapporte peu de cycles mais que le temps réel écoulé est élevé, un piège EL2 est présent
    let is_skewed = (time_delta_ns > 5_000) && (cycle_delta < 100);

    if cycle_delta > MAX_ALLOWED_CYCLES || is_skewed {
        // Alerte d'intégrité micro-architecturale : arrêt immédiat
        crate::panic_purge::execute_zeroization();
        std::process::exit(137);
    }
}
