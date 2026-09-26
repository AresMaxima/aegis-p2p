#[cfg(all(target_arch = "aarch64", unix))]
use std::arch::asm;
#[cfg(unix)]
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC_RAW, getpid};

/// Lecture atomique du compteur de cycles CPU virtuel avec barrière ISB.
/// 
/// # Limite du modèle de menace (ARMv8.4-A VHE) :
/// Sur les SoCs supportant ARMv8.4-A Virtual Host Extensions (VHE), un hyperviseur
/// sophistiqué peut manipuler le registre `CNTVOFF_EL2` pour ajuster l'offset temporel
/// et masquer la latence des traps hyperviseurs sans créer de dérive visible.
/// Cette mesure reste néanmoins une barrière efficace contre les rootkits Ring-0
/// conventionnels (eBPF, ftrace, hooks kprobes) et les hyperviseurs non-VHE.
#[inline(always)]
fn read_cntvct_atomic() -> u64 {
    #[cfg(all(target_arch = "aarch64", unix))]
    {
        let cnt: u64;
        unsafe {
            asm!(
                "isb",
                "mrs {}, cntvct_el0",
                out(reg) cnt,
                options(nomem, nostack)
            );
        }
        cnt
    }
    #[cfg(not(all(target_arch = "aarch64", unix)))]
    {
        0
    }
}

fn read_monotonic_raw_ns() -> u64 {
    #[cfg(unix)]
    {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe {
            clock_gettime(CLOCK_MONOTONIC_RAW, &mut ts);
        }
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    }
    #[cfg(not(unix))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

pub fn verify_syscall_latency() {
    let cycle_start = read_cntvct_atomic();
    let time_start = read_monotonic_raw_ns();

    #[cfg(unix)]
    unsafe { getpid(); }

    let cycle_end = read_cntvct_atomic();
    let time_end = read_monotonic_raw_ns();

    let cycle_delta = cycle_end.saturating_sub(cycle_start);
    let time_delta_ns = time_end.saturating_sub(time_start);

    #[cfg(all(target_arch = "aarch64", unix))]
    {
        const MAX_ALLOWED_CYCLES: u64 = 800;
        let is_skewed = (time_delta_ns > 5_000) && (cycle_delta < 100);

        if cycle_delta > MAX_ALLOWED_CYCLES || is_skewed {
            std::process::exit(137);
        }
    }
}
