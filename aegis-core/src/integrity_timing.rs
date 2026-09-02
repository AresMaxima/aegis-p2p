use std::arch::asm;
use libc::getpid;

/// Reads the ARM64 virtual cycle counter directly from hardware (bypasses OS kernel)
#[inline(always)]
fn read_cntvct() -> u64 {
    let cnt: u64;
    unsafe {
        asm!("mrs {}, cntvct_el0", out(reg) cnt, options(nomem, nostack));
    }
    cnt
}

/// Measures syscall execution latency to detect Ring-0 hooks, ftrace, eBPF, or hypervisor overhead
pub fn verify_syscall_latency() {
    let start = read_cntvct();

    // Trivial syscall (getpid)
    unsafe { getpid() };

    let end = read_cntvct();
    let latency = end.saturating_sub(start);

    // Microarchitectural threshold (cycles)
    // Ring-0 hooks typically introduce >1500-3000 cycles overhead on getpid
    const MAX_SYSCALL_CYCLES: u64 = 800;

    if latency > MAX_SYSCALL_CYCLES {
        // Ring-0 manipulation or hypervisor detected
        eprintln!("[CRITICAL] Ring-0 intercept detected! Latency: {} cycles", latency);
        std::process::exit(137);
    }
}
