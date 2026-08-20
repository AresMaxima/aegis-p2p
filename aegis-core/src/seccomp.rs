#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn apply_strict_seccomp_filter() {
    use libc::*;

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    // Tampon de filtrage Seccomp-BPF : interception des appels système critiques
    let filter = [
        // Chargement du numéro d'appel système (offset 0 dans seccomp_data)
        sock_filter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: 0 },
        // Blocage d'execve / execveat (Interdiction d'exécuter un binaire externe)
        sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 5, jf: 0, k: SYS_execve as u32 },
        // Blocage du ptrace (Interdiction d'inspection par un débogueur)
        sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 4, jf: 0, k: SYS_ptrace as u32 },
        // Blocage de l'accès direct mémoire inter-processus
        sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 3, jf: 0, k: SYS_process_vm_readv as u32 },
        sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 2, jf: 0, k: SYS_process_vm_writev as u32 },
        // Blocage de kexec_load (Interdiction de remplacement dynamique de noyau)
        sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_kexec_load as u32 },
        // Autorisation des autres appels système légitimes
        sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
        // Destruction immédiate du processus si un appel système interdit est détecté
        sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS },
    ];

    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut sock_filter,
    };

    unsafe {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn apply_strict_seccomp_filter() {}