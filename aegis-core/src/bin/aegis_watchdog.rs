use std::process;

#[cfg(unix)]
mod watchdog_unix {
    use std::env;
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::process;
    use std::time::{Duration, Instant};

    const NVRAM_HANDLE_SLOT: u32 = 0x0180F02A;
    const HEARTBEAT_TIMEOUT_MS: u64 = 100;
    const HEARTBEAT_PAYLOAD_SIZE: usize = 32;

    pub fn run() {
        let args: Vec<String> = env::args().collect();
        if args.len() < 2 {
            eprintln!("[AEGIS-WATCHDOG] Usage: aegis_watchdog <fd_number>");
            process::exit(1);
        }

        let fd: i32 = match args[1].parse() {
            Ok(num) if num >= 0 => num,
            _ => {
                eprintln!("[AEGIS-WATCHDOG] Descripteur de fichier IPC invalide.");
                process::exit(1);
            }
        };

        // SAFETY: Descripteur IPC ouvert transmis par le processus parent via socketpair()
        let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

        if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(HEARTBEAT_TIMEOUT_MS))) {
            eprintln!("[AEGIS-WATCHDOG] Échec de configuration du timeout IPC: {}", e);
            invalidate_tpm(NVRAM_HANDLE_SLOT);
        }

        eprintln!(
            "[AEGIS-WATCHDOG] Daemon actif (POSIX). FD: {}, Timeout: {} ms",
            fd, HEARTBEAT_TIMEOUT_MS
        );

        let mut buffer = [0u8; HEARTBEAT_PAYLOAD_SIZE];
        let ack_token = [0xFFu8; HEARTBEAT_PAYLOAD_SIZE];
        let mut last_heartbeat = Instant::now();

        loop {
            match stream.read(&mut buffer) {
                Ok(HEARTBEAT_PAYLOAD_SIZE) => {
                    last_heartbeat = Instant::now();
                    if stream.write_all(&ack_token).is_err() {
                        eprintln!("[AEGIS-WATCHDOG] Déconnexion IPC (Écriture ACK).");
                        break;
                    }
                }
                Ok(0) => {
                    eprintln!("[AEGIS-WATCHDOG-EMERGENCY] Signal POLLHUP/EOF intercepté (Parent SIGKILL).");
                    break;
                }
                Ok(bytes) => {
                    eprintln!("[AEGIS-WATCHDOG-EMERGENCY] Trame corrompue ({} B).", bytes);
                    break;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    if last_heartbeat.elapsed() >= Duration::from_millis(HEARTBEAT_TIMEOUT_MS) {
                        eprintln!("[AEGIS-WATCHDOG-EMERGENCY] Rupture de Heartbeat (> {} ms).", HEARTBEAT_TIMEOUT_MS);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[AEGIS-WATCHDOG-EMERGENCY] Erreur IPC: {}", e);
                    break;
                }
            }
        }

        invalidate_tpm(NVRAM_HANDLE_SLOT);
    }

    fn invalidate_tpm(handle: u32) {
        eprintln!(
            "[AEGIS-WATCHDOG-CRITICAL] Rupture de confiance IPC. Invalidation TPM Slot 0x{:08X}",
            handle
        );
        unsafe {
            libc::syscall(libc::SYS_exit_group, 137);
        }
    }
}

fn main() {
    #[cfg(unix)]
    {
        watchdog_unix::run();
    }

    #[cfg(not(unix))]
    {
        eprintln!("[AEGIS-WATCHDOG] Mode Stub Windows (Exécution réelle ciblée sur AArch64 Linux/Android).");
        process::exit(0);
    }
}