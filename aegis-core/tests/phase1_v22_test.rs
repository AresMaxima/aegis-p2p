#[cfg(test)]
mod tests {
    use aegis_core::ffi_security::force_gpu_scramble;
    #[cfg(unix)]
    use aegis_core::ffi_security::init_native_security;
    use aegis_core::secure_buffer::SecureBuffer;
    use std::process::Command;
    use std::env;

    #[test]
    fn test_v22_secure_buffer_allocation() {
        let mut buf = SecureBuffer::new(4096);
        assert_eq!(buf.len(), 4096);
        buf.as_slice_mut()[0] = 0xA5;
        assert_eq!(buf.as_slice()[0], 0xA5);
    }

    #[test]
    fn test_v22_gpu_scramble_no_crash_on_null() {
        force_gpu_scramble();
    }

    #[test]
    #[cfg(unix)]
    fn test_jalon1_v22_crash_interception_exit_137() {
        // Sous-processus : on déclenche le crash
        if env::var("AEGIS_SHOULD_CRASH").is_ok() {
            init_native_security();
            unsafe {
                let invalid_ptr: *mut u8 = std::ptr::null_mut();
                *invalid_ptr = 0xFF;
            }
            return;
        }

        // Processus parent : on lance le test en boucle fermée et on vérifie le crash
        let exe = env::current_exe().unwrap();
        let status = Command::new(exe)
            .arg("--test-threads=1")
            .arg("test_jalon1_v22_crash_interception_exit_137")
            .env("AEGIS_SHOULD_CRASH", "1")
            .status()
            .expect("Échec du lancement du sous-processus");

        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6), "Le processus aurait dû crash avec SIGABRT (6)");
    }
}