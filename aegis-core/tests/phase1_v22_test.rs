#[cfg(test)]
mod tests {
    use aegis_core::ffi_security::force_gpu_scramble;
    #[cfg(unix)]
    use aegis_core::ffi_security::init_native_security;
    use aegis_core::secure_buffer::SecureBuffer;

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
        init_native_security();

        unsafe {
            let invalid_ptr: *mut u8 = std::ptr::null_mut();
            *invalid_ptr = 0xFF;
        }
    }
}