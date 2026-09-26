#[cfg(test)]
mod tests {
    use aegis_core::crypto_pq::{
        decrypt_aes_256_gcm_neon, encrypt_aes_256_gcm_neon, generate_hybrid_keypair,
    };
    use aegis_core::secure_buffer::SecureBuffer;
    use rand::RngCore;
    use std::time::Instant;

    #[test]
    fn test_phase2_aes_gcm_hardware_roundtrip() {
        let mut key = SecureBuffer::new(32);
        rand::thread_rng().fill_bytes(key.as_slice_mut());

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let plaintext = b"MESSAGE_HAUTEMENT_CONFIDENTIEL_AEGIS_v2.2_HARDWARE";
        let aad = b"HEADER_AAD";

        let ciphertext = encrypt_aes_256_gcm_neon(&key, &nonce, plaintext, aad)
            .expect("Le chiffrement AES-256-GCM doit réussir");

        let decrypted = decrypt_aes_256_gcm_neon(&key, &nonce, &ciphertext, aad)
            .expect("Le déchiffrement AES-256-GCM doit réussir");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_phase2_kyber_keypair_generation() {
        let (pk, sk) = generate_hybrid_keypair();
        assert!(!pk.x25519_pk.as_bytes().is_empty());
        assert!(!sk.x25519_sk.as_bytes().is_empty());
    }

    #[test]
    fn test_phase2_aes_gcm_throughput_benchmark() {
        let chunk_size = 10 * 1024 * 1024; // 10 Mo
        let mut key = SecureBuffer::new(32);
        rand::thread_rng().fill_bytes(key.as_slice_mut());

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut payload = vec![0u8; chunk_size];
        rand::thread_rng().fill_bytes(&mut payload);

        let start = Instant::now();
        let ciphertext = encrypt_aes_256_gcm_neon(&key, &nonce, &payload, b"")
            .expect("Benchmark encryption failed");
        let duration = start.elapsed();

        let mbytes_per_sec = (chunk_size as f64 / (1024.0 * 1024.0)) / duration.as_secs_f64();
        println!("\n[BENCHMARK] Débit AES-256-GCM : {:.2} Mo/s", mbytes_per_sec);

        assert!(ciphertext.len() > chunk_size);

        #[cfg(not(debug_assertions))]
        {
            assert!(mbytes_per_sec > 50.0, "Le débit cryptographique est anormalement bas");
        }

        #[cfg(debug_assertions)]
        {
            println!("[BENCHMARK] Débit hors-optimisation (debug/coverage) : {:.2} Mo/s", mbytes_per_sec);
        }
    }
}